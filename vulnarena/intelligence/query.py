import re
from datetime import UTC, datetime

from vulnarena.intelligence.schemas import Filters

CVE_PATTERN = re.compile(r"(?<![A-Za-z0-9])CVE-\d{4}-\d{4,}(?![A-Za-z0-9])", re.I)
STOP_WORDS = set(
    "the a an in on at is are was were be to of for and or with by from this that "
    "which what how why find explain vulnerability vulnerabilities issue security "
    "about does can me please show list affected following before after".split()
)
ALIASES = {
    "修复": "fix patched upgrade remediation",
    "缓解": "mitigation workaround",
    "受影响版本": "affected versions",
    "反序列化": "deserialization",
    "提权": "privilege escalation",
    "本地提权": "local privilege escalation",
    "远程代码执行": "remote code execution",
    "命令执行": "command execution",
    "文件上传": "file upload",
    "目录遍历": "path traversal",
    "路径遍历": "path traversal",
    "任意文件读取": "arbitrary file read",
    "缓冲区溢出": "buffer overflow",
    "内存破坏": "memory corruption",
    "释放后使用": "use after free",
    "拒绝服务": "denial of service",
    "认证绕过": "authentication bypass",
    "跨站脚本": "cross site scripting XSS",
    "注入": "injection",
    "条件竞争": "race condition",
    "整数溢出": "integer overflow",
    "日志": "log",
    "符号链接": "symlink symbolic link",
    "压缩包": "archive",
    "Log4Shell": "log4j JNDI",
    "Spring4Shell": "spring framework data binding",
    "DirtyPipe": "linux pipe",
    "PrintNightmare": "windows print spooler",
    "Zerologon": "netlogon",
    "regreSSHion": "openssh signal handler",
}


def tokens(text: str) -> list[str]:
    english = [
        word
        for word in re.findall(r"[a-z0-9]+(?:[-_.][a-z0-9]+)*", text.lower())
        if len(word) > 1 and word not in STOP_WORDS
    ]
    chinese = []
    for part in re.findall(r"[\u3400-\u9fff]+", text):
        chinese.extend(part[index : index + 2] for index in range(len(part) - 1))
    return list(dict.fromkeys([*english, *chinese]))[:2000]


def expanded_query(question: str) -> str:
    return (
        question
        + " "
        + " ".join(
            english for chinese, english in ALIASES.items() if chinese.lower() in question.lower()
        )
    )


def query_anchors(question: str) -> list[str]:
    """Honor explicit technical names in Chinese/quoted questions, not generic terms.

    These are query constraints rather than CVE-specific boosts. For unrestricted
    English prose leave retrieval to its normal ranking to avoid treating ordinary
    words as mandatory product names.
    """
    if not re.search(r"[\u3400-\u9fff]", question):
        return []
    generic = STOP_WORDS | {
        "linux",
        "windows",
        "java",
        "python",
        "rust",
        "php",
        "net",
        "go",
        "remote",
        "local",
        "code",
        "execution",
        "privilege",
        "escalation",
        "buffer",
        "overflow",
        "use",
        "free",
        "denial",
        "service",
        "best-fit",
        "http",
        "https",
        "sql",
        "cve",
        "cwe",
        "cvss",
        "version",
    }
    names = {name.lower(): expansion for name, expansion in ALIASES.items() if name.isascii()}
    words = []
    for word in re.findall(r"[A-Za-z][A-Za-z0-9_.-]*", CVE_PATTERN.sub("", question)):
        words.extend(re.findall(r"[A-Za-z][A-Za-z0-9_.-]*", names.get(word.lower(), word)))
    return list(
        dict.fromkeys(
            word.lower() for word in words if word.lower() not in generic and len(word) >= 2
        )
    )[:8]


def has_query_anchor(text: str, anchors: list[str]) -> bool:
    return not anchors or any(
        re.search(r"(?<![a-z0-9])" + re.escape(word) + r"(?![a-z0-9])", text.lower())
        for word in anchors
    )


def parse_filters(question: str, requested: Filters) -> Filters:
    value = requested.model_dump()
    without_ids = CVE_PATTERN.sub("", question)
    years = [
        int(year)
        for pair in re.findall(
            r"(?<![A-Za-z0-9.])(20[0-9]{2})\s*年|(?:\bin\b|\bduring\b|\byear\b)\s+(20[0-9]{2})\b",
            without_ids,
            re.I,
        )
        for year in pair
        if year
    ]
    for start, end in re.findall(
        r"(?<![\d.])(20[0-9]{2})\s*(?:[-–~到至]|\bto\b)\s*(20[0-9]{2})(?!\d)",
        without_ids,
        re.I,
    ):
        years.extend([int(start), int(end)])
    prefix = re.match(r"^\s*(20[0-9]{2})\s+", without_ids)
    if prefix:
        years.append(int(prefix[1]))
    if not years:
        years = [2000 + int(year) for year in re.findall(r"(?<![\d.])(2[0-9])年", without_ids)]
    years = list(dict.fromkeys(years))
    if years and not value["year_from"] and not value["year_to"]:
        value["year_from"], value["year_to"] = min(years), max(years)
        if len(years) == 1 and re.search(r"以来|至今|到现在", without_ids):
            value["year_to"] = max(years[0], datetime.now(UTC).year)
    if not value["topic"]:
        detected = []
        for topic in [
            "Linux",
            "Windows",
            "Python",
            "JavaScript",
            "Java",
            "PHP",
            "Rust",
            ".NET",
            "Go",
            "C/C++",
        ]:
            if re.search(r"(?<![A-Za-z])" + re.escape(topic) + r"(?![A-Za-z])", question, re.I):
                detected.append(topic)
        if len(detected) == 1:
            value["topic"] = detected[0]
    if not value["severity"]:
        for word, severity in [
            ("严重", "CRITICAL"),
            ("高危", "HIGH"),
            ("中危", "MEDIUM"),
            ("低危", "LOW"),
            ("未评分", "UNKNOWN"),
        ]:
            if word in question:
                value["severity"] = severity
                break
    return Filters(**value)


def is_statistics(question: str) -> bool:
    if re.search(
        r"多少.{0,4}(?:版本|字节|参数|内存)|how many.{0,20}(?:versions|bytes)", question, re.I
    ):
        return False
    return bool(re.search(r"多少|数量|总数|统计|how many|count of", question, re.I))


def in_domain(question: str) -> bool:
    return bool(
        CVE_PATTERN.search(question)
        or re.search(
            r"漏洞|修复|提权|注入|溢出|序列化|上传|遍历|拒绝服务|竞态|认证|泄露|代码执行|执行代码|目录外|路径归一化|证书|签名校验|"
            r"cve|cwe|cvss|exploit|vulnerab|patch|overflow|injection|traversal|"
            r"linux|windows|python|java|php|rust|openssl|openssh|log4|spring|"
            r"curl|http/2|ssrf|xss|polkit|dirty.?pipe|netlogon|libwebp|"
            r"netip|ipv4|ipv6|host header|socks|jndi|liblzma|xz|sudo|pkexec|llama|"
            r"remote code execution|command execution|authentication bypass|"
            r"information disclosure|privilege escalation|elevation of privilege|"
            r"code.signing|certificates?|credential|unauthenticated|arbitrary code|"
            r"access control|path normali[sz]ation",
            question,
            re.I,
        )
    )


def reciprocal_rank_fusion(rankings: list[list[str]], limit: int = 60) -> list[tuple[str, float]]:
    scores = {}
    for ranking in rankings:
        for position, identity in enumerate(ranking, 1):
            scores[identity] = scores.get(identity, 0) + 1 / (60 + position)
    return sorted(scores.items(), key=lambda item: (-item[1], item[0]))[:limit]
