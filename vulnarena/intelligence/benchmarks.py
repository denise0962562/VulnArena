"""100 transparent retrieval cases: 20 source-checked seeds, 4 phrasings + 20 negatives.

The seed descriptions were checked against the saved NVD originals. Template
expansions are labelled as such; these are not 100 independent human judgements.
Keep a separate held-out set before using these results as a production benchmark.
"""

VERSION = "nvd-study-100-v1"
SEEDS = [
    (
        "CVE-2021-44228",
        "Apache Log4j JNDI LDAP message lookup remote code execution",
        "Log4j 日志中的 JNDI LDAP 查找为何会导致远程代码执行",
        "Log4Shell 中攻击者控制日志参数造成的风险",
    ),
    (
        "CVE-2022-22965",
        "Spring MVC WebFlux JDK 9 Tomcat WAR data binding remote code execution",
        "Spring 在 JDK 9 和 Tomcat WAR 部署下的数据绑定远程代码执行",
        "Spring4Shell 的 WAR 与可执行 jar 部署条件有什么不同",
    ),
    (
        "CVE-2024-3094",
        "xz liblzma malicious upstream tarballs disguised test file",
        "xz 上游压缩包中通过测试文件植入 liblzma 恶意代码的漏洞",
        "xz 5.6.0 供应链恶意代码如何进入 liblzma",
    ),
    (
        "CVE-2024-4577",
        "PHP CGI Apache Windows Best-Fit code pages argument injection",
        "Windows 上 PHP CGI 因 Best-Fit 字符映射造成参数注入",
        "PHP CGI 在特定 Windows 代码页下误解命令行选项",
    ),
    (
        "CVE-2021-34527",
        "Windows Print Spooler privileged file operations remote code execution SYSTEM",
        "Windows 打印后台处理服务错误执行特权文件操作的漏洞",
        "PrintNightmare 为什么可能获得 SYSTEM 权限",
    ),
    (
        "CVE-2020-1472",
        "Netlogon MS-NRPC domain controller secure channel privilege escalation",
        "Netlogon 安全通道连接域控制器引发的提权漏洞",
        "Zerologon 与 MS-NRPC 域控制器连接有关的风险",
    ),
    (
        "CVE-2021-4034",
        "polkit pkexec setuid argument count environment variables local privilege escalation",
        "polkit 的 pkexec 错误处理参数数量造成本地提权",
        "pkexec 把环境变量当命令执行的本地提权问题",
    ),
    (
        "CVE-2022-0847",
        "Linux pipe buffer flags uninitialized page cache read only files",
        "Linux 管道缓冲区 flags 未初始化导致只读文件页缓存可被修改",
        "DirtyPipe 怎样利用残留管道标志造成提权",
    ),
    (
        "CVE-2023-4863",
        "libwebp heap buffer overflow crafted HTML out of bounds write",
        "libwebp 堆缓冲区溢出与越界写入漏洞",
        "Chrome 使用 libwebp 处理恶意页面引发的内存写入风险",
    ),
    (
        "CVE-2023-38545",
        "curl SOCKS5 proxy handshake long hostname heap buffer overflow",
        "curl 在 SOCKS5 代理握手处理过长主机名时的堆溢出",
        "curl 的 SOCKS5 名称解析切换为何会引发缓冲区问题",
    ),
    (
        "CVE-2023-44487",
        "HTTP/2 request cancellation rapid stream reset denial of service",
        "HTTP/2 快速取消请求和重置流造成拒绝服务",
        "HTTP/2 Rapid Reset 怎样消耗服务器资源",
    ),
    (
        "CVE-2024-34359",
        "llama-cpp-python Llama chat template Jinja2 model loading",
        "llama-cpp-python 加载模型聊天模板时的模板注入风险",
        "Python 的 llama.cpp 绑定在读取 GGUF 聊天模板时的问题",
    ),
    (
        "CVE-2024-27980",
        "child_process.spawn spawnSync batch files command argument injection shell disabled",
        "child_process.spawn 在未启用 shell 时处理批处理文件仍可命令注入",
        "Node.js spawnSync 处理恶意批处理参数的代码执行漏洞",
    ),
    (
        "CVE-2024-24576",
        "Rust Command Windows bat cmd batch file arguments escaping",
        "Rust Command 在 Windows 上调用 bat 或 cmd 时参数转义不充分",
        "Rust 标准库批处理进程参数可能绕过转义执行命令",
    ),
    (
        "CVE-2023-29406",
        "Go net/http HTTP/1 client Host header additional header request injection",
        "Go HTTP/1 客户端未完整校验 Host 请求头导致请求注入",
        "Go net/http 对 Request.Host 与 URL.Host 的校验问题",
    ),
    (
        "CVE-2024-24790",
        "Go netip IsPrivate IsLoopback IPv4-mapped IPv6 false results",
        "Go netip 对 IPv4 映射 IPv6 地址的 IsPrivate 判断错误",
        "Go 中 IPv4 映射地址让 IsLoopback 等方法返回错误结果",
    ),
    (
        "CVE-2023-43622",
        "Apache HTTP Server HTTP/2 initial window size zero worker exhaustion",
        "Apache HTTP/2 初始窗口大小为零导致连接长期阻塞",
        "Apache HTTP Server 因零窗口连接耗尽工作线程的问题",
    ),
    (
        "CVE-2024-6387",
        "OpenSSH sshd signal handler race authentication timeout regression",
        "OpenSSH sshd 认证超时后信号处理不安全的竞态漏洞",
        "regreSSHion 中 sshd 安全回归和信号处理的关系",
    ),
    (
        "CVE-2021-3156",
        "sudoedit -s trailing backslash off by one heap overflow privilege escalation",
        "sudoedit 命令行末尾反斜杠造成 off-by-one 堆溢出提权",
        "Sudo 的 sudoedit -s 反斜杠参数处理问题",
    ),
    (
        "CVE-2022-3602",
        "OpenSSL X.509 certificate name constraints malicious email buffer overrun",
        "OpenSSL X.509 证书名称约束校验中的恶意邮件地址缓冲区溢出",
        "OpenSSL 证书链验证后的名称约束检查问题",
    ),
]


def dataset_info(dataset="holdout"):
    import json
    from pathlib import Path

    filename = "holdout-v1.json" if dataset == "regression" else "holdout-v2.json"
    data = json.loads((Path(__file__).with_name("data") / filename).read_text(encoding="utf-8"))
    if dataset == "regression":
        data["note"] = (
            "原留出集已用于诊断领域判断缺陷，现作为扩展回归集；不再作为盲测。 " + data["note"]
        )
    return data


def holdout():
    return dataset_info("holdout")


def cases(dataset="development"):
    if dataset in {"holdout", "regression"}:
        return dataset_info(dataset)["cases"]
    output = []
    for identifier, english, chinese, paraphrase in SEEDS:
        for category, question in [
            ("exact_cve", "解释 " + identifier),
            ("english", "Explain the vulnerability involving " + english),
            ("cross_language", chinese),
            ("paraphrase", paraphrase),
        ]:
            output.append(
                {
                    "id": f"{identifier}-{category}",
                    "category": category,
                    "question": question,
                    "expected_cves": [identifier],
                    "expected_abstain": False,
                    "provenance": "NVD-checked seed; authored phrasing/template expansion",
                }
            )
    for number in range(10):
        output.append(
            {
                "id": f"missing-{number}",
                "category": "no_evidence",
                "question": f"解释 CVE-2099-{990000 + number} 的漏洞原因和修复版本",
                "expected_cves": [],
                "expected_abstain": True,
                "provenance": "nonexistent exact ID",
            }
        )
    for number, question in enumerate(
        [
            "写一首关于春天的诗",
            "明天的天气怎么样",
            "推荐一道晚餐菜谱",
            "帮我计算一加一",
            "巴黎有哪些景点",
            "写一个生日祝福",
            "介绍一下猫的习性",
            "怎样种植番茄",
            "推荐一首轻音乐",
            "给我讲一个童话故事",
        ]
    ):
        output.append(
            {
                "id": f"outside-{number}",
                "category": "out_of_domain",
                "question": question,
                "expected_cves": [],
                "expected_abstain": True,
                "provenance": "out-of-domain query",
            }
        )
    return output
