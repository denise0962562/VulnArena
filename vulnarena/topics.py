"""Search hints, not assertions about the implementation language of a CVE."""

import re

TOPICS = {
    "Linux": r"linux|ubuntu|debian|red hat|suse|kernel",
    "Windows": r"windows|microsoft|active directory",
    "Java": r"\bjava\b|log4j|spring|tomcat|jenkins|maven",
    "Go": r"\bgolang\b|\bgo\b|gogs|gitea",
    "Python": r"python|django|flask|fastapi|pypi|pillow",
    "PHP": r"\bphp\b|wordpress|laravel|symfony|composer|drupal",
    "C/C++": r"\bc\+\+|\bglibc\b|openssl|libcurl|\blibc\b|\bzlib\b|ffmpeg|libxml",
    ".NET": r"\.net\b|asp\.net|nuget|\bc#\b|dotnet",
    "Rust": r"\brust\b|rustsec|\bcargo\b|tokio",
    "JavaScript": r"javascript|node\.js|\bnpm\b|webpack|\bnext\.js\b",
    "其他": "",
}


def classify(text: str) -> list[str]:
    return [name for name, pattern in TOPICS.items() if pattern and re.search(pattern, text, re.I)]
