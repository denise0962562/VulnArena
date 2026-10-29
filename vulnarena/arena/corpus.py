"""Detection corpora.

Every entry is a request line in the same shape the middleware inspects:
``METHOD path?query|body``. A rule is only worth activating if it catches all
attack samples of its category and touches none of the benign ones.
"""

import re
from enum import StrEnum
from urllib.parse import unquote

COMMENT = re.compile(r"--[^\n]*|/\*.*?\*/", re.S)
WHITESPACE = re.compile(r"\s+")


class Category(StrEnum):
    SQLI = "sqli"
    IDOR = "idor"
    PATH_TRAVERSAL = "path_traversal"
    SSRF = "ssrf"


# Not every defect can be stopped at the gateway. IDOR has no request-level
# signature, and path traversal cannot be separated from legitimate notes that
# mention "../" - both are fixed in code and never gated as regex rules.
REGEX_CATEGORIES = frozenset({Category.SQLI, Category.SSRF})

CODE_ONLY: dict[Category, str] = {
    Category.IDOR: "a regex cannot tell an attacker from the ticket owner",
    Category.PATH_TRAVERSAL: "legitimate notes also contain ../, so any pattern kills real traffic",
}


def normalise(raw: str) -> str:
    text = unquote(unquote(raw))
    # Query strings encode spaces as '+', so a \s+ pattern must still match.
    text = text.replace("+", " ")
    text = COMMENT.sub(" ", text)
    return WHITESPACE.sub(" ", text).strip().lower()


def observation(method: str, path: str, query: str, body: str) -> tuple[str, str]:
    raw = f"{method.upper()} {path}?{query}|{body}"
    return raw, normalise(raw)


ATTACK: dict[Category, list[str]] = {
    Category.SQLI: [
        "GET /api/portal/tickets?q=x%25%27%20UNION%20SELECT%200%2Csecret%2C%27open%27"
        "%2C%272026-09-01%27%20FROM%20flag_vault%20--|",
        "GET /api/portal/tickets?q=%27%20OR%20%271%27%3D%271|",
        'POST /api/portal/login|{"username":"admin\' --","password":"x"}',
        "GET /api/portal/tickets?q=x%27%20UnIoN%20SeLeCt%20secret%20FROM%20flag_vault|",
        "GET /api/portal/tickets?q=%27%20UNION%20ALL%20SELECT%200%2Csecret"
        "%2C%27open%27%20FROM%20flag_vault--|",
    ],
    Category.PATH_TRAVERSAL: [
        "GET /api/portal/exports?name=..%2F..%2Fetc%2Fportal%2Fsecret_key|",
        "GET /api/portal/exports?name=..%252F..%252Fetc%252Fportal%252Fsecret_key|",
        "GET /api/portal/exports?name=....%2F%2F....%2F%2Fetc%2Fportal%2Fsecret_key|",
    ],
    Category.SSRF: [
        "POST /api/portal/webhooks/test|"
        '{"target_url":"http://169.254.169.254/latest/meta-data/iam/security-credentials/"}',
        "POST /api/portal/webhooks/test|"
        '{"target_url":"http://0xa9fea9fe/latest/meta-data/iam/security-credentials/"}',
        'POST /api/portal/webhooks/test|{"target_url":"http://2852039166/latest/meta-data/"}',
    ],
    Category.IDOR: [
        "GET /api/portal/tickets/11|",
        "GET /api/portal/tickets/12|",
    ],
}

BENIGN: list[str] = [
    "GET /api/portal/tickets?q=O'Brien|",
    "GET /api/portal/tickets?q=100%25|",
    "GET /api/portal/tickets?q=ticket's%20status|",
    "GET /api/portal/tickets?q=%E6%8A%A5%E8%A1%A8|",
    "GET /api/portal/exports?name=headcount-2026Q3.csv|",
    "GET /api/portal/exports?name=tickets-2026Q3.csv|",
    'POST /api/portal/webhooks/test|{"target_url":"http://hooks.internal/ingest"}',
    'POST /api/portal/login|{"username":"alice","password":"alice-pw"}',
    "GET /api/portal/tickets/1|",
    "GET /api/portal/tickets?q=select%20the%20row|",
    "GET /api/portal/tickets?q=1%3D1%20%E8%BF%99%E4%B8%AA%E5%85%AC%E5%BC%8F|",
    "POST /api/portal/tickets|"
    '{"note":"..%2F%20%E4%B8%8A%E7%BA%A7%E7%9B%AE%E5%BD%95%E8%AF%B4%E6%98%8E"}',
]
