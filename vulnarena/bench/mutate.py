"""红队的"造变体"：把已知 payload 变成等价但字面不同的写法。

这一层不依赖模型——它是不需要网络的红队基本功（注释拆分、大小写、等价关键字、
编码），也正因为不依赖模型，回合制的基线是确定、可复现的。
模型生成的变体是它的增强版（P4 的可选部分）。
"""

import re
from urllib.parse import quote

SPACE = re.compile(r"\s+")

# 每类只是"可用的变形手法"，不代表全部绕过方式
TRANSFORMS = ("comment", "case", "space", "keyword", "encode", "hash", "true")


def _comment(sample: str) -> str:
    """union select → union/**/select：注释替换空格，规则按 \\s+ 就匹配不到了。"""
    return SPACE.sub("/**/", sample, count=1)


def _case(sample: str) -> str:
    return "".join(char.upper() if index % 2 else char for index, char in enumerate(sample))


def _space(sample: str) -> str:
    """用制表符/换行替换空格：很多规则只写了 \\s 一次，遇到空白组合就漏。"""
    return SPACE.sub("\t", sample, count=1)


def _keyword(sample: str) -> str:
    """union select → union all select（等价语法，多一个关键字）。"""
    return re.sub(r"(?i)\bunion\b", "union all", sample, count=1)


def _encode(sample: str) -> str:
    return quote(sample, safe="/?=&|{}[]:\"',.-_")


def _hash_comment(sample: str) -> str:
    """把 -- 注释换成 MySQL 的 # 注释：规则只写了 -- 就失效。"""
    return re.sub(r"--", "#", sample, count=1)


def _always_true(sample: str) -> str:
    """' or 1=1 换成 ' or 'a'='a：语义等价，字面完全不同。"""
    return re.sub(r"(?i)('\s*or\s+'?1'?\s*=\s*'?1'?)", "' or 'a'='a", sample)


_FUNCTIONS = {
    "comment": _comment,
    "case": _case,
    "space": _space,
    "keyword": _keyword,
    "encode": _encode,
    "hash": _hash_comment,
    "true": _always_true,
}


def mutate(sample: str, *, transforms: tuple[str, ...] = TRANSFORMS) -> list[str]:
    """生成若干等价变体，去掉和原文相同的结果。"""
    variants: list[str] = []
    for name in transforms:
        function = _FUNCTIONS.get(name)
        if function is None:
            continue
        candidate = function(sample)
        if candidate and candidate != sample and candidate not in variants:
            variants.append(candidate)
    return variants


def mutate_all(attacks: dict[str, list[str]]) -> dict[str, list[str]]:
    """对整份语料做一遍变形，返回新增样本（不含原有的）。"""
    added: dict[str, list[str]] = {}
    for category, samples in attacks.items():
        known = set(samples)
        fresh: list[str] = []
        for sample in samples:
            for variant in mutate(sample):
                if variant not in known and variant not in fresh:
                    fresh.append(variant)
        if fresh:
            added[category] = fresh
    return added


def limited_variants(corpus, category: str, limit: int = 20) -> list[str]:
    """Shared CLI/API candidate policy. Unique normalized additions are counted later."""
    known = set(corpus.attacks.get(category, []))
    fresh = []
    for sample in corpus.attacks.get(category, []):
        for candidate in mutate(sample):
            if candidate not in known and candidate not in fresh:
                fresh.append(candidate)
            if len(fresh) >= limit:
                return fresh[:limit]
    return fresh
