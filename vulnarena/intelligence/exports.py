import html
import json
import re


def prose(text):
    value = html.escape(text, quote=False)
    for character in ["\\", "[", "]", "*", "_", chr(96)]:
        value = value.replace(character, "\\" + character)
    return value


def block(text, language="text"):
    longest = max((len(value) for value in re.findall(r"~+", text)), default=0)
    fence = "~" * max(3, longest + 1)
    return fence + language + "\n" + text + "\n" + fence


def card_markdown(card):
    lines = [
        "# " + card["cve_id"] + " · AI 学习卡片",
        prose(card.get("note", "")),
        "生成时间：" + card.get("created_at", ""),
        "模型：" + card.get("model", "") + " · 提示词：" + card.get("prompt_version", ""),
    ]
    for section in card.get("sections", []):
        lines.extend(["## " + section["title"], prose(section["text"])])
        for reference in section.get("references", []):
            lines.extend(["来源 " + reference["source_id"], block(reference["quote"])])
    lines.append("## 原始资料与版本")
    for source in card.get("sources", []):
        lines.extend(
            [
                "### " + source["source_id"] + " · " + source["cve_id"],
                prose(source["url"]),
                "CVE 修订时间：" + source.get("updated_at", ""),
                "来源版本：" + source["signature"],
                block(source["text"]),
            ]
        )
    lines.extend(
        [
            "## 上游结构化字段",
            block(json.dumps(card.get("facts", {}), ensure_ascii=False, indent=2), "json"),
        ]
    )
    return "\n\n".join(lines) + "\n"
