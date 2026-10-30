"""评测台：指标口径、报告格式、CLI 退出码。"""

from pathlib import Path

from vulnarena.arena.corpus import Category
from vulnarena.arena.policy import WafRule
from vulnarena.arena.templates import SQLI_RULE_REGEX, SSRF_RULE_REGEX, WEAK_RULE_REGEX
from vulnarena.bench import evaluate, load_corpus, to_json, to_markdown
from vulnarena.bench.__main__ import main


def _rule(regex: str, category: Category = Category.SQLI) -> WafRule:
    return WafRule(category=category, regex=regex, source="template")


def test_good_rule_passes_every_check():
    result = evaluate(_rule(SQLI_RULE_REGEX), load_corpus())
    assert result.passed, result.reasons
    assert result.recall == 1.0
    assert result.false_positive == 0.0
    assert result.attack_total > 0


def test_weak_rule_is_rejected_on_recall():
    result = evaluate(_rule(WEAK_RULE_REGEX), load_corpus())
    assert not result.passed
    assert result.recall < 1.0
    assert result.missed, "应该能列出被漏掉的样本"
    assert any("recall" in reason for reason in result.reasons)


def test_overbroad_rule_is_rejected_on_false_positives():
    # 只匹配一个单引号：既拦不住真正的注入，又会把 O'Brien 这类正常搜索误杀
    result = evaluate(_rule(r"'"), load_corpus())
    assert not result.passed
    assert result.false_positives
    assert any("false positive" in reason for reason in result.reasons)


def test_broken_regex_is_reported_not_raised():
    result = evaluate(_rule("("), load_corpus())
    assert not result.passed
    assert any("compile" in reason for reason in result.reasons)


def test_ssrf_rule_passes_on_its_own_category():
    result = evaluate(_rule(SSRF_RULE_REGEX, Category.SSRF), load_corpus())
    assert result.passed, result.reasons


def test_reports_render_the_numbers():
    corpus = load_corpus()
    results = [evaluate(_rule(SQLI_RULE_REGEX), corpus), evaluate(_rule(WEAK_RULE_REGEX), corpus)]

    markdown = to_markdown(results)
    assert "| 规则 | 类别 | 召回 | 误杀 |" in markdown
    assert "未通过" in markdown

    payload = to_json(results)
    assert '"passed": 1' in payload.replace(": ", ": ") or '"passed":1' in payload
    assert '"failed": 1' in payload


def test_cli_exit_code_reflects_the_gate():
    # 沙箱里只有工作区可写，所以写到 reports/ 下再清理
    out = Path("reports") / "_cli-test.json"
    try:
        assert main(["run", "--json", str(out)]) == 0  # 内置规则全部通过
        assert out.exists()
        assert '"summary"' in out.read_text(encoding="utf-8")
    finally:
        out.unlink(missing_ok=True)
