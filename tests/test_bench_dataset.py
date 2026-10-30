"""P6 数据工厂：pair 的取舍必须是真的（好规则能过、坏规则过不了）。"""

import json
from pathlib import Path

from vulnarena.bench.__main__ import main
from vulnarena.bench.corpus import load_corpus
from vulnarena.bench.dataset import build_pairs, build_records, classification_records, widen


def test_widened_rule_is_a_superset_of_the_template():
    from vulnarena.arena.templates import SQLI_RULE_REGEX

    widened = widen(SQLI_RULE_REGEX)
    assert widened != SQLI_RULE_REGEX
    assert "[\\s/*]*" in widened, "空白被放宽成空白或注释"


def test_pairs_are_built_from_a_real_difference():
    pairs = build_pairs(load_corpus(), rounds=3)
    assert pairs, "第一轮就应该产出样本"
    first = pairs[0]
    assert first.chosen_recall == 1.0
    assert first.rejected_recall < 1.0, "被拒的规则必须真的更差"


def test_classification_covers_both_labels():
    records = classification_records(load_corpus())
    labels = {record["label"] for record in records}
    assert labels == {"attack", "benign"}
    assert all(record["text"] for record in records)


def test_records_mix_pairs_and_classification():
    records = build_records(load_corpus(), rounds=3)
    tasks = {record["task"] for record in records}
    assert tasks == {"write a waf regex", "classify"}


def test_cli_writes_jsonl():
    out = Path("reports") / "_dataset-test.jsonl"
    try:
        assert main(["dataset", "--rounds", "1", "--out", str(out)]) == 0
        lines = out.read_text(encoding="utf-8").splitlines()
        assert lines
        payload = json.loads(lines[0])
        assert "task" in payload
    finally:
        out.unlink(missing_ok=True)
