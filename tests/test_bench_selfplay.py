"""P4：红队变形造样本 → 语料变强 → 蓝队召回下降。"""

from vulnarena.bench.corpus import load_corpus
from vulnarena.bench.mutate import mutate, mutate_all
from vulnarena.bench.selfplay import run_selfplay

BYPASS = "GET /pos?q=union/**/select"


def test_mutations_are_equivalent_but_different():
    original = "GET /pos?q=union select"
    variants = mutate(original)
    assert variants, "应该造出至少一个变体"
    assert all(variant != original for variant in variants)
    assert any("/**/" in variant for variant in variants), "注释拆分是最典型的手法"
    assert any(
        variant.lower() == original.lower() and variant != original for variant in variants
    ), "大小写变体"


def test_mutate_all_only_returns_new_samples():
    attacks = {"sqli": ["GET /pos?q=union select"]}
    added = mutate_all(attacks)
    assert added["sqli"]
    assert all(sample not in attacks["sqli"] for sample in added["sqli"])


async def test_selfplay_grows_the_corpus_and_dents_recall():
    corpus = load_corpus()

    def red(current, category):
        known = set(current.attacks.get(category, []))
        return [] if BYPASS in known else [BYPASS]

    rounds = await run_selfplay(corpus, rounds=2, category="sqli", red=red)

    assert [item.round_no for item in rounds] == [1, 2]
    assert rounds[0].recall < 1.0, "红队第一轮就该把规则打出缺口"
    assert rounds[1].corpus_attacks >= rounds[0].corpus_attacks
    assert rounds[0].new_samples == [BYPASS]


async def test_selfplay_without_red_keeps_recall_at_one():
    corpus = load_corpus()
    rounds = await run_selfplay(corpus, rounds=1, category="sqli", red=lambda _c, _cat: [])
    assert rounds[0].recall == 1.0
    assert rounds[0].passed is True
