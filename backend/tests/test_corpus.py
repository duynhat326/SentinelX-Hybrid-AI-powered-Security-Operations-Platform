import re
from collections import Counter

from app.database.models import DetectionRule
from app.database.session import get_factory
from app.detection.engine import RULES
from tests.corpus_runner import confusion, load_cases, run_case


def _fast(monkeypatch):
    from app.core import config

    monkeypatch.setenv("SENTINELX_RATE_LIMIT_PER_MINUTE", "1000000")
    config.get_settings.cache_clear()


def test_corpus_is_big_enough_and_balanced():
    cases = load_cases()
    assert len(cases) >= 100 and len({c["id"] for c in cases}) == len(cases)
    per_rule = Counter((c["rule"], c["label"]) for c in cases)
    for r in RULES:
        assert per_rule[(r.id, "malicious")] >= 5 and per_rule[(r.id, "benign")] >= 5, r.id
    assert all(c["synthetic"] for c in cases)
    assert not any(c.get("known_gap") and c["label"] != "malicious" for c in cases)


def test_every_corpus_case_behaves_as_labeled(client, monkeypatch, capsys):
    _fast(monkeypatch)
    results, wrong = [], []
    for c in load_cases():
        fired = c["rule"] in run_case(client, c)
        results.append((c, fired))
        expected = c["label"] == "malicious" and not c.get("known_gap")  # known gaps must still be missed
        if fired != expected:
            wrong.append(f"{c['id']} ({c['note']}): fired={fired} expected={expected}")
    with capsys.disabled():
        print("\nrule     TP  FN  FP  TN  precision recall   (synthetic regression corpus, not a real-world evaluation)")
        for rid, c in sorted(confusion(results).items()):
            p = c["TP"] / (c["TP"] + c["FP"]) if c["TP"] + c["FP"] else float("nan")
            r = c["TP"] / (c["TP"] + c["FN"]) if c["TP"] + c["FN"] else float("nan")
            print(f"{rid}  {c['TP']:>3} {c['FN']:>3} {c['FP']:>3} {c['TN']:>3}  {p:8.2f} {r:8.2f}")
    assert not wrong, "\n".join(wrong)


def test_disabling_a_rule_stops_its_alerts(client, monkeypatch):
    _fast(monkeypatch)
    for rule in RULES:
        case = next(c for c in load_cases() if c["rule"] == rule.id and c["label"] == "malicious" and not c.get("known_gap"))
        assert rule.id in run_case(client, case, host=f"on-{rule.id}")
        with get_factory()() as db:
            db.get(DetectionRule, rule.id).enabled = False
            db.commit()
        assert rule.id not in run_case(client, case, host=f"off-{rule.id}"), rule.id
        with get_factory()() as db:
            db.get(DetectionRule, rule.id).enabled = True
            db.commit()


def test_rule_metadata_and_docs():
    from pathlib import Path

    docs = (Path(__file__).resolve().parents[2] / "docs" / "detection-rules.md").read_text()
    for r in RULES:
        assert r.severity in {"low", "medium", "high", "critical"}
        assert r.mitre and all(re.fullmatch(r"T\d{4}(\.\d{3})?", t) for t in r.mitre), r.id
        assert r.references and all(u.startswith("https://attack.mitre.org/") for u in r.references)
        assert r.id in docs and r.title in docs, f"{r.id} missing from docs/detection-rules.md"
