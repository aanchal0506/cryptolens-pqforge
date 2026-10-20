"""Tests for stages 1-6. Run with: python -m pytest tests -q"""
import json

import numpy as np
import pytest

from cryptolens.config import FAMILY_LABELS
from cryptolens.pipeline import Pipeline
from cryptolens.stage1_ingestion import (load_dataset, normalize_category,
                                         sample_negative_snippets)
from cryptolens.stage2a_ast_features import FEATURE_DIM, FEATURE_NAMES, extract_features
from cryptolens.stage3_classifier import FusionClassifier, arbitrate
from cryptolens.detector import scan_snippet
from cryptolens.stage4_migration import (MigrationRequest, TemplateMigrator, build_messages,
                                         extract_code_block, rewrite_hashes)
from cryptolens.stage5_verification import run_in_sandbox, verify
from cryptolens.stage6_report import build_cbom, ci_gate

MD5_CODE = "import hashlib\n\ndef digest(d):\n    return hashlib.md5(d).hexdigest()\n"


# ---- stage 1 --------------------------------------------------------------------------
@pytest.mark.parametrize("text,expected", [
    ("Hashing", "hash"), ("Message Authentication Code", "mac"),
    ("Authenticated Encryption (AEAD)", "aead"), ("Symmetric Encryption", "symmetric"),
    ("Digital Signature", "signature"), ("Key Exchange", "key_exchange"), ("Combined", "combined")])
def test_normalize_category(text, expected):
    assert normalize_category(text) == expected


def test_normalize_category_rejects_unknown():
    with pytest.raises(ValueError):
        normalize_category("cooking")


def test_load_dataset_jsonl_and_chatml(tmp_path):
    rows = [{"migration_category": "Hashing", "pre_quantum_code": MD5_CODE},
            {"messages": [{"role": "user", "content":
                           "MIGRATION CATEGORY: Digital Signature\nPRE-QUANTUM CODE:\nx = 1"},
                          {"role": "assistant", "content": "y = 2"}]},
            {"nonsense": 1}]
    f = tmp_path / "d.jsonl"
    f.write_text("\n".join(json.dumps(r) for r in rows))
    entries, skipped = load_dataset(f)
    assert [e.family for e in entries] == ["hash", "signature"]
    assert len(skipped) == 1 and "columns" in skipped[0]


def test_negative_snippets_parse_and_have_no_crypto():
    import ast
    snippets = sample_negative_snippets(10)
    assert len(snippets) == 10
    for s in snippets:
        ast.parse(s)


# ---- stage 2 --------------------------------------------------------------------------
def test_features_shape_and_signal():
    vec = extract_features(MD5_CODE)
    assert vec.shape == (FEATURE_DIM,) and FEATURE_DIM == len(FEATURE_NAMES)
    assert vec[FEATURE_NAMES.index("import:hashlib")] == 1
    assert vec[FEATURE_NAMES.index("algo:MD5")] == 1


def test_features_zero_on_syntax_error():
    assert not extract_features("def (:").any()


# ---- stage 3 --------------------------------------------------------------------------
@pytest.fixture(scope="module")
def tiny_model():
    texts = [MD5_CODE.replace("md5", a) for a in ("md5", "sha1", "sha256") * 4]
    texts += ["def add(a, b):\n    return a + b\n"] * 6 + ["def name(x):\n    return str(x)\n"] * 6
    fams = ["hash"] * 12 + ["none"] * 12
    algos = ["MD5", "SHA-1", "SHA-256"] * 4 + ["none"] * 12
    return FusionClassifier("tfidf", n_components=8).fit(texts, fams, algos)


def test_model_predicts_family(tiny_model):
    pred = tiny_model.predict([MD5_CODE, "def add(a, b):\n    return a + b\n"])
    assert [p.family for p in pred] == ["hash", "none"]
    assert set(pred[0].family_probs) <= set(FAMILY_LABELS)


def test_model_pickles(tiny_model, tmp_path):
    tiny_model.save(tmp_path / "m.joblib")
    again = FusionClassifier.load(tmp_path / "m.joblib")
    assert again.predict([MD5_CODE])[0].family == "hash"


def test_arbiter_rule_wins_without_model():
    d = arbitrate(scan_snippet(MD5_CODE), None)
    assert d.status == "detected" and d.algorithm == "MD5" and d.source == "rule"


def test_arbiter_flags_disagreement(tiny_model):
    from cryptolens.stage3_classifier import ModelPrediction
    # a confident model that disagrees with the rule layer
    fake = ModelPrediction("signature", 0.9, {}, "RSA", 0.9)
    d = arbitrate(scan_snippet(MD5_CODE), fake)
    assert d.status == "contested" and d.families == ["hash"]


# ---- stage 4 --------------------------------------------------------------------------
def test_rewrite_hashes_covers_aliases_and_strings():
    code = "import hashlib as h\nh.md5(b'')\nhashlib.new('sha1')\nfrom hashlib import sha256\n"
    out = rewrite_hashes(code)
    assert "md5" not in out and "sha1" not in out and "sha256" not in out
    assert "h.sha3_256" in out


def test_prompt_contains_label_and_retry_context():
    req = MigrationRequest(MD5_CODE, "hash", "MD5", "SHA3-256", feedback="re-scan failed")
    msgs = build_messages(req, previous_code="x = 1")
    assert "MIGRATION CATEGORY: hash" in msgs[1]["content"] and "TARGET: SHA3-256" in msgs[1]["content"]
    assert msgs[-1]["content"].startswith("VERIFICATION FAILED")


def test_extract_code_block():
    assert extract_code_block("text\n```python\nx = 1\n```\nmore") == "x = 1\n"


# ---- stage 5 --------------------------------------------------------------------------
@pytest.mark.parametrize("family,target", [("symmetric", "AES-256-GCM"), ("aead", "ChaCha20-Poly1305"),
                                           ("signature", "ML-DSA-87"), ("key_exchange", "ML-KEM-1024")])
def test_reference_templates_verify(family, target):
    result = TemplateMigrator().migrate(MigrationRequest("x = 1", family, "", target))
    report = verify(result.code, family)
    assert report.passed, report.feedback()


def test_unmigrated_code_fails_with_useful_feedback():
    report = verify(MD5_CODE, "hash")
    assert not report.passed and "MD5" in report.feedback()


def test_broken_syntax_fails_fast():
    report = verify("def (:", "hash")
    assert not report.passed and len(report.checks) == 1


def test_sandbox_reports_runtime_error_and_timeout(monkeypatch):
    assert "ZeroDivisionError" in run_in_sandbox("1/0")["error"]
    monkeypatch.setattr("cryptolens.stage5_verification.SANDBOX_TIMEOUT_S", 2)
    assert "timed out" in run_in_sandbox("while True: pass")["error"]


def test_dataset_test_code_is_executed():
    ok = run_in_sandbox("def f():\n    return 1\n", "assert f() == 1")
    bad = run_in_sandbox("def f():\n    return 1\n", "assert f() == 2")
    assert ok["tests"] is True and "AssertionError" in bad["error"]


# ---- stages 1-6 together -----------------------------------------------------------------
def test_pipeline_end_to_end_rules_only():
    src = (MD5_CODE + "\nfrom cryptography.hazmat.primitives.asymmetric import rsa\n\n"
           "def sign(d):\n    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
           "    return k.sign(d, None, None)\n")
    result = Pipeline().analyze(src)
    found = [o for o in result["outcomes"] if o.decision.status != "no_crypto"]
    assert {o.decision.algorithm for o in found} == {"MD5", "RSA"}
    assert all(o.verified for o in found)
    assert result["gate"]["passed"]


def test_ci_gate_fails_on_unmigrated_finding():
    result = Pipeline().analyze(MD5_CODE, migrate=False)
    passed, reasons = ci_gate(result["cbom"])
    assert not passed and "MD5" in reasons[0]


def test_cbom_summary_counts():
    result = Pipeline().analyze(MD5_CODE)
    summary = build_cbom(result["outcomes"])["summary"]
    assert summary["components"] == 1 and summary["by_migration_state"] == {"migrated_verified": 1}


# ---- quantum demo (Qiskit) -----------------------------------------------------------------
def test_shor_factors_15_for_every_valid_base():
    from cryptolens.quantum_demo import shor_demo
    for a in (2, 4, 7, 8, 11, 13):
        result = shor_demo(a)
        assert result["factors"] == [3, 5], a
        assert pow(a, result["order"], 15) == 1


def test_shor_rejects_non_coprime_base():
    from cryptolens.quantum_demo import shor_demo
    with pytest.raises(ValueError):
        shor_demo(5)


def test_grover_finds_secret_with_quadratic_speedup():
    from cryptolens.quantum_demo import grover_demo
    result = grover_demo("1011")
    assert result["found"] and result["success_probability"] > 0.9
    assert result["iterations"] < result["classical_expected_guesses"]