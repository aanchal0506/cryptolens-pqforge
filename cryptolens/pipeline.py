"""End-to-end pipeline: wires stages 1-6 together in the order of the architecture diagram.

    ingest -> AST features + neural encoding -> fusion -> 2-stage head -> arbiter
           -> migration prompt + LLM -> category verification (retry on failure) -> report

`Pipeline.analyze()` returns the per-unit outcomes plus a trace of what each stage did,
which the web UI uses to draw the stage stepper.
"""
import ast
import re
import textwrap
import time
from dataclasses import dataclass, field
from pathlib import Path

from .config import MAX_MIGRATION_ATTEMPTS, MODEL_DIR
from .detector import scan_source
from .explain import explain
from .stage1_ingestion import collect_python_files, read_source
from .stage2a_ast_features import FEATURE_DIM
from .stage3_classifier import (Decision, FusionClassifier, arbitrate, fallback_threats,
                                threats_for)
from .stage4_migration import MigrationRequest, build_migrator
from .stage5_verification import verify
from .stage6_report import ACTIONABLE_RISKS, build_cbom, ci_gate

DEFAULT_MODEL_PATH = MODEL_DIR / "classifier.joblib"
MIGRATABLE_STATUS = {"detected", "model_only", "contested"}


@dataclass
class UnitOutcome:
    file: str
    unit: str
    start: int
    end: int
    code: str
    decision: Decision
    attempts: list = field(default_factory=list)   # every attempt of every threat, in order
    verified: bool = False                         # True when ALL threats are verified
    threats: list = field(default_factory=list)    # one dict per weak primitive (own attempts)
    final_code: str = ""                           # every verified fix, assembled in one block

    def __post_init__(self):
        if not self.threats:
            found = self.decision.threats or fallback_threats(self.decision, self.start)
            self.threats = [dict(t, algorithm=", ".join(t["algorithms"]), attempts=[],
                                 verified=False,
                                 why=explain(t["family"], t["algorithms"], t["risk"], t["target"]))
                            for t in found]

    @property
    def migrated_code(self):
        return self.attempts[-1]["code"] if self.attempts else ""

    def to_dict(self):
        return {"file": self.file, "unit": self.unit, "start": self.start, "end": self.end,
                "code": self.code, "decision": self.decision.to_dict(),
                "attempts": self.attempts, "verified": self.verified,
                "threats": self.threats, "final_code": self.final_code}


def load_model(path=DEFAULT_MODEL_PATH):
    """Load the trained classifier, or return None so the pipeline runs rules-only."""
    path = Path(path)
    if not path.exists():
        return None
    try:
        return FusionClassifier.load(path)
    except ImportError as err:      # scikit-learn/scipy cannot be loaded on this machine
        print(f"warning: trained model not loaded ({err}); running rules-only")
        return None


class Pipeline:
    def __init__(self, model=None, migrator="template"):
        self.model = model
        self.migrator = build_migrator(migrator) if isinstance(migrator, str) else migrator

    # -- stages 1-3 --------------------------------------------------------- #
    def classify(self, source, filename="<snippet>"):
        """Return a list of (UnitResult, unit_code, Decision) for one source text."""
        lines = source.splitlines()
        rule_results = scan_source(source, filename)
        # Each unit carries the file's imports, so it can be re-scanned and run on its own
        # (an alias such as `import hashlib as h` would otherwise be lost).
        texts = []
        for r in rule_results:
            # dedent so a method (indented inside its class) is valid code on its own
            body = textwrap.dedent("\n".join(lines[r.start - 1:r.end]))
            header = _import_header(source, body)
            texts.append(body if (not header or header in body) else header + "\n\n" + body)
        preds = self.model.predict(texts) if (self.model and texts) else [None] * len(texts)
        # Loose module/class-level code with no rule hit is usually just imports and constants.
        # The model sees the crypto imports and would flag it, but nothing is being executed
        # there, so the rule layer's "no crypto" stands.
        preds = [None if (r.unit.endswith(("<module>", "<class body>")) and r.status == "no_crypto")
                 else p for r, p in zip(rule_results, preds)]
        decisions = [arbitrate(r, p) for r, p in zip(rule_results, preds)]
        for r, d in zip(rule_results, decisions):
            d.threats = threats_for(r, d)
        return list(zip(rule_results, texts, decisions))

    # -- stages 4-5 --------------------------------------------------------- #
    def migrate_and_verify(self, outcome, test_code=""):
        """Migration with the retry loop from the diagram: fail -> retry with error context.

        Every threat (weak primitive family) in the unit gets its own prompt, its own
        attempts and its own verification. The unit counts as verified only when all of
        its actionable threats are.
        """
        outcome.attempts = []
        todo = [t for t in outcome.threats if t["risk"] in ACTIONABLE_RISKS] or outcome.threats
        for t in todo:
            self._migrate_threat(outcome, t, test_code, many=len(outcome.threats) > 1)
        outcome.verified = bool(todo) and all(t["verified"] for t in todo)
        outcome.final_code = assemble_final_code(outcome)

    def _migrate_threat(self, outcome, threat, test_code, many):
        focus = ""
        if many:
            focus = (f"fix only the {threat['family']} primitive ({threat['algorithm']}) "
                     f"near line {threat['line']}; other threats are handled separately")
        req = MigrationRequest(outcome.code, threat["family"], threat["algorithm"],
                               threat["target"], focus=focus)
        threat["attempts"], threat["verified"] = [], False
        previous = ""
        for attempt in range(1, MAX_MIGRATION_ATTEMPTS + 1):
            result = self.migrator.migrate(req, previous)
            report = verify(result.code, threat["family"], test_code)
            record = {"attempt": attempt, "threat": threat["family"], "backend": result.backend,
                      "note": result.note, "messages": result.messages, "code": result.code,
                      "verification": report.to_dict()}
            threat["attempts"].append(record)
            outcome.attempts.append(record)
            if report.passed:
                threat["verified"] = True
                return
            previous, req.feedback = result.code, report.feedback()

    # -- everything --------------------------------------------------------- #
    def analyze(self, source, filename="<snippet>", migrate=True):
        trace = []
        t0 = time.perf_counter()
        n_lines = len(source.splitlines())
        classified = self.classify(source, filename)
        trace.append({"stage": "1", "title": "Ingestion",
                      "summary": f"{n_lines} lines parsed into {len(classified)} code units"})
        trace.append({"stage": "2a", "title": "AST features",
                      "summary": f"{FEATURE_DIM}-value rule/structure vector per unit"})
        enc = self.model.encoder.name if self.model else "not loaded"
        dim = self.model.encoder.dim if self.model else 0
        trace.append({"stage": "2b", "title": "Neural encoding",
                      "summary": f"encoder: {enc}" + (f" ({dim} values per unit)" if dim else "")})
        trace.append({"stage": "3", "title": "Fusion + classification",
                      "summary": "AST + embedding fused; family head, then algorithm head"
                      if self.model else "no trained model, rule layer only"})

        outcomes = [UnitOutcome(r.file, r.unit, r.start, r.end, text, dec)
                    for r, text, dec in classified]
        found = [o for o in outcomes if o.decision.status != "no_crypto"]
        trace.append({"stage": "3b", "title": "Arbiter",
                      "summary": f"{len(found)} crypto units; "
                      + ", ".join(f"{n} {s}" for s, n in _count(o.decision.status for o in found))})

        todo = [o for o in outcomes if o.decision.risk in ACTIONABLE_RISKS
                and o.decision.status in MIGRATABLE_STATUS]
        n_threats = sum(1 for o in todo for t in o.threats if t["risk"] in ACTIONABLE_RISKS)
        if migrate:
            for o in todo:
                self.migrate_and_verify(o)
        trace.append({"stage": "4", "title": "Migration prompt + LLM",
                      "summary": f"{n_threats} threats in {len(todo)} units, one prompt each, "
                      f"sent to the '{self.migrator.name}' backend"
                      if migrate else "skipped (scan only)"})
        ok = sum(t["verified"] for o in todo for t in o.threats
                 if t["risk"] in ACTIONABLE_RISKS)
        trace.append({"stage": "5", "title": "Verification",
                      "summary": f"{ok} of {n_threats} threat migrations verified"
                      if migrate else "skipped (scan only)"})

        cbom = build_cbom(outcomes, filename)
        passed, reasons = ci_gate(cbom)
        trace.append({"stage": "6", "title": "Report + CI gate",
                      "summary": f"gate {'PASS' if passed else 'FAIL'}, "
                      f"{len(cbom['components'])} components in the CBOM"})
        return {"outcomes": outcomes, "cbom": cbom, "gate": {"passed": passed, "reasons": reasons},
                "trace": trace, "seconds": round(time.perf_counter() - t0, 2)}

    def analyze_path(self, path, migrate=True):
        """Analyze every .py file under a path and merge the results."""
        merged = None
        for f in collect_python_files(path):
            res = self.analyze(read_source(f), str(f), migrate)
            if merged is None:
                merged = res
            else:
                merged["outcomes"] += res["outcomes"]
                merged["seconds"] = round(merged["seconds"] + res["seconds"], 2)
        if merged:  # the report and gate must cover all files, not just the first
            merged["cbom"] = build_cbom(merged["outcomes"], str(path))
            passed, reasons = ci_gate(merged["cbom"])
            merged["gate"] = {"passed": passed, "reasons": reasons}
        return merged


def assemble_final_code(outcome):
    """Put the verified fixes of one unit into a single block of code.

    Hash and MAC fixes are rewritten inside the original code. Cipher, signature and
    key-exchange fixes are replacement helpers, so they are added as labelled sections.
    A threat that could not be verified is listed as a comment instead of being hidden.
    """
    code, inplace, sections, unfixed = outcome.code, False, [], []
    for t in outcome.threats:
        if not t["attempts"] or t["risk"] not in ACTIONABLE_RISKS:
            continue
        if not t["verified"]:
            unfixed.append(f"# NOT FIXED: {t['family']} ({t['algorithm']}) near line {t['line']}"
                           " - needs a manual change")
            continue
        fixed = t["attempts"][-1]["code"]
        if t["family"] in ("hash", "mac"):
            code, inplace = fixed, True
        else:
            sections.append((f"{t['family']} fix for {t['algorithm']} (near line {t['line']}): "
                             f"use these helpers instead of the old call", fixed))
    if not sections and not unfixed:
        return code
    if not inplace and len(sections) == 1 and not unfixed:
        return sections[0][1]
    bar = "# " + "=" * 70
    out = []
    if inplace or unfixed or sections:
        out.append(f"{bar}\n# original code (hash/MAC fixes applied in place)\n{bar}\n{code.rstrip()}")
    for title, body in sections:
        out.append(f"{bar}\n# {title}\n{bar}\n{body.rstrip()}")
    out += unfixed
    return "\n\n".join(out) + "\n"


def _import_header(source, body=None):
    """Source text of the file's top-level imports.

    With `body`, only imports whose name is actually used in that code are kept, so a unit
    does not drag in libraries it never touches (they may not be installed).
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return ""
    lines = source.splitlines()
    chunks = []
    for node in tree.body:
        if not isinstance(node, (ast.Import, ast.ImportFrom)):
            continue
        bound = [(a.asname or a.name.split(".")[0]) for a in node.names]
        if body is None or any(re.search(rf"\b{re.escape(n)}\b", body) for n in bound):
            chunks.append("\n".join(lines[node.lineno - 1:node.end_lineno]))
    return "\n".join(chunks)


def _count(items):
    counts = {}
    for item in items:
        counts[item] = counts.get(item, 0) + 1
    return sorted(counts.items())