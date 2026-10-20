"""Stage 6 - Report and CI gate.

Turns pipeline outcomes into
  * a CBOM-style JSON document (a cryptographic bill of materials, loosely following the
    CycloneDX CBOM idea: one component per finding, with location, risk and migration state)
  * a short Markdown summary for humans
  * a pass/fail gate for CI, so a pull request can be blocked while risky crypto remains
"""
from collections import Counter
from datetime import datetime, timezone

# Risk classes that should fail a CI run unless the finding has been migrated and verified.
BLOCKING_RISKS = {"broken_by_shor", "already_deprecated"}
ACTIONABLE_RISKS = BLOCKING_RISKS | {"weakened_by_grover"}


def migration_state(outcome, threat=None):
    """One word describing where a finding (or one threat inside it) stands."""
    risk = threat["risk"] if threat else outcome.decision.risk
    verified = threat["verified"] if threat else outcome.verified
    attempts = threat["attempts"] if threat else outcome.attempts
    if risk == "quantum_safe":
        return "safe"
    if verified:
        return "migrated_verified"
    if attempts:
        return "migration_failed"
    if outcome.decision.status in ("abstain", "ambiguous", "contested"):
        return "needs_human_review"
    return "pending"


def build_cbom(outcomes, source_name="<input>"):
    """Create the report dictionary from a list of UnitOutcome objects."""
    components = []
    for out in outcomes:
        d = out.decision
        if d.status == "no_crypto":
            continue
        threats = out.threats if out.threats else [None]
        for t in threats:
            ref = f"{out.file}:{out.unit}:{out.start}" + (f"#{t['family']}" if len(threats) > 1 else "")
            components.append({
                "type": "cryptographic-asset",
                "name": (t["algorithm"] if t else d.algorithm) or "unclassified",
                "bom-ref": ref,
                "cryptoProperties": {
                    "assetType": "algorithm",
                    "primitive": t["family"] if t else (",".join(d.families) or "unknown"),
                    "quantumRisk": t["risk"] if t else d.risk,
                    "recommendedTarget": t["target"] if t else d.target,
                },
                "evidence": {"file": out.file, "unit": out.unit, "lines": [out.start, out.end],
                             "threatLine": t["line"] if t else out.start},
                "classification": {"status": d.status, "source": d.source,
                                   "confidence": round(d.confidence, 3), "note": d.note},
                "migration": {"state": migration_state(out, t),
                              "attempts": len(t["attempts"]) if t else len(out.attempts),
                              "backend": (t["attempts"][-1]["backend"] if t and t["attempts"]
                                          else None)},
            })
    risks = Counter(c["cryptoProperties"]["quantumRisk"] for c in components)
    states = Counter(c["migration"]["state"] for c in components)
    return {
        "bomFormat": "CBOM-style",
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source": source_name,
        "summary": {"components": len(components), "by_risk": dict(risks),
                    "by_migration_state": dict(states)},
        "components": components,
    }


def ci_gate(cbom):
    """Return (passed, reasons). Fails while any blocking finding is not safely resolved."""
    reasons = []
    for comp in cbom["components"]:
        risk = comp["cryptoProperties"]["quantumRisk"]
        state = comp["migration"]["state"]
        if risk in BLOCKING_RISKS and state != "migrated_verified":
            where = comp["evidence"]
            reasons.append(f"{where['file']}:{where['lines'][0]} {comp['name']} "
                           f"({risk}, {state})")
    return (not reasons), reasons


def to_markdown(cbom):
    passed, reasons = ci_gate(cbom)
    lines = [f"# Crypto inventory - {cbom['source']}", "",
             f"CI gate: **{'PASS' if passed else 'FAIL'}**", "",
             "| Location | Algorithm | Risk | Target | State |", "|---|---|---|---|---|"]
    for comp in cbom["components"]:
        ev, props = comp["evidence"], comp["cryptoProperties"]
        lines.append(f"| {ev['file']}:{ev['lines'][0]} {ev['unit']} | {comp['name']} | "
                     f"{props['quantumRisk']} | {props['recommendedTarget'] or '-'} | "
                     f"{comp['migration']['state']} |")
    if reasons:
        lines += ["", "Blocking findings:"] + [f"- {r}" for r in reasons]
    return "\n".join(lines) + "\n"