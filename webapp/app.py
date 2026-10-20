"""Web UI for CryptoLens / PQ-Forge.

    python webapp/app.py            # then open http://127.0.0.1:5000

Endpoints
    GET  /              the single-page interface
    POST /api/analyze   {code, migrate, backend}  -> findings, stage trace, CBOM, CI gate
    GET  /api/metrics   contents of reports/metrics.json (written by cryptolens.train)
    POST /api/quantum   {a, secret} -> Qiskit Shor and Grover demo results
    GET  /api/sample    a demo file with a mix of risky and safe crypto
"""
import json
import os
import sys
from pathlib import Path

# allow running as `python webapp/app.py` from the project root
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from flask import Flask, jsonify, render_template, request  # noqa: E402

from cryptolens.config import REPORT_DIR  # noqa: E402
from cryptolens.pipeline import Pipeline, load_model  # noqa: E402

app = Flask(__name__)
MODEL = load_model()          # None if train.py has not been run: UI then shows rules-only
MAX_CODE_CHARS = 60_000       # keeps one request cheap; this is a demo server


def serialize(result):
    """Convert pipeline output to plain JSON; units with no crypto are only counted."""
    findings = [o.to_dict() for o in result["outcomes"] if o.decision.status != "no_crypto"]
    return {"findings": findings, "units_total": len(result["outcomes"]),
            "trace": result["trace"], "cbom": result["cbom"], "gate": result["gate"],
            "seconds": result["seconds"], "model_loaded": MODEL is not None}


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/api/analyze")
def analyze():
    body = request.get_json(silent=True) or {}
    code = body.get("code", "")
    if not code.strip():
        return jsonify(error="Paste some Python code first."), 400
    if len(code) > MAX_CODE_CHARS:
        return jsonify(error=f"Code is longer than {MAX_CODE_CHARS} characters."), 400
    backend = body.get("backend", "template")
    if backend == "anthropic" and not os.environ.get("ANTHROPIC_API_KEY"):
        return jsonify(error="ANTHROPIC_API_KEY is not set on the server."), 400
    try:
        result = Pipeline(MODEL, backend).analyze(code, "input.py", migrate=bool(body.get("migrate", True)))
    except SyntaxError as err:
        return jsonify(error=f"The code does not parse: line {err.lineno}: {err.msg}"), 400
    return jsonify(serialize(result))


@app.get("/api/metrics")
def metrics():
    path = REPORT_DIR / "metrics.json"
    if not path.exists():
        return jsonify(error="No metrics yet. Run: python -m cryptolens.train"), 404
    return jsonify(json.loads(path.read_text(encoding="utf-8")))


@app.post("/api/quantum")
def quantum():
    """Run the Qiskit Shor / Grover demos (toy sizes, on a simulator)."""
    from cryptolens.quantum_demo import run_all
    body = request.get_json(silent=True) or {}
    secret = str(body.get("secret", "1011"))
    try:
        a = int(body.get("a", 7))
        if not (set(secret) <= {"0", "1"} and 2 <= len(secret) <= 8):
            raise ValueError("secret must be 2 to 8 bits of 0/1")
        return jsonify(run_all(a, secret))
    except ValueError as err:
        return jsonify(error=str(err)), 400


@app.get("/api/sample")
def sample():
    return jsonify(code=(Path(__file__).parent / "sample_app.py").read_text(encoding="utf-8"))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)