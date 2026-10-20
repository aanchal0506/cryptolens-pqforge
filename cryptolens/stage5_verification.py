"""Stage 5 - Category-specific verification.

Every migrated snippet goes through the same pipeline of checks:

  1. syntax        the code must parse
  2. re-scan       the SAME classifier is run on the new code. The migration only counts as
                   done if it now sees a quantum-safe primitive of the right family. This is
                   the "classifier as verification oracle" idea from the project document.
  3. validator     one of four category validators (hash/mac, cipher, signature, kem):
                   static security rules plus a dynamic run in a sandbox
  4. dynamic run   the code is executed in a separate, resource-limited Python process.
                   If the dataset supplies test code it is run too; otherwise the module's
                   own `_selftest()` is used when it has one.

A failed report carries `feedback()` text that goes back into the migration prompt.
"""
import ast
import json
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field

from .config import SANDBOX_MEMORY_MB, SANDBOX_TIMEOUT_S
from .detector import scan_snippet


@dataclass
class Check:
    name: str
    passed: bool
    detail: str = ""


@dataclass
class VerificationReport:
    validator: str
    checks: list = field(default_factory=list)

    @property
    def passed(self):
        return all(c.passed for c in self.checks)

    def feedback(self):
        """Plain-text list of failures, used in the retry prompt."""
        return "\n".join(f"- {c.name}: {c.detail}" for c in self.checks if not c.passed)

    def to_dict(self):
        return {"validator": self.validator, "passed": self.passed,
                "checks": [c.__dict__ for c in self.checks]}


# --------------------------------------------------------------------------- #
# Sandbox
# --------------------------------------------------------------------------- #
# The runner executes the migrated code, then the optional test code, then _selftest().
_RUNNER = r"""
import json, sys
src = open("migrated.py").read()
tests = open("tests.py").read()
ns = {"__name__": "migrated"}
out = {"ran": False, "selftest": None, "tests": None}
try:
    exec(compile(src, "migrated.py", "exec"), ns)
    out["ran"] = True
    if tests.strip():
        exec(compile(tests, "tests.py", "exec"), ns)
        out["tests"] = True
    elif callable(ns.get("_selftest")):
        out["selftest"] = bool(ns["_selftest"]())
except BaseException as exc:
    out["error"] = type(exc).__name__ + ": " + str(exc)[:300]
print("RESULT:" + json.dumps(out))
"""


def _limit_resources():
    """Run in the child before exec: cap memory and CPU time (Linux only)."""
    import resource
    limit = SANDBOX_MEMORY_MB * 1024 * 1024
    resource.setrlimit(resource.RLIMIT_AS, (limit, limit))
    # one second above the wall-clock timeout, so a runaway loop is reported as "timed out"
    # by the parent first and the CPU limit only acts as a backstop
    resource.setrlimit(resource.RLIMIT_CPU, (SANDBOX_TIMEOUT_S + 1, SANDBOX_TIMEOUT_S + 1))


def _clean_env():
    """Minimal environment for the child process. Windows Python also needs SYSTEMROOT."""
    return {k: v for k, v in os.environ.items() if k.upper() in ("PATH", "SYSTEMROOT")}


def run_in_sandbox(code, test_code=""):
    """Execute code in a throw-away directory and subprocess. Returns the parsed result dict.

    Limits: wall-clock timeout, memory, CPU, empty environment, isolated interpreter (-I).
    This is not a security boundary against hostile code; for untrusted input run the
    whole tool inside a container.
    """
    with tempfile.TemporaryDirectory() as work:
        for name, text in (("migrated.py", code), ("tests.py", test_code), ("runner.py", _RUNNER)):
            with open(os.path.join(work, name), "w", encoding="utf-8") as fh:
                fh.write(text)
        try:
            proc = subprocess.run(
                [sys.executable, "-I", "runner.py"], cwd=work, capture_output=True, text=True,
                timeout=SANDBOX_TIMEOUT_S, env=_clean_env(),
                preexec_fn=_limit_resources if os.name == "posix" else None)
        except subprocess.TimeoutExpired:
            return {"ran": False, "error": f"timed out after {SANDBOX_TIMEOUT_S}s"}
    for line in proc.stdout.splitlines():
        if line.startswith("RESULT:"):
            return json.loads(line[len("RESULT:"):])
    if proc.returncode < 0:
        return {"ran": False, "error": f"process killed by signal {-proc.returncode} "
                                       "(memory or CPU limit)"}
    return {"ran": False, "error": (proc.stderr or "no output")[-300:]}


# --------------------------------------------------------------------------- #
# Shared checks
# --------------------------------------------------------------------------- #
def check_syntax(code):
    try:
        ast.parse(code)
        return Check("syntax", True)
    except SyntaxError as err:
        return Check("syntax", False, f"line {err.lineno}: {err.msg}")


def check_rescan(code, expected_family):
    """The classifier must now see only quantum-safe primitives of the threat's family.

    Only this threat's family is judged. A function with three weak primitives gets three
    migrations, and each one is checked against its own primitive.
    """
    scan = scan_snippet(code)
    if scan.status != "detected":
        return Check("re-scan", False, f"classifier status is '{scan.status}', expected 'detected'")
    # Moving a plain cipher to AES-GCM legitimately turns "symmetric" into "aead".
    acceptable = {expected_family}
    if expected_family in ("symmetric", "aead"):
        acceptable = {"symmetric", "aead"}
    mine = scan.threats if expected_family == "combined" else \
        [t for t in scan.threats if t["family"] in acceptable]
    if not mine:
        return Check("re-scan", False,
                     f"expected family '{expected_family}', found {scan.families}")
    weak = [t for t in mine if t["risk"] != "quantum_safe"]
    if weak:
        t = weak[0]
        return Check("re-scan", False,
                     f"still {t['risk']}: {', '.join(t['algorithms'])} (target {t['target']})")
    return Check("re-scan", True,
                 f"{', '.join(a for t in mine for a in t['algorithms'])} -> quantum_safe")
def check_dynamic(code, test_code):
    result = run_in_sandbox(code, test_code)
    if not result.get("ran"):
        return Check("sandbox run", False, result.get("error", "did not run"))
    if "error" in result:
        label = "dataset test" if result.get("tests") is None and test_code.strip() else "self-test"
        return Check("sandbox run", False, f"{label} failed: {result['error']}")
    if result.get("tests"):
        return Check("sandbox run", True, "ran and passed the dataset's test code")
    if result.get("selftest"):
        return Check("sandbox run", True, "ran and passed its self-test")
    return Check("sandbox run", True, "ran without errors (no test available, so behaviour "
                                      "is not proven)")


# --------------------------------------------------------------------------- #
# Category validators (static rules)
# --------------------------------------------------------------------------- #
def _hash_mac_rules(code):
    problems = []
    if re.search(r"\bhashlib\.(md5|sha1)\b|[\"'](md5|sha1)[\"']", code):
        problems.append("MD5/SHA-1 still referenced")
    # comparing digests with == leaks timing; hmac.compare_digest is the safe form
    if re.search(r"(hexdigest|digest)\(\)\s*==", code):
        problems.append("digest compared with == (use hmac.compare_digest)")
    return problems


def _cipher_rules(code):
    problems = []
    if re.search(r"MODE_ECB|modes\.ECB", code):
        problems.append("ECB mode is not allowed")
    if re.search(r"\b(nonce|iv)\s*=\s*b?[\"']", code):
        problems.append("fixed nonce/IV literal")
    if re.search(r"\bkey\s*=\s*b?[\"']", code):
        problems.append("hard-coded key literal")
    return problems


def _signature_rules(code):
    problems = []
    if re.search(r"\b(rsa|ec|dsa|ed25519|ed448)\.generate_private_key|RSA\.generate", code):
        problems.append("classical signature key generation remains")
    return problems


def _kem_rules(code):
    problems = []
    if re.search(r"\b(x25519|x448|dh|ec)\.\w*generate_private_key|\.exchange\(", code):
        problems.append("classical key exchange remains")
    return problems


# diagram boxes: four category-specific validators
VALIDATORS = {
    "hash": ("hash_mac", _hash_mac_rules), "mac": ("hash_mac", _hash_mac_rules),
    "symmetric": ("cipher", _cipher_rules), "aead": ("cipher", _cipher_rules),
    "signature": ("signature", _signature_rules),
    "key_exchange": ("kem", _kem_rules),
}


def verify(code, family, test_code=""):
    """Run all checks for one migration result and return a VerificationReport."""
    name, rules = VALIDATORS.get(family, ("generic", lambda c: []))
    report = VerificationReport(validator=name)
    syntax = check_syntax(code)
    report.checks.append(syntax)
    if not syntax.passed:          # nothing else can run on broken code
        return report
    report.checks.append(check_rescan(code, family))
    problems = rules(code)
    report.checks.append(Check(f"{name} rules", not problems, "; ".join(problems)))
    report.checks.append(check_dynamic(code, test_code))
    return report