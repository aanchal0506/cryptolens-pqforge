"""Layer 1: rule based detection on top of the AST units."""
import ast
import re
from dataclasses import dataclass, field, asdict

from .extractor import extract_units
from .rules import RULES, RISK, KEX_TARGETS, SEVERITY

NAME_HINT = re.compile(r"sign|verif|encrypt|decrypt|cipher|digest|hmac|keygen|secret|nonce|seal",
                       re.I)
DIGEST_NAMES = {"md5": "MD5", "sha1": "SHA-1", "sha224": "SHA-224", "sha256": "SHA-256",
                "sha384": "SHA-384", "sha512": "SHA-512", "sha3_256": "SHA3-256",
                "sha3_512": "SHA3-512"}
JWT_ALGS = {"HS256": ("mac", "HMAC-SHA256"), "HS384": ("mac", "HMAC-SHA256"),
            "HS512": ("mac", "HMAC-SHA256"), "RS256": ("signature", "RSA"),
            "RS384": ("signature", "RSA"), "RS512": ("signature", "RSA"),
            "PS256": ("signature", "RSA"), "ES256": ("signature", "EC"),
            "ES384": ("signature", "EC"), "ES512": ("signature", "EC"),
            "EdDSA": ("signature", "Ed25519")}


@dataclass
class Detection:
    line: int
    rule: str
    family: str
    algorithm: str
    role: str = "primary"
    params: dict = field(default_factory=dict)


@dataclass
class UnitResult:
    file: str
    unit: str
    start: int
    end: int
    families: list
    algorithms: list
    combined: bool
    risk: str
    target: str
    status: str            # detected | ambiguous | needs_model | no_crypto
    confidence: float
    source: str            # which layer decided
    evidence: list
    threats: list = field(default_factory=list)   # one entry per weak primitive family


def _dotted(node):
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return list(reversed(parts))
    return None


def _calls(stmts):
    found, stack = [], list(stmts)
    while stack:
        n = stack.pop()
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if isinstance(n, ast.Call):
            found.append(n)
        stack.extend(ast.iter_child_nodes(n))
    return sorted(found, key=lambda c: (c.lineno, c.col_offset))


def _const(node):
    return node.value if isinstance(node, ast.Constant) else None


def _tail(node):
    d = _dotted(node)
    return d[-1] if d else None


def _generic_params(call, pos):
    p = {}
    for name, arg in zip(pos or [], call.args):
        if _const(arg) is not None:
            p[name] = _const(arg)
    for kw in call.keywords:
        if kw.arg and _const(kw.value) is not None:
            p[kw.arg] = _const(kw.value)
    for arg in list(call.args) + [k.value for k in call.keywords]:
        t = _tail(arg)
        if t and t.startswith("MODE_"):
            p["mode"] = t[5:]
    return p


def _special(kind, call, det, params):
    if kind == "hashlib_new" and call.args and isinstance(_const(call.args[0]), str):
        key = _const(call.args[0]).lower().replace("-", "")
        det.algorithm = DIGEST_NAMES.get(key, key.upper())
    elif kind == "hmac":
        dm = call.args[2] if len(call.args) > 2 else None
        for kw in call.keywords:
            if kw.arg == "digestmod":
                dm = kw.value
        name = None
        if dm is not None:
            name = (_const(dm) if isinstance(_const(dm), str) else _tail(dm))
        if name:
            alg = DIGEST_NAMES.get(str(name).lower().replace("-", ""))
            if alg:
                # SHA-256 -> HMAC-SHA256, but SHA3-256 -> HMAC-SHA3-256
                det.algorithm = "HMAC-" + alg.replace("SHA-", "SHA")
                params["digest"] = alg
    elif kind == "aes_new":
        key = call.args[0] if call.args else None
        if isinstance(_const(key), (bytes, str)):
            params["key_bytes"] = len(_const(key))
            if params["key_bytes"] == 32:
                det.algorithm = "AES-256"
    elif kind == "jwt":
        algs = []
        for kw in call.keywords:
            if kw.arg == "algorithm" and isinstance(_const(kw.value), str):
                algs = [_const(kw.value)]
            if kw.arg == "algorithms" and isinstance(kw.value, (ast.List, ast.Tuple)):
                algs = [_const(e) for e in kw.value.elts if isinstance(_const(e), str)]
        for a in algs:
            if a in JWT_ALGS:
                det.family, det.algorithm = JWT_ALGS[a]
                params["jwt_alg"] = a
                return True
        return False
    elif kind == "aes_keygen":
        bits = params.get("bit_length", _const(call.args[0]) if call.args else None)
        if bits == 256:
            det.algorithm = "AES-256-GCM"
    elif kind == "oqs" and call.args and isinstance(_const(call.args[0]), str):
        params["scheme"] = _const(call.args[0])
    return True


def detect_in_unit(unit, aliases):
    detections, motifs = [], set()
    for call in _calls(unit.stmts):
        if isinstance(call.func, ast.Attribute):
            motifs.add(call.func.attr)
        parts = _dotted(call.func)
        if not parts or parts[0] not in aliases:
            continue
        qualified = ".".join([aliases[parts[0]]] + parts[1:])
        rule = RULES.get(qualified)
        if rule is None:
            continue
        role = rule.get("role", "primary")
        if role == "param":
            detections.append(Detection(call.lineno, qualified, "", "", "param",
                                        {rule["param"][0]: rule["param"][1]}))
            continue
        det = Detection(call.lineno, qualified, rule.get("family", ""),
                        rule.get("algorithm", ""), role)
        params = _generic_params(call, rule.get("pos"))
        if rule.get("special") and not _special(rule["special"], call, det, params):
            continue
        det.params = params
        detections.append(det)
    return detections, motifs


def _resolve(detections, motifs):
    """Use method names like .sign / .exchange to settle RSA and EC."""
    ambiguous = False
    for d in detections:
        if d.algorithm == "EC":
            if "exchange" in motifs:
                d.family, d.algorithm = "key_exchange", "ECDH"
            elif motifs & {"sign", "verify", "signer", "verifier"}:
                d.algorithm = "ECDSA"
            else:
                ambiguous = True
        elif d.algorithm == "RSA" and d.family == "signature":
            if motifs & {"encrypt", "decrypt"} and not motifs & {"sign", "verify"}:
                d.family = "key_exchange"
    return ambiguous


def _refine(detections):
    """A specific detection replaces the generic one in the same unit,
    e.g. AESGCM.generate_key(bit_length=256) makes plain 'AES-GCM' redundant."""
    if any(d.algorithm == "AES-256-GCM" for d in detections):
        return [d for d in detections if d.algorithm != "AES-GCM"]
    return detections


def _implied_by_padding(detections, real, motifs):
    """The key may be created elsewhere (self.key, an argument), but an RSA padding object
    plus a sign/encrypt call still reveals the algorithm."""
    if any(d.role == "primary" for d in real):
        return []
    pads = {d.params.get("padding") for d in detections if d.role == "param"}
    line = next((d.line for d in detections if d.role == "param"), 0)
    if pads & {"PSS", "PKCS1v15"} and motifs & {"sign", "verify"}:
        return [Detection(line, "padding", "signature", "RSA")]
    if "OAEP" in pads and motifs & {"encrypt", "decrypt"}:
        return [Detection(line, "padding", "key_exchange", "RSA")]
    return []


def make_threat(family, algorithms, line):
    """One threat = one primitive family inside a unit, with its own risk and target."""
    algos = sorted(set(algorithms))
    if "AES-256-GCM" in algos:          # a 256-bit key helper makes plain AES-GCM redundant
        algos = [a for a in algos if a != "AES-GCM"]
    worst, target = "quantum_safe", ""
    for a in algos:
        risk, tgt = RISK.get(a, ("needs_review", None))
        if family == "key_exchange" and a in KEX_TARGETS:
            tgt = KEX_TARGETS[a]
        if SEVERITY.index(risk) >= SEVERITY.index(worst):
            worst, target = risk, tgt or target
    return {"family": family, "algorithms": algos, "risk": worst, "target": target, "line": line}


def _threats_of(primary):
    groups = {}
    for d in primary:
        groups.setdefault(d.family, []).append(d)
    found = [make_threat(f, [d.algorithm for d in ds], min(d.line for d in ds))
             for f, ds in groups.items()]
    return sorted(found, key=lambda t: t["line"])


def classify_unit(unit, aliases):
    detections, motifs = detect_in_unit(unit, aliases)
    real = [d for d in detections if d.role != "param" and d.family]
    real += _implied_by_padding(detections, real, motifs)
    ambiguous = _resolve(real, motifs)
    real = _refine(real)
    primary = [d for d in real if d.role == "primary"] or real
    families = sorted({d.family for d in primary})
    algos = sorted({d.algorithm for d in primary})
    target, worst = "", "quantum_safe"
    for d in primary:
        risk, tgt = RISK.get(d.algorithm, ("needs_review", None))
        if d.family == "key_exchange" and d.algorithm in KEX_TARGETS:
            tgt = KEX_TARGETS[d.algorithm]
        if SEVERITY.index(risk) >= SEVERITY.index(worst):
            worst = risk
            target = tgt or target
    if primary:
        status = "ambiguous" if ambiguous else "detected"
        conf = 0.7 if ambiguous else 1.0
        source = "rule"
    elif NAME_HINT.search(unit.name):
        status, conf, source, worst = "needs_model", 0.0, "none", "unknown"
    else:
        status, conf, source, worst = "no_crypto", 1.0, "rule", "not_crypto"
    evidence = [asdict(d) for d in detections]
    return UnitResult(unit.file, unit.name, unit.start, unit.end, families, algos,
                      len(families) > 1, worst, target, status, conf, source, evidence,
                      _threats_of(primary) if status in ("detected", "ambiguous") else [])


def scan_source(source, filename="<string>"):
    units, aliases = extract_units(source, filename)
    return [classify_unit(u, aliases) for u in units]


def merge_results(results, name="<snippet>"):
    """Collapse the per-unit results of one snippet into a single result.

    Used when a whole dataset entry (a few functions) is treated as one item.
    """
    if not results:
        return UnitResult("<snippet>", name, 1, 1, [], [], False, "not_crypto", "",
                          "no_crypto", 1.0, "rule", [])
    hits = [r for r in results if r.status in ("detected", "ambiguous")]
    if not hits:
        hinted = [r for r in results if r.status == "needs_model"]
        base = hinted[0] if hinted else results[0]
        return UnitResult(base.file, name, 1, max(r.end for r in results), [], [], False,
                          base.risk, "", base.status, base.confidence, base.source, [])
    families = sorted({f for r in hits for f in r.families})
    algos = sorted({a for r in hits for a in r.algorithms})
    worst = max((r.risk for r in hits), key=lambda x: SEVERITY.index(x) if x in SEVERITY else -1)
    target = next((r.target for r in hits if r.risk == worst and r.target), "")
    # Same rule as _refine, but across units: a 256-bit key helper makes plain AES-GCM
    # redundant (the key generator and the cipher usually sit in different functions).
    if "AES-256-GCM" in algos and "AES-GCM" in algos:
        algos.remove("AES-GCM")
        worst = max((RISK.get(a, ("needs_review", None))[0] for a in algos),
                    key=lambda x: SEVERITY.index(x))
        target = next((RISK[a][1] for a in algos
                       if a in RISK and RISK[a][0] == worst and RISK[a][1]), "")
    status = "detected" if any(r.status == "detected" for r in hits) else "ambiguous"
    conf = min(r.confidence for r in hits)
    evidence = [e for r in hits for e in r.evidence]
    groups = {}
    for r in hits:
        for t in r.threats:
            groups.setdefault(t["family"], []).append(t)
    threats = sorted((make_threat(f, [a for t in ts for a in t["algorithms"]],
                                  min(t["line"] for t in ts)) for f, ts in groups.items()),
                     key=lambda t: t["line"])
    return UnitResult(hits[0].file, name, 1, max(r.end for r in results), families, algos,
                      len(families) > 1, worst, target, status, conf, "rule", evidence, threats)


def scan_snippet(source):
    """Rule-layer result for a whole snippet, or a no_crypto result if it won't parse."""
    try:
        return merge_results(scan_source(source))
    except SyntaxError:
        return UnitResult("<snippet>", "<snippet>", 1, 1, [], [], False, "not_crypto", "",
                          "no_crypto", 0.0, "rule", [])


def scan_path(path):
    import os
    results, files = [], []
    if os.path.isfile(path):
        files = [path]
    else:
        skip = {".git", "venv", ".venv", "site-packages", "node_modules", "__pycache__"}
        for root, dirs, names in os.walk(path):
            dirs[:] = [d for d in dirs if d not in skip]
            files += [os.path.join(root, n) for n in names if n.endswith(".py")]
    for f in sorted(files):
        try:
            with open(f, encoding="utf-8") as fh:
                results += scan_source(fh.read(), f)
        except (SyntaxError, UnicodeDecodeError) as e:
            print(f"skipped {f}: {e}")
    return results