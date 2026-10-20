"""Stage 2a - Static AST feature extraction.

Turns a code snippet into one fixed-length numeric vector. Nothing is executed;
we only read the syntax tree. The vector has five blocks:

  imports      which crypto libraries are imported
  rule_family  how many rule hits per primitive family
  rule_algo    how many rule hits per algorithm (MD5, RSA, AES-GCM, ...)
  risk         how many hits per quantum-risk class
  motifs       method names that hint at the operation (.sign, .exchange, ...)
  literals     key-size style numbers (16, 32, 2048, ...)
  shape        control-flow shape (functions, classes, try, with, loops ...)
"""
import ast
import math

import numpy as np

from .config import FAMILIES
from .detector import scan_source
from .extractor import build_alias_map
from .rules import RISK, SEVERITY

# Libraries and sub-modules whose presence is a strong hint.
KNOWN_MODULES = [
    "hashlib", "hmac", "secrets", "base64", "os", "jwt", "oqs",
    "cryptography.fernet",
    "cryptography.hazmat.primitives.hashes",
    "cryptography.hazmat.primitives.hmac",
    "cryptography.hazmat.primitives.cmac",
    "cryptography.hazmat.primitives.ciphers",
    "cryptography.hazmat.primitives.ciphers.aead",
    "cryptography.hazmat.primitives.asymmetric.rsa",
    "cryptography.hazmat.primitives.asymmetric.ec",
    "cryptography.hazmat.primitives.asymmetric.dsa",
    "cryptography.hazmat.primitives.asymmetric.dh",
    "cryptography.hazmat.primitives.asymmetric.ed25519",
    "cryptography.hazmat.primitives.asymmetric.x25519",
    "cryptography.hazmat.primitives.asymmetric.padding",
    "cryptography.hazmat.primitives.asymmetric.mldsa",
    "cryptography.hazmat.primitives.asymmetric.mlkem",
    "cryptography.hazmat.primitives.kdf",
    "cryptography.hazmat.primitives.serialization",
    "Crypto.Cipher", "Crypto.Hash", "Crypto.PublicKey", "Crypto.Signature",
    "Crypto.Protocol", "nacl",
]

FAMILY_COLUMNS = FAMILIES
ALGORITHMS = sorted(RISK)
RISK_CLASSES = SEVERITY

MOTIFS = [
    "encrypt", "decrypt", "sign", "verify", "exchange", "encapsulate", "decapsulate",
    "encap_secret", "decap_secret", "digest", "hexdigest", "update", "finalize",
    "compare_digest", "generate_key", "generate_private_key", "generate_keypair",
    "public_key", "derive", "hexlify",
]
KEY_SIZE_LITERALS = [8, 12, 16, 24, 32, 48, 64, 128, 192, 256, 384, 512, 1024, 2048, 3072, 4096]

SHAPE_NODES = [ast.FunctionDef, ast.ClassDef, ast.With, ast.Try, ast.For, ast.While,
               ast.AsyncFunctionDef, ast.Lambda, ast.Return]


def _feature_names():
    names = [f"import:{m}" for m in KNOWN_MODULES]
    names += [f"family:{f}" for f in FAMILY_COLUMNS]
    names += [f"algo:{a}" for a in ALGORITHMS]
    names += [f"risk:{r}" for r in RISK_CLASSES]
    names += [f"motif:{m}" for m in MOTIFS]
    names += [f"literal:{n}" for n in KEY_SIZE_LITERALS]
    names += [f"shape:{n.__name__}" for n in SHAPE_NODES]
    names += ["shape:log_lines", "shape:log_calls"]
    return names


FEATURE_NAMES = _feature_names()
FEATURE_DIM = len(FEATURE_NAMES)


def extract_features(source):
    """Return a float vector of length FEATURE_DIM for one snippet.

    Code that does not parse (the dataset has a few fragments) gives an all-zero vector;
    the neural branch still sees the raw text in that case.
    """
    vec = np.zeros(FEATURE_DIM, dtype=np.float32)
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return vec
    index = {name: i for i, name in enumerate(FEATURE_NAMES)}

    # imports: a module counts if any imported name starts with it
    imported = set(build_alias_map(tree).values())
    for mod in KNOWN_MODULES:
        if any(i == mod or i.startswith(mod + ".") for i in imported):
            vec[index[f"import:{mod}"]] = 1

    # rule hits, aggregated over all units in the snippet
    for unit in scan_source(source):
        for ev in unit.evidence:
            if ev["role"] == "param" or not ev["family"]:
                continue
            vec[index[f"family:{ev['family']}"]] += 1
            if ev["algorithm"] in ALGORITHMS:
                vec[index[f"algo:{ev['algorithm']}"]] += 1
        if unit.risk in RISK_CLASSES:
            vec[index[f"risk:{unit.risk}"]] += 1

    # motifs, literals, shape: one pass over the tree
    calls = 0
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            calls += 1
            if isinstance(node.func, ast.Attribute) and node.func.attr in MOTIFS:
                vec[index[f"motif:{node.func.attr}"]] = 1
        elif isinstance(node, ast.Constant) and type(node.value) is int:
            if node.value in KEY_SIZE_LITERALS:
                vec[index[f"literal:{node.value}"]] = 1
        for kind in SHAPE_NODES:
            if isinstance(node, kind):
                vec[index[f"shape:{kind.__name__}"]] += 1
    vec[index["shape:log_lines"]] = math.log1p(len(source.splitlines()))
    vec[index["shape:log_calls"]] = math.log1p(calls)
    return vec


def extract_matrix(sources):
    """Stack vectors for many snippets into an (n, FEATURE_DIM) matrix."""
    return np.vstack([extract_features(s) for s in sources])