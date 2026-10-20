"""Stage 1 - Ingestion.

Three jobs:
  1. find Python files in a folder (or accept a single file)
  2. load the source paper's dataset (800 entries, six crypto families + combined cases)
  3. provide real non-crypto code to use as negative examples ("none" class)

The dataset loader is deliberately tolerant about column names and file formats,
because we want it to work on the files exactly as published on e-cienciaDatos.
If a column cannot be found it fails loudly and lists what it did find.
"""
import ast
import csv
import json
import random
import re
import sysconfig
import textwrap
from dataclasses import dataclass
from pathlib import Path

from .config import RANDOM_SEED

# Folders that never contain the project's own code.
SKIP_DIRS = {".git", "venv", ".venv", "site-packages", "node_modules", "__pycache__", "build"}


# --------------------------------------------------------------------------- #
# 1. Source files
# --------------------------------------------------------------------------- #
def collect_python_files(path):
    """Return a sorted list of .py files under `path` (or [path] if it is a file)."""
    path = Path(path)
    if path.is_file():
        return [path]
    files = []
    for p in path.rglob("*.py"):
        if not SKIP_DIRS.intersection(p.parts):
            files.append(p)
    return sorted(files)


def read_source(path):
    """Read a file as text; undecodable bytes are replaced instead of crashing the scan."""
    return Path(path).read_text(encoding="utf-8", errors="replace")


# --------------------------------------------------------------------------- #
# 2. Dataset loading
# --------------------------------------------------------------------------- #
@dataclass
class DatasetEntry:
    entry_id: str
    family: str            # one of FAMILIES, "combined" or "none"
    pre_code: str          # pre-quantum code (the classifier input)
    post_code: str = ""    # post-quantum reference solution
    test_code: str = ""    # functional test from the dataset, if it ships one
    algorithm: str = ""    # only filled if the dataset itself has an algorithm column


# Accepted spellings for each field (compared after lower-casing and replacing - with _).
FIELD_ALIASES = {
    "pre": ["pre_quantum_code", "pre_quantum", "pre_code", "prequantum", "source_code",
            "original_code", "code", "input"],
    "post": ["post_quantum_code", "post_quantum", "post_code", "postquantum", "target",
             "migrated_code", "output"],
    "category": ["migration_category", "category", "primitive_family", "family", "primitive",
                 "label"],
    "test": ["test_code", "functional_test", "tests", "test", "oracle"],
    "id": ["id", "entry_id", "name", "index"],
    "algorithm": ["algorithm", "pre_quantum_algorithm", "source_algorithm"],
}


def normalize_category(text):
    """Map the dataset's free-text category onto our label set.

    Order matters: 'authenticated encryption' must be checked before 'encryption'.
    """
    t = str(text).lower().replace("_", " ").replace("-", " ")
    if re.search(r"combin|multi|mixed", t):
        return "combined"
    if re.search(r"authenticated|aead", t):
        return "aead"
    if re.search(r"key (exchange|agreement|encapsulation)|\bkem\b|diffie", t):
        return "key_exchange"
    if re.search(r"signature|signing", t):
        return "signature"
    if re.search(r"\bmac\b|hmac|message authentication", t):
        return "mac"
    if "hash" in t or "digest" in t:
        return "hash"
    if re.search(r"symmetric|cipher|encrypt", t):
        return "symmetric"
    raise ValueError(f"unknown category: {text!r}")


def _pick(record, field):
    """Find the value for a logical field using the alias list."""
    lowered = {str(k).lower().replace("-", "_").replace(" ", "_"): v for k, v in record.items()}
    for alias in FIELD_ALIASES[field]:
        if alias in lowered and lowered[alias] not in (None, ""):
            return lowered[alias]
    return None


def _parse_chatml(record):
    """Handle fine-tuning style rows: {"messages": [{"role":..., "content":...}, ...]}."""
    msgs = record.get("messages") or []
    user = next((m["content"] for m in msgs if m.get("role") == "user"), "")
    asst = next((m["content"] for m in msgs if m.get("role") == "assistant"), "")
    cat = re.search(r"MIGRATION CATEGORY:\s*(.+)", user, re.I)
    code = re.search(r"PRE-QUANTUM CODE:\s*(.+)", user, re.I | re.S)
    if not (cat and code):
        return None
    return {"migration_category": cat.group(1).strip(), "pre_quantum_code": code.group(1).strip(),
            "post_quantum_code": asst}


def _read_records(path):
    """Yield raw dict records from .jsonl / .json / .csv."""
    suffix = path.suffix.lower()
    text = path.read_text(encoding="utf-8", errors="replace")
    if suffix == ".jsonl":
        for line in text.splitlines():
            if line.strip():
                yield json.loads(line)
    elif suffix == ".json":
        data = json.loads(text)
        if isinstance(data, dict):  # {"entries": [...]} or similar
            data = next((v for v in data.values() if isinstance(v, list)), [data])
        yield from data
    elif suffix == ".csv":
        csv.field_size_limit(10_000_000)
        yield from csv.DictReader(text.splitlines())


def load_dataset(path):
    """Load the paper's dataset from a file or a folder of files.

    Returns (entries, skipped) where `skipped` explains every row we could not use.
    """
    path = Path(path)
    files = [path] if path.is_file() else sorted(
        p for p in path.rglob("*") if p.suffix.lower() in {".jsonl", ".json", ".csv"})
    if not files:
        raise FileNotFoundError(f"no .jsonl/.json/.csv files found in {path}")

    entries, skipped = [], []
    for f in files:
        for i, rec in enumerate(_read_records(f)):
            if isinstance(rec, dict) and "messages" in rec:
                rec = _parse_chatml(rec) or rec
            pre, cat = _pick(rec, "pre"), _pick(rec, "category")
            if pre is None or cat is None:
                skipped.append(f"{f.name}[{i}]: missing code or category; columns = {list(rec)}")
                continue
            try:
                family = normalize_category(cat)
            except ValueError as err:
                skipped.append(f"{f.name}[{i}]: {err}")
                continue
            entries.append(DatasetEntry(
                entry_id=str(_pick(rec, "id") or f"{f.stem}-{i}"),
                family=family, pre_code=str(pre),
                post_code=str(_pick(rec, "post") or ""),
                test_code=str(_pick(rec, "test") or ""),
                algorithm=str(_pick(rec, "algorithm") or "")))
    if not entries:
        raise ValueError("dataset loaded but no usable rows. Details:\n" + "\n".join(skipped[:10]))
    return entries, skipped


# --------------------------------------------------------------------------- #
# 3. Negative examples
# --------------------------------------------------------------------------- #
CRYPTO_WORDS = re.compile(
    r"hashlib|hmac|secrets|ssl|crypt|cipher|digest|sha\d|md5|rsa|ecdsa|sign|token|password|nacl|jwt",
    re.I)


def sample_negative_snippets(n, seed=RANDOM_SEED, min_lines=4, max_lines=40):
    """Pick `n` real functions from the Python standard library that contain no crypto.

    Real code is a better negative class than hand-written toy functions: it has the
    same style variety (classes, loops, string handling) as real repositories.
    """
    stdlib = Path(sysconfig.get_paths()["stdlib"])
    rng = random.Random(seed)
    files = [p for p in stdlib.glob("*.py") if p.stat().st_size < 120_000]
    rng.shuffle(files)
    snippets = []
    for f in files:
        try:
            source = f.read_text(encoding="utf-8")
            tree = ast.parse(source)
        except (SyntaxError, UnicodeDecodeError):
            continue
        lines = source.splitlines()
        funcs = [node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)]
        rng.shuffle(funcs)
        for fn in funcs[:3]:
            size = fn.end_lineno - fn.lineno + 1
            # methods are indented inside their class, dedent so the snippet parses alone
            code = textwrap.dedent("\n".join(lines[fn.lineno - 1:fn.end_lineno]))
            if min_lines <= size <= max_lines and not CRYPTO_WORDS.search(code):
                snippets.append(code)
        if len(snippets) >= n:
            break
    return snippets[:n]