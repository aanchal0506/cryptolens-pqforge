"""Stage 4 - Migration prompt and migration backends.

The classifier label is injected into a ChatML prompt, so the migration LLM is told
exactly which primitive family and algorithm to replace and what to replace it with.
(Without the label the model has to guess, which is the weakness the project targets.)

Two interchangeable backends share one interface:

  TemplateMigrator    offline and deterministic. Hash/MAC code is rewritten in place;
                      cipher, signature and key-exchange code is replaced by a reference
                      implementation built on the `cryptography` package. Each reference
                      template carries a `_selftest()` the verifier can run.
  AnthropicMigrator   calls a Claude model through the Anthropic API. Needs the `anthropic`
                      package and ANTHROPIC_API_KEY. Not exercised in the offline test run.
"""
import os
import re
import textwrap
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from .config import FAMILY_TARGETS

SYSTEM_PROMPT = textwrap.dedent("""\
    You are a cryptography migration engineer. Rewrite the given Python code so that it no
    longer depends on quantum-vulnerable or deprecated primitives.
    Rules:
    - Use the TARGET algorithm given in the request. Use the `cryptography` package, or the
      Python standard library where it is enough.
    - Keep the public function names and signatures unless the primitive forces a change.
    - Never hard-code keys. Never use ECB mode, fixed nonces or an unauthenticated mode.
    - If a FOCUS line is given, the code holds several weak primitives. Change ONLY the one
      named there and leave the rest of the code exactly as it is.
    - Reply with ONE fenced ```python block and nothing else.""")

@dataclass
class MigrationRequest:
    code: str
    family: str          # one of the dataset categories
    algorithm: str       # detected source algorithm(s), may be empty
    target: str          # FIPS-style target
    feedback: str = ""   # verifier error text on a retry
    focus: str = ""      # which threat to fix when the code has several

@dataclass
class MigrationResult:
    code: str
    backend: str
    messages: list = field(default_factory=list)
    note: str = ""


# --------------------------------------------------------------------------- #
# Prompt (ChatML)
# --------------------------------------------------------------------------- #
def build_messages(req, previous_code=""):
    """Return the ChatML message list. On a retry the failed attempt and its error are added."""
    user = (f"MIGRATION CATEGORY: {req.family}\n"
            f"DETECTED ALGORITHM: {req.algorithm or 'unknown'}\n"
            f"TARGET: {req.target or FAMILY_TARGETS.get(req.family, '')}\n"
            + (f"FOCUS: {req.focus}\n" if req.focus else "")
            + f"PRE-QUANTUM CODE:\n{req.code}")
    messages = [{"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user}]
    if req.feedback and previous_code:
        messages += [
            {"role": "assistant", "content": f"```python\n{previous_code}\n```"},
            {"role": "user", "content": "VERIFICATION FAILED:\n" + req.feedback +
             "\nFix these problems and reply with the full corrected code."}]
    return messages


def extract_code_block(reply):
    """Pull the python code out of a model reply (falls back to the raw text)."""
    match = re.search(r"```(?:python)?\s*\n(.*?)```", reply, re.S)
    return (match.group(1) if match else reply).strip() + "\n"


class Migrator(ABC):
    name = "base"

    @abstractmethod
    def migrate(self, req, previous_code=""):
        ...


# --------------------------------------------------------------------------- #
# Offline backend
# --------------------------------------------------------------------------- #
# in-place hash renames: old name -> replacement
_HASH_SWAP = {"md5": "sha3_256", "sha1": "sha3_256", "sha224": "sha3_256",
              "sha256": "sha3_256", "sha384": "sha3_512", "sha512": "sha3_512"}
_CRYPTO_CLASS_SWAP = {"MD5": "SHA3_256", "SHA1": "SHA3_256", "SHA224": "SHA3_256",
                      "SHA256": "SHA3_256", "SHA384": "SHA3_512", "SHA512": "SHA3_512"}


def rewrite_hashes(code):
    """Swap hash names inside hashlib calls, digestmod strings and cryptography `hashes`."""
    # the module may be imported under another name: `import hashlib as h`
    prefixes = ["hashlib"] + re.findall(r"import hashlib as (\w+)", code)
    def attr(m):
        return m.group(1) + "." + _HASH_SWAP[m.group(2)]
    code = re.sub(r"\b(" + "|".join(prefixes) + r")\.(md5|sha1|sha224|sha256|sha384|sha512)\b",
                  attr, code)
    # strings such as hashlib.new("md5") or hmac.new(k, m, "sha256")
    code = re.sub(r"""(["'])(md5|sha1|sha224|sha256|sha384|sha512)\1""",
                  lambda m: m.group(1) + _HASH_SWAP[m.group(2)] + m.group(1), code)
    # from hashlib import sha256
    def from_import(m):
        names = [n.strip() for n in m.group(1).split(",")]
        return "from hashlib import " + ", ".join(_HASH_SWAP.get(n, n) for n in names)
    code = re.sub(r"from hashlib import ([\w, ]+)", from_import, code)
    code = re.sub(r"\bhashes\.(MD5|SHA1|SHA224|SHA256|SHA384|SHA512)\b",
                  lambda m: "hashes." + _CRYPTO_CLASS_SWAP[m.group(1)], code)
    return code


_AEAD_TEMPLATES = {
    "AES-256-GCM": ("AESGCM", "from cryptography.hazmat.primitives.ciphers.aead import AESGCM",
                    "AESGCM.generate_key(bit_length=256)"),
    "ChaCha20-Poly1305": ("ChaCha20Poly1305",
                          "from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305",
                          "ChaCha20Poly1305.generate_key()"),
}


def _cipher_template(target):
    cls, imp, keygen = _AEAD_TEMPLATES.get(target, _AEAD_TEMPLATES["AES-256-GCM"])
    label = target if target in _AEAD_TEMPLATES else "AES-256-GCM"
    return f'''\
"""Authenticated encryption with {label} (migrated)."""
import os

{imp}


def generate_key():
    return {keygen}


def encrypt(key, plaintext, associated_data=None):
    """Return nonce || ciphertext+tag. A fresh random nonce is used for every call."""
    nonce = os.urandom(12)
    return nonce + {cls}(key).encrypt(nonce, plaintext, associated_data)


def decrypt(key, blob, associated_data=None):
    nonce, body = blob[:12], blob[12:]
    return {cls}(key).decrypt(nonce, body, associated_data)


def _selftest():
    key = generate_key()
    blob = encrypt(key, b"hello", b"header")
    assert decrypt(key, blob, b"header") == b"hello"
    tampered = blob[:-1] + bytes([blob[-1] ^ 1])
    try:
        decrypt(key, tampered, b"header")
    except Exception:
        return True
    raise AssertionError("tampered ciphertext was accepted")
'''


def _signature_template(target):
    level = target.split("-")[-1] if target.startswith("ML-DSA-") else "87"
    return f'''\
"""Digital signatures with ML-DSA-{level} (FIPS 204), migrated."""
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA{level}PrivateKey


def generate_keypair():
    private_key = MLDSA{level}PrivateKey.generate()
    return private_key, private_key.public_key()


def sign(private_key, message):
    return private_key.sign(message)


def verify(public_key, signature, message):
    """Return True if the signature is valid, False otherwise."""
    try:
        public_key.verify(signature, message)
        return True
    except Exception:
        return False


def _selftest():
    private_key, public_key = generate_keypair()
    signature = sign(private_key, b"message")
    assert verify(public_key, signature, b"message")
    assert not verify(public_key, signature, b"other message")
    return True
'''


def _kem_template(target):
    size = target.split("-")[-1] if target.startswith("ML-KEM-") else "1024"
    return f'''\
"""Key establishment with ML-KEM-{size} (FIPS 203), migrated."""
from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM{size}PrivateKey


def generate_keypair():
    private_key = MLKEM{size}PrivateKey.generate()
    return private_key, private_key.public_key()


def encapsulate(public_key):
    """Sender side: returns (shared_secret, ciphertext)."""
    return public_key.encapsulate()


def decapsulate(private_key, ciphertext):
    """Receiver side: recovers the same shared secret."""
    return private_key.decapsulate(ciphertext)


def _selftest():
    private_key, public_key = generate_keypair()
    secret_sender, ciphertext = encapsulate(public_key)
    assert decapsulate(private_key, ciphertext) == secret_sender
    return True
'''


class TemplateMigrator(Migrator):
    name = "template"

    def migrate(self, req, previous_code=""):
        messages = build_messages(req, previous_code)
        family, target = req.family, req.target or FAMILY_TARGETS.get(req.family, "")
        if family in ("hash", "mac"):
            code, note = rewrite_hashes(req.code), "in-place hash replacement"
        elif family in ("symmetric", "aead"):
            code, note = _cipher_template(target), "reference AEAD template"
        elif family == "signature":
            code, note = _signature_template(target), "reference ML-DSA template"
        elif family == "key_exchange":
            code, note = _kem_template(target), "reference ML-KEM template"
        else:  # combined / unknown: only the safe in-place part can be done
            code, note = rewrite_hashes(req.code), "partial: only hash names rewritten"
        if not code.endswith("\n"):
            code += "\n"
        return MigrationResult(code, self.name, messages, note)


# --------------------------------------------------------------------------- #
# LLM backend
# --------------------------------------------------------------------------- #
class AnthropicMigrator(Migrator):
    name = "anthropic"

    def __init__(self, model=None, max_tokens=2000):
        self.model = model or os.environ.get("CRYPTOLENS_LLM_MODEL", "claude-sonnet-5-5")
        self.max_tokens = max_tokens

    def migrate(self, req, previous_code=""):
        import anthropic  # imported here so the offline path never needs it
        messages = build_messages(req, previous_code)
        client = anthropic.Anthropic()
        reply = client.messages.create(
            model=self.model, max_tokens=self.max_tokens, system=SYSTEM_PROMPT,
            messages=[m for m in messages if m["role"] != "system"])
        text = "".join(block.text for block in reply.content if block.type == "text")
        return MigrationResult(extract_code_block(text), self.name, messages, self.model)


def build_migrator(kind="template"):
    if kind == "template":
        return TemplateMigrator()
    if kind == "anthropic":
        return AnthropicMigrator()
    raise ValueError(f"unknown migrator {kind!r} (use 'template' or 'anthropic')")