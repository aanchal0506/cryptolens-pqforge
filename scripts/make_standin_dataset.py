"""Generate a SYNTHETIC stand-in for the paper's 800-entry dataset.

WHY THIS EXISTS
  The real dataset (DOI 10.21950/7GK4MJ, e-cienciaDatos) could not be downloaded from the
  build environment. This script lets the whole pipeline be trained, tested and demoed
  without it. Numbers produced from this file say NOTHING about real-world accuracy:
  the snippets are template-generated and far more regular than real repositories.

  To get real results: download the real dataset into data/ and run `python -m cryptolens.train`
  (see data/README.md). This stand-in is then ignored.

Usage:  python scripts/make_standin_dataset.py [--out data/standin_dataset.jsonl] [--n 800]
"""
import argparse
import json
import random
from pathlib import Path

NAMES = ["data", "payload", "message", "blob", "content", "record", "buf", "secret_text"]
FUNCS = ["process", "protect", "handle", "compute", "build", "make", "prepare", "run"]
KEYS = ["key", "secret", "k", "master_key", "shared_key"]


def pick(rng, pool):
    return rng.choice(pool)


# --- each template returns a code string; they differ in library, algorithm and style --- #
def hash_templates(rng):
    d, f = pick(rng, NAMES), pick(rng, FUNCS)
    algo = pick(rng, ["md5", "sha1", "sha256", "sha512", "sha224", "sha384"])
    return rng.choice([
        f"import hashlib\n\ndef {f}_digest({d}):\n    return hashlib.{algo}({d}).hexdigest()\n",
        f"import hashlib\n\ndef {f}_fingerprint({d}):\n    h = hashlib.{algo}()\n    h.update({d})\n    return h.hexdigest()\n",
        f"import hashlib\n\ndef {f}_id({d}):\n    return hashlib.new('{algo}', {d}).digest()\n",
        f"from cryptography.hazmat.primitives import hashes\n\ndef {f}_hash({d}):\n    digest = hashes.Hash(hashes.{algo.upper()}())\n    digest.update({d})\n    return digest.finalize()\n",
        f"from Crypto.Hash import {algo.upper()}\n\ndef {f}_checksum({d}):\n    return {algo.upper()}.new({d}).hexdigest()\n",
    ])


def mac_templates(rng):
    d, f, k = pick(rng, NAMES), pick(rng, FUNCS), pick(rng, KEYS)
    algo = pick(rng, ["md5", "sha1", "sha256", "sha512"])
    return rng.choice([
        f"import hmac\nimport hashlib\n\ndef {f}_tag({k}, {d}):\n    return hmac.new({k}, {d}, hashlib.{algo}).hexdigest()\n",
        f"import hmac\n\ndef {f}_sign({k}, {d}):\n    return hmac.new({k}, {d}, '{algo}').digest()\n",
        f"import hmac\nimport hashlib\n\ndef {f}_check({k}, {d}, tag):\n    expected = hmac.new({k}, {d}, digestmod=hashlib.{algo}).digest()\n    return hmac.compare_digest(expected, tag)\n",
        f"from cryptography.hazmat.primitives import hashes, hmac\n\ndef {f}_mac({k}, {d}):\n    h = hmac.HMAC({k}, hashes.{algo.upper()}())\n    h.update({d})\n    return h.finalize()\n",
        f"from cryptography.hazmat.primitives.cmac import CMAC\nfrom cryptography.hazmat.primitives.ciphers import algorithms\n\ndef {f}_cmac({k}, {d}):\n    c = CMAC(algorithms.AES({k}))\n    c.update({d})\n    return c.finalize()\n",
    ])


def symmetric_templates(rng):
    d, f, k = pick(rng, NAMES), pick(rng, FUNCS), pick(rng, KEYS)
    return rng.choice([
        f"from Crypto.Cipher import AES\n\ndef {f}_encrypt({k}, {d}):\n    cipher = AES.new({k}, AES.MODE_CBC)\n    return cipher.encrypt({d})\n",
        f"from Crypto.Cipher import AES\n\ndef {f}_ecb({k}, {d}):\n    return AES.new({k}, AES.MODE_ECB).encrypt({d})\n",
        f"from Crypto.Cipher import DES\n\ndef {f}_legacy({k}, {d}):\n    return DES.new({k}, DES.MODE_CBC).encrypt({d})\n",
        f"from cryptography.fernet import Fernet\n\ndef {f}_token({k}, {d}):\n    return Fernet({k}).encrypt({d})\n",
        f"from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes\n\ndef {f}_ctr({k}, nonce, {d}):\n    enc = Cipher(algorithms.AES({k}), modes.CTR(nonce)).encryptor()\n    return enc.update({d}) + enc.finalize()\n",
        f"from Crypto.Cipher import ARC4\n\ndef {f}_stream({k}, {d}):\n    return ARC4.new({k}).encrypt({d})\n",
        f"from Crypto.Cipher import Blowfish\n\ndef {f}_bf({k}, {d}):\n    return Blowfish.new({k}, Blowfish.MODE_CBC).encrypt({d})\n",
    ])


def aead_templates(rng):
    d, f, k = pick(rng, NAMES), pick(rng, FUNCS), pick(rng, KEYS)
    return rng.choice([
        f"from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n\ndef {f}_seal({k}, nonce, {d}):\n    return AESGCM({k}).encrypt(nonce, {d}, None)\n",
        f"from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n\ndef {f}_open({k}, nonce, {d}):\n    return AESGCM({k}).decrypt(nonce, {d}, b'hdr')\n",
        f"from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305\n\ndef {f}_chacha({k}, nonce, {d}):\n    return ChaCha20Poly1305({k}).encrypt(nonce, {d}, None)\n",
        f"from Crypto.Cipher import AES\n\ndef {f}_gcm({k}, {d}):\n    cipher = AES.new({k}, AES.MODE_GCM)\n    ct, tag = cipher.encrypt_and_digest({d})\n    return cipher.nonce, ct, tag\n",
        f"from cryptography.hazmat.primitives.ciphers.aead import AESCCM\n\ndef {f}_ccm({k}, nonce, {d}):\n    return AESCCM({k}).encrypt(nonce, {d}, None)\n",
    ])


def signature_templates(rng):
    d, f = pick(rng, NAMES), pick(rng, FUNCS)
    return rng.choice([
        f"from cryptography.hazmat.primitives import hashes\nfrom cryptography.hazmat.primitives.asymmetric import rsa, padding\n\ndef {f}_sign({d}):\n    key = rsa.generate_private_key(public_exponent=65537, key_size={rng.choice([2048, 3072, 4096])})\n    return key.sign({d}, padding.PKCS1v15(), hashes.SHA256())\n",
        f"from cryptography.hazmat.primitives import hashes\nfrom cryptography.hazmat.primitives.asymmetric import ec\n\ndef {f}_ecdsa(private_key, {d}):\n    return private_key.sign({d}, ec.ECDSA(hashes.SHA256()))\n",
        f"from cryptography.hazmat.primitives.asymmetric import ed25519\n\ndef {f}_ed({d}):\n    key = ed25519.Ed25519PrivateKey.generate()\n    return key.sign({d})\n",
        f"from cryptography.hazmat.primitives import hashes\nfrom cryptography.hazmat.primitives.asymmetric import dsa\n\ndef {f}_dsa({d}):\n    key = dsa.generate_private_key(key_size=2048)\n    return key.sign({d}, hashes.SHA256())\n",
        f"import jwt\n\ndef {f}_token(claims, pem):\n    return jwt.encode(claims, pem, algorithm='{rng.choice(['RS256', 'ES256', 'RS512'])}')\n",
    ])


def kex_templates(rng):
    f = pick(rng, FUNCS)
    return rng.choice([
        f"from cryptography.hazmat.primitives.asymmetric import ec\n\ndef {f}_ecdh(peer_public):\n    key = ec.generate_private_key(ec.SECP256R1())\n    return key.exchange(ec.ECDH(), peer_public)\n",
        f"from cryptography.hazmat.primitives.asymmetric import x25519\n\ndef {f}_x25519(peer_public):\n    private = x25519.X25519PrivateKey.generate()\n    return private.exchange(peer_public)\n",
        f"from cryptography.hazmat.primitives.asymmetric import dh\n\ndef {f}_dh(parameters, peer_public):\n    private = parameters.generate_private_key()\n    return private.exchange(peer_public)\n",
        f"from cryptography.hazmat.primitives.asymmetric import x448\n\ndef {f}_x448(peer_public):\n    return x448.X448PrivateKey.generate().exchange(peer_public)\n",
    ])


FAMILY_MAKERS = {
    "hash": ("Hashing", hash_templates), "mac": ("Message Authentication Code", mac_templates),
    "symmetric": ("Symmetric Encryption", symmetric_templates),
    "aead": ("Authenticated Encryption", aead_templates),
    "signature": ("Digital Signature", signature_templates),
    "key_exchange": ("Key Exchange", kex_templates),
}


def rename_variants(code, rng):
    """Light noise: sometimes add a docstring or a logging line so snippets are not all alike."""
    if rng.random() < 0.3:
        code = code.replace("):\n", "):\n    \"\"\"Helper used by the service layer.\"\"\"\n", 1)
    if rng.random() < 0.2:
        code = "import logging\n\nlog = logging.getLogger(__name__)\n\n" + code
    return code


def generate(n, seed=7):
    rng = random.Random(seed)
    families = list(FAMILY_MAKERS)
    entries = []
    per_family = int(n * 0.9) // len(families)
    for family in families:
        label, maker = FAMILY_MAKERS[family]
        for i in range(per_family):
            code = rename_variants(maker(rng), rng)
            entries.append({"id": f"standin-{family}-{i}", "migration_category": label,
                            "pre_quantum_code": code, "post_quantum_code": "", "test_code": ""})
    while len(entries) < n:                      # remaining ~10%: two families in one snippet
        a, b = rng.sample(families, 2)
        code = FAMILY_MAKERS[a][1](rng) + "\n\n" + FAMILY_MAKERS[b][1](rng)
        entries.append({"id": f"standin-combined-{len(entries)}",
                        "migration_category": "Combined", "pre_quantum_code": code,
                        "post_quantum_code": "", "test_code": ""})
    rng.shuffle(entries)
    return entries


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(Path(__file__).resolve().parent.parent / "data" /
                                         "standin_dataset.jsonl"))
    ap.add_argument("--n", type=int, default=800)
    args = ap.parse_args()
    rows = generate(args.n)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row) + "\n")
    print(f"wrote {len(rows)} synthetic entries to {args.out}")