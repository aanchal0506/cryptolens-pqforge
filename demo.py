import hashlib
import hmac
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding, x25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def file_checksum(data):
    # 1. MD5: already broken
    return hashlib.md5(data).hexdigest()


def content_fingerprint(data):
    # 2. SHA-256: weakened by Grover (policy flag)
    return hashlib.sha256(data).hexdigest()


def sign_message(private_key, message):
    # 3. RSA signature: broken by Shor
    return private_key.sign(
        message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
        hashes.SHA256(),
    )


def make_session_key(peer_public_key):
    # 4. X25519 key exchange: broken by Shor
    private_key = x25519.X25519PrivateKey.generate()
    return private_key.exchange(peer_public_key)


def encrypt_record(key, data):
    # 5. AES in ECB mode: weak mode, Grover-weakened
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    enc = cipher.encryptor()
    return enc.update(data) + enc.finalize()


def api_tag(secret, payload):
    # 6. HMAC-SHA256
    return hmac.new(secret, payload, hashlib.sha256).hexdigest()


def secure_upload(data, key):
    # 7. THREE problems in one function: MD5 + AES-ECB + RSA
    digest = hashlib.md5(data).hexdigest()
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return digest, enc, priv


def seal_modern(data):
    # 8. Already fine: AES-256-GCM with a fresh nonce
    key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, data, None)


def modern_hash(data):
    # 9. Already fine: SHA3-256
    return hashlib.sha3_256(data).hexdigest()


def add_numbers(a, b):
    # 10. Not cryptography at all
    return a + b
