"""Small demo file used to try the scanner. Nothing here is meant to run."""
import hashlib as h
import hmac
import jwt
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes as hh
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from Crypto.Cipher import AES
import oqs


def hash_password(pw):
    return h.md5(pw.encode()).hexdigest()


def sign_document(data):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.sign(data, padding.PSS(mgf=None, salt_length=32), hh.SHA256())


def derive_shared(peer):
    key = ec.generate_private_key(ec.SECP256R1())
    return key.exchange(ec.ECDH(), peer)


def seal_blob(blob, key):
    return AESGCM(key).encrypt(b"n" * 12, blob, None)


def make_cookie(payload, secret):
    return Fernet(secret).encrypt(payload)


def old_encrypt(data):
    cipher = AES.new(b"0123456789abcdef", AES.MODE_CBC)
    return cipher.encrypt(data)


def tag_message(key, msg):
    return hmac.new(key, msg, "sha1").hexdigest()


def issue_token(claims, private_pem):
    return jwt.encode(claims, private_pem, algorithm="RS256")


def pq_handshake():
    with oqs.KeyEncapsulation("ML-KEM-768") as kem:
        return kem.generate_keypair()


def sign_payload(payload):
    # wrapper around some internal helper, no direct library call here
    return _backend().do_it(payload)


def format_name(first, last):
    return f"{last}, {first}"