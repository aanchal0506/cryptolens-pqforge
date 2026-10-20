"""Rule catalogue: fully-qualified call names -> what they mean.

role:
  primary  - the call itself tells us the unit does this kind of crypto
  support  - normally sits inside another primitive (e.g. a hash used by a signature)
  param    - only adds a parameter (curve, padding), no family of its own
pos: names for positional arguments we want to record as parameters.
"""

H = "cryptography.hazmat.primitives"
ASYM = H + ".asymmetric"
CIPH = H + ".ciphers"

RULES = {
    # ---- hashlib ----
    "hashlib.md5": dict(family="hash", algorithm="MD5"),
    "hashlib.sha1": dict(family="hash", algorithm="SHA-1"),
    "hashlib.sha224": dict(family="hash", algorithm="SHA-224"),
    "hashlib.sha256": dict(family="hash", algorithm="SHA-256"),
    "hashlib.sha384": dict(family="hash", algorithm="SHA-384"),
    "hashlib.sha512": dict(family="hash", algorithm="SHA-512"),
    "hashlib.sha3_256": dict(family="hash", algorithm="SHA3-256"),
    "hashlib.sha3_512": dict(family="hash", algorithm="SHA3-512"),
    "hashlib.blake2b": dict(family="hash", algorithm="BLAKE2b"),
    "hashlib.blake2s": dict(family="hash", algorithm="BLAKE2s"),
    "hashlib.pbkdf2_hmac": dict(family="hash", algorithm="PBKDF2", special="pbkdf2"),
    "hashlib.new": dict(family="hash", algorithm="?", special="hashlib_new"),
    # ---- pyca hashes (usually supporting another primitive) ----
    H + ".hashes.MD5": dict(family="hash", algorithm="MD5", role="support"),
    H + ".hashes.SHA1": dict(family="hash", algorithm="SHA-1", role="support"),
    H + ".hashes.SHA256": dict(family="hash", algorithm="SHA-256", role="support"),
    H + ".hashes.SHA384": dict(family="hash", algorithm="SHA-384", role="support"),
    H + ".hashes.SHA512": dict(family="hash", algorithm="SHA-512", role="support"),
    H + ".hashes.SHA3_256": dict(family="hash", algorithm="SHA3-256", role="support"),
    H + ".hashes.Hash": dict(family="hash", algorithm="?", role="support"),
    # ---- pycryptodome hashes ----
    "Crypto.Hash.MD5.new": dict(family="hash", algorithm="MD5"),
    "Crypto.Hash.SHA1.new": dict(family="hash", algorithm="SHA-1"),
    "Crypto.Hash.SHA256.new": dict(family="hash", algorithm="SHA-256"),
    "Crypto.Hash.SHA512.new": dict(family="hash", algorithm="SHA-512"),
    # ---- MAC ----
    "hmac.new": dict(family="mac", algorithm="HMAC", special="hmac"),
    "hmac.HMAC": dict(family="mac", algorithm="HMAC", special="hmac"),
    H + ".hmac.HMAC": dict(family="mac", algorithm="HMAC"),
    H + ".cmac.CMAC": dict(family="mac", algorithm="CMAC"),
    "Crypto.Hash.HMAC.new": dict(family="mac", algorithm="HMAC"),
    "Crypto.Hash.CMAC.new": dict(family="mac", algorithm="CMAC"),
    # ---- symmetric (unauthenticated) ----
    CIPH + ".algorithms.AES": dict(family="symmetric", algorithm="AES"),
    CIPH + ".algorithms.TripleDES": dict(family="symmetric", algorithm="3DES"),
    CIPH + ".algorithms.ARC4": dict(family="symmetric", algorithm="RC4"),
    CIPH + ".algorithms.Blowfish": dict(family="symmetric", algorithm="Blowfish"),
    "Crypto.Cipher.AES.new": dict(family="symmetric", algorithm="AES", special="aes_new"),
    "Crypto.Cipher.DES3.new": dict(family="symmetric", algorithm="3DES"),
    "Crypto.Cipher.DES.new": dict(family="symmetric", algorithm="DES"),
    "Crypto.Cipher.ARC4.new": dict(family="symmetric", algorithm="RC4"),
    "Crypto.Cipher.Blowfish.new": dict(family="symmetric", algorithm="Blowfish"),
    # ---- AEAD ----
    "cryptography.fernet.Fernet": dict(family="aead", algorithm="Fernet"),
    CIPH + ".aead.AESGCM": dict(family="aead", algorithm="AES-GCM"),
    CIPH + ".aead.AESCCM": dict(family="aead", algorithm="AES-CCM"),
    CIPH + ".aead.ChaCha20Poly1305": dict(family="aead", algorithm="ChaCha20-Poly1305"),
    "nacl.secret.SecretBox": dict(family="aead", algorithm="XSalsa20-Poly1305"),
    # ---- RSA / EC / DH / EdDSA / X25519 ----
    ASYM + ".rsa.generate_private_key": dict(family="signature", algorithm="RSA",
                                            special="asym", pos=["public_exponent", "key_size"]),
    "Crypto.PublicKey.RSA.generate": dict(family="signature", algorithm="RSA",
                                          special="asym", pos=["key_size"]),
    "Crypto.Signature.pkcs1_15.new": dict(family="signature", algorithm="RSA"),
    "Crypto.Signature.pss.new": dict(family="signature", algorithm="RSA"),
    ASYM + ".ec.generate_private_key": dict(family="signature", algorithm="EC", special="asym"),
    ASYM + ".ec.generate_private_key": dict(family="signature", algorithm="EC", special="asym"),
    ASYM + ".ec.ECDSA": dict(family="signature", algorithm="ECDSA"),
    ASYM + ".dsa.generate_private_key": dict(family="signature", algorithm="DSA", pos=["key_size"]),
    ASYM + ".dh.generate_parameters": dict(family="key_exchange", algorithm="DH",
                                           pos=["generator", "key_size"]),
    ASYM + ".ed25519.Ed25519PrivateKey.generate": dict(family="signature", algorithm="Ed25519"),
    ASYM + ".ed448.Ed448PrivateKey.generate": dict(family="signature", algorithm="Ed448"),
    ASYM + ".x25519.X25519PrivateKey.generate": dict(family="key_exchange", algorithm="X25519"),
    ASYM + ".x448.X448PrivateKey.generate": dict(family="key_exchange", algorithm="X448"),
    "nacl.signing.SigningKey": dict(family="signature", algorithm="Ed25519"),
    "nacl.public.PrivateKey": dict(family="key_exchange", algorithm="X25519"),
    # ---- post-quantum, built into pyca/cryptography >= 47 ----
    ASYM + ".mlkem.MLKEM768PrivateKey.generate": dict(family="key_exchange", algorithm="ML-KEM-768"),
    ASYM + ".mlkem.MLKEM1024PrivateKey.generate": dict(family="key_exchange", algorithm="ML-KEM-1024"),
    ASYM + ".mldsa.MLDSA44PrivateKey.generate": dict(family="signature", algorithm="ML-DSA-44"),
    ASYM + ".mldsa.MLDSA65PrivateKey.generate": dict(family="signature", algorithm="ML-DSA-65"),
    ASYM + ".mldsa.MLDSA87PrivateKey.generate": dict(family="signature", algorithm="ML-DSA-87"),
    CIPH + ".aead.AESGCM.generate_key": dict(family="aead", algorithm="AES-GCM", special="aes_keygen"),
    # params only
    ASYM + ".padding.PSS": dict(role="param", param=("padding", "PSS")),
    ASYM + ".padding.PKCS1v15": dict(role="param", param=("padding", "PKCS1v15")),
    ASYM + ".padding.OAEP": dict(role="param", param=("padding", "OAEP")),
    ASYM + ".ec.SECP256R1": dict(role="param", param=("curve", "secp256r1")),
    ASYM + ".ec.SECP384R1": dict(role="param", param=("curve", "secp384r1")),
    ASYM + ".ec.SECP521R1": dict(role="param", param=("curve", "secp521r1")),
    ASYM + ".ec.SECP256K1": dict(role="param", param=("curve", "secp256k1")),
    # ---- JWT ----
    "jwt.encode": dict(special="jwt"),
    "jwt.decode": dict(special="jwt"),
    # ---- post-quantum (liboqs) ----
    "oqs.KeyEncapsulation": dict(family="key_exchange", algorithm="KEM", special="oqs"),
    "oqs.Signature": dict(family="signature", algorithm="PQ-signature", special="oqs"),
}

# algorithm -> (risk class, suggested replacement)
RISK = {
    "MD5": ("already_deprecated", "SHA3-256"),
    "SHA-1": ("already_deprecated", "SHA3-256"),
    "SHA-224": ("weakened_by_grover", "SHA3-256"),
    "SHA-256": ("weakened_by_grover", "SHA3-256"),
    "SHA-384": ("weakened_by_grover", "SHA3-512"),
    "SHA-512": ("weakened_by_grover", "SHA3-512"),
    "SHA3-256": ("quantum_safe", None),
    "SHA3-512": ("quantum_safe", None),
    "BLAKE2b": ("needs_review", "SHA3-256"),
    "BLAKE2s": ("needs_review", "SHA3-256"),
    "PBKDF2": ("needs_review", "SHA3-256 based KDF"),
    "HMAC": ("needs_review", "HMAC-SHA3-256"),
    "HMAC-MD5": ("already_deprecated", "HMAC-SHA3-256"),
    "HMAC-SHA1": ("already_deprecated", "HMAC-SHA3-256"),
    "HMAC-SHA256": ("weakened_by_grover", "HMAC-SHA3-256"),
    "CMAC": ("weakened_by_grover", "HMAC-SHA3-256"),
    "AES": ("weakened_by_grover", "AES-256-GCM"),
    "AES-256": ("quantum_safe", None),
    "3DES": ("already_deprecated", "AES-256-GCM"),
    "DES": ("already_deprecated", "AES-256-GCM"),
    "RC4": ("already_deprecated", "AES-256-GCM"),
    "Blowfish": ("already_deprecated", "AES-256-GCM"),
    "Fernet": ("weakened_by_grover", "ChaCha20-Poly1305"),
    "AES-GCM": ("weakened_by_grover", "ChaCha20-Poly1305"),
    "AES-CCM": ("weakened_by_grover", "ChaCha20-Poly1305"),
    "ChaCha20-Poly1305": ("quantum_safe", None),
    "XSalsa20-Poly1305": ("quantum_safe", None),
    "RSA": ("broken_by_shor", "ML-DSA-87"),
    "DSA": ("broken_by_shor", "ML-DSA-87"),
    "ECDSA": ("broken_by_shor", "ML-DSA-87"),
    "EC": ("broken_by_shor", "ML-DSA-87"),
    "Ed25519": ("broken_by_shor", "ML-DSA-87"),
    "Ed448": ("broken_by_shor", "ML-DSA-87"),
    "DH": ("broken_by_shor", "ML-KEM-1024"),
    "ECDH": ("broken_by_shor", "ML-KEM-1024"),
    "X25519": ("broken_by_shor", "ML-KEM-1024"),
    "X448": ("broken_by_shor", "ML-KEM-1024"),
    "KEM": ("quantum_safe", None),
    "PQ-signature": ("quantum_safe", None),
    "HMAC-SHA512": ("weakened_by_grover", "HMAC-SHA3-256"),
    "HMAC-SHA3-256": ("quantum_safe", None),
    "HMAC-SHA3-512": ("quantum_safe", None),
    "AES-256-GCM": ("quantum_safe", None),
    "ML-KEM-768": ("quantum_safe", None),
    "ML-KEM-1024": ("quantum_safe", None),
    "ML-DSA-44": ("quantum_safe", None),
    "ML-DSA-65": ("quantum_safe", None),
    "ML-DSA-87": ("quantum_safe", None),
}

# when the same algorithm is used for key exchange the target changes
KEX_TARGETS = {"RSA": "ML-KEM-1024", "EC": "ML-KEM-1024", "ECDH": "ML-KEM-1024"}

SEVERITY = ["quantum_safe", "needs_review", "weakened_by_grover",
            "already_deprecated", "broken_by_shor"]