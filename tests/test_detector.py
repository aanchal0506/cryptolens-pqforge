from cryptolens import scan_source


def one(src, name=None):
    res = scan_source(src)
    if name:
        res = [r for r in res if r.unit == name]
    assert len(res) == 1, [r.unit for r in res]
    return res[0]


def test_alias_import_resolves():
    r = one("import hashlib as hx\ndef f(p):\n    return hx.sha1(p).hexdigest()\n", "f")
    assert r.families == ["hash"] and r.algorithms == ["SHA-1"]
    assert r.risk == "already_deprecated"


def test_from_import_alias():
    src = ("from cryptography.hazmat.primitives import hashes as hh\n"
           "from cryptography.hazmat.primitives.asymmetric import rsa\n"
           "def f(d):\n    k = rsa.generate_private_key(65537, 2048)\n"
           "    return k.sign(d, None, hh.SHA256())\n")
    r = one(src, "f")
    assert r.families == ["signature"]          # the hash is only supporting
    assert r.algorithms == ["RSA"]
    assert r.risk == "broken_by_shor"
    assert r.target == "ML-DSA-87"


def test_key_size_positional():
    src = ("from cryptography.hazmat.primitives.asymmetric import rsa\n"
           "def f():\n    return rsa.generate_private_key(65537, 3072)\n")
    ev = one(src, "f").evidence[0]
    assert ev["params"]["key_size"] == 3072


def test_ec_exchange_becomes_ecdh():
    src = ("from cryptography.hazmat.primitives.asymmetric import ec\n"
           "def f(peer):\n    k = ec.generate_private_key(ec.SECP256R1())\n"
           "    return k.exchange(ec.ECDH(), peer)\n")
    r = one(src, "f")
    assert r.families == ["key_exchange"] and r.algorithms == ["ECDH"]
    assert r.target == "ML-KEM-1024"


def test_ec_sign_becomes_ecdsa():
    src = ("from cryptography.hazmat.primitives.asymmetric import ec\n"
           "def f(m):\n    k = ec.generate_private_key(ec.SECP256R1())\n"
           "    return k.sign(m, None)\n")
    assert one(src, "f").algorithms == ["ECDSA"]


def test_ec_without_motif_is_ambiguous():
    src = ("from cryptography.hazmat.primitives.asymmetric import ec\n"
           "def f():\n    return ec.generate_private_key(ec.SECP256R1())\n")
    r = one(src, "f")
    assert r.status == "ambiguous" and r.confidence < 1


def test_hmac_digest_read_from_call():
    r = one("import hmac\ndef f(k, m):\n    return hmac.new(k, m, 'sha1').digest()\n", "f")
    assert r.families == ["mac"] and r.algorithms == ["HMAC-SHA1"]


def test_jwt_algorithm_literal():
    src = "import jwt\ndef f(c, k):\n    return jwt.encode(c, k, algorithm='RS256')\n"
    r = one(src, "f")
    assert r.families == ["signature"] and r.algorithms == ["RSA"]


def test_jwt_without_literal_is_ignored():
    src = "import jwt\ndef f(c, k, a):\n    return jwt.encode(c, k, algorithm=a)\n"
    assert one(src, "f").status == "no_crypto"


def test_combined_unit():
    src = ("import hashlib, hmac\n"
           "def f(k, m):\n    d = hashlib.sha256(m).digest()\n"
           "    return hmac.new(k, d, 'sha256').digest()\n")
    r = one(src, "f")
    assert r.combined and r.families == ["hash", "mac"]


def test_wrapper_goes_to_model():
    r = one("def sign_it(x):\n    return helper(x)\n", "sign_it")
    assert r.status == "needs_model"


def test_plain_function_is_not_crypto():
    assert one("def add(a, b):\n    return a + b\n", "add").status == "no_crypto"


def test_nested_function_not_double_counted():
    src = ("import hashlib\ndef outer():\n    def inner(x):\n"
           "        return hashlib.md5(x)\n    return inner\n")
    res = {r.unit: r for r in scan_source(src)}
    assert res["outer.inner"].algorithms == ["MD5"]
    assert res["outer"].status == "no_crypto"


def test_method_gets_class_prefix():
    src = ("import hashlib\nclass A:\n    def h(self, x):\n"
           "        return hashlib.sha256(x)\n")
    assert "A.h" in {r.unit for r in scan_source(src)}


def test_pqc_kem_is_quantum_safe():
    src = ("import oqs\ndef f():\n    with oqs.KeyEncapsulation('ML-KEM-768') as k:\n"
           "        return k.generate_keypair()\n")
    r = one(src, "f")
    assert r.risk == "quantum_safe" and r.families == ["key_exchange"]