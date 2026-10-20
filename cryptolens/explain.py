"""Plain-language reasons: why a primitive is weak, and why a particular replacement.

The UI shows these next to every threat. The text is fixed (no model involved), so the
explanation is the same every run.
"""

# Why the OLD primitive is a problem, by risk class.
PROBLEM = {
    "broken_by_shor": (
        "Its security rests on a maths problem (factoring, or discrete logarithms, on plain "
        "numbers or on elliptic curves). Shor's algorithm solves exactly those problems fast "
        "on a large quantum computer, so a longer key does not save it. Data recorded today "
        "can be decrypted later ('harvest now, decrypt later')."),
    "already_deprecated": (
        "It is already broken or too weak for ordinary computers (found collisions, tiny "
        "keys, known attacks). Quantum computers are not even needed to defeat it."),
    "weakened_by_grover": (
        "It is not broken, but Grover's algorithm searches a key space in roughly the square "
        "root of the normal time. That halves the effective strength (a 128-bit key behaves "
        "like 64 bits). Doubling the size, or using a modern construction, restores the margin."),
    "needs_review": (
        "It is not clearly unsafe, but its quantum strength depends on how it is used "
        "(parameters, output size). A person should look at it."),
}

# Extra detail for specific old algorithms.
DETAIL = {
    "RSA": "RSA is built on factoring large numbers, which is what Shor's algorithm does well.",
    "DSA": "DSA relies on discrete logarithms, which Shor's algorithm solves.",
    "DH": "Diffie-Hellman relies on discrete logarithms, which Shor's algorithm solves.",
    "ECDH": "Elliptic-curve Diffie-Hellman relies on the elliptic-curve discrete log, which Shor's algorithm solves.",
    "X25519": "X25519 is elliptic-curve Diffie-Hellman; Shor's algorithm breaks the curve's discrete log.",
    "X448": "X448 is elliptic-curve Diffie-Hellman; Shor's algorithm breaks the curve's discrete log.",
    "ECDSA": "ECDSA signatures depend on the elliptic-curve discrete log, which Shor's algorithm solves.",
    "EC": "Elliptic-curve keys depend on the curve's discrete log, which Shor's algorithm solves.",
    "Ed25519": "Ed25519 signatures depend on the curve's discrete log, which Shor's algorithm solves.",
    "Ed448": "Ed448 signatures depend on the curve's discrete log, which Shor's algorithm solves.",
    "MD5": "MD5 collisions can be produced in seconds on a laptop; it must not protect anything.",
    "SHA-1": "Practical SHA-1 collisions have been demonstrated; browsers and CAs rejected it years ago.",
    "DES": "DES has a 56-bit key, which ordinary hardware can brute-force.",
    "3DES": "3DES has a 64-bit block, which allows birthday attacks (Sweet32), and is retired by NIST.",
    "RC4": "RC4 has known biases in its output stream; it is banned in TLS.",
    "Blowfish": "Blowfish has a 64-bit block, which allows birthday attacks on large data.",
    "AES": "AES itself is sound, but AES-128 would drop to about 64 bits against Grover. "
           "AES-256 keeps about 128 bits. ECB mode (if used) also leaks patterns and must go.",
    "AES-GCM": "AES-GCM is fine at 256-bit keys; with a 128-bit key Grover halves it.",
    "SHA-256": "Grover cuts brute-force preimage search on a 256-bit hash to about 128 bits. "
               "That is still strong; the project policy still flags it for review.",
    "HMAC-SHA256": "The MAC is sound; the flag is the same Grover margin as for SHA-256.",
    "Fernet": "Fernet uses AES-128, which Grover reduces to about 64 bits of strength.",
}

# Why THIS replacement.
WHY_TARGET = {
    "ML-DSA-87": (
        "ML-DSA (FIPS 204, from CRYSTALS-Dilithium) is a signature scheme built on lattice "
        "problems (Module-LWE / Module-SIS). No quantum algorithm is known that solves these "
        "quickly. The -87 level is NIST's highest security category."),
    "ML-KEM-1024": (
        "ML-KEM (FIPS 203, from CRYSTALS-Kyber) replaces key exchange with a key-encapsulation "
        "scheme built on lattice problems (Module-LWE). It is NIST's standard for establishing "
        "shared secrets, and -1024 is the highest security level."),
    "AES-256-GCM": (
        "AES with a 256-bit key keeps about 128 bits of strength even against Grover. GCM "
        "mode also authenticates the data, unlike ECB or plain CBC, and needs a fresh nonce "
        "for every message."),
    "ChaCha20-Poly1305": (
        "A 256-bit-key authenticated cipher. It keeps about 128 bits against Grover, is fast "
        "without AES hardware, and is not affected by AES-specific timing problems."),
    "SHA3-256": (
        "SHA3 is the newer NIST hash family (Keccak). Honest note: at the same output size "
        "SHA3-256 is not stronger against quantum attacks than SHA-256; the move is a project "
        "policy choice (different design, no length-extension weakness). MD5 and SHA-1 must "
        "leave regardless."),
    "SHA3-512": (
        "The 512-bit SHA3 variant keeps about 256 bits against Grover. Same note as SHA3-256: "
        "a policy choice for a newer design, not a quantum necessity."),
    "HMAC-SHA3-256": (
        "A message-authentication code built on SHA3-256. Needs no change of structure: the "
        "inner hash is swapped, the key handling stays the same."),
}


def explain(family, algorithms, risk, target):
    """Return {'problem': ..., 'replacement': ...} for one threat."""
    parts = [PROBLEM.get(risk, "")]
    parts += [DETAIL[a] for a in algorithms if a in DETAIL]
    why = WHY_TARGET.get(target, "")
    if not why and target:
        why = f"{target} is the project's recommended replacement for the {family} family."
    return {"problem": " ".join(p for p in parts if p), "replacement": why}