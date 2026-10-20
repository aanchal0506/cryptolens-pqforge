"""Quantum demos (Qiskit) that back the project's risk classes.

The classifier labels code as `broken_by_shor` or `weakened_by_grover`. This module runs
small, real quantum circuits that show WHY, on a simulator:

  shor_demo()     factors N = 15 with Shor's algorithm (order finding by phase estimation).
                  Factoring is what breaks RSA; the same idea (discrete logs) breaks ECC/DH.
  grover_demo()   finds a secret n-bit key among 2^n by Grover search. The speed-up is only
                  quadratic, so symmetric keys and hashes are weakened, not broken.

Both run on Qiskit's exact statevector simulator. They use toy sizes: real RSA-2048 needs
millions of physical qubits and is far out of reach of any simulator or current hardware.
"""
import math
import random
from fractions import Fraction

from qiskit import QuantumCircuit
from qiskit.circuit.library import QFTGate
from qiskit.quantum_info import Statevector

N_SHOR = 15
SHOTS = 1024


# --------------------------------------------------------------------------- #
# Shor, N = 15
# --------------------------------------------------------------------------- #
def _controlled_mult_mod15(a, power):
    """Gate that multiplies a 4-qubit register by a^power mod 15 (controlled by one qubit).

    For N = 15 each multiplication is just a fixed shuffle of the 4 bits, which keeps the
    circuit tiny. (General N needs modular-arithmetic circuits, which is the hard part.)
    """
    block = QuantumCircuit(4)
    for _ in range(power):
        if a in (2, 13):
            block.swap(2, 3); block.swap(1, 2); block.swap(0, 1)
        if a in (7, 8):
            block.swap(0, 1); block.swap(1, 2); block.swap(2, 3)
        if a in (4, 11):
            block.swap(1, 3); block.swap(0, 2)
        if a in (7, 11, 13):
            for q in range(4):
                block.x(q)
    gate = block.to_gate(label=f"{a}^{power} mod 15")
    return gate.control()


def shor_circuit(a, counting=3):
    """Phase-estimation circuit for the map x -> a*x mod 15."""
    qc = QuantumCircuit(counting + 4)
    qc.h(range(counting))
    qc.x(counting)                      # work register starts at |1>
    for k in range(counting):
        qc.append(_controlled_mult_mod15(a, 2 ** k), [k] + list(range(counting, counting + 4)))
    qc.append(QFTGate(counting).inverse(), range(counting))
    return qc


def shor_demo(a=7, counting=3):
    """Run order finding for `a` mod 15 and derive the factors. Returns a plain dict."""
    if math.gcd(a, N_SHOR) != 1:
        raise ValueError("a must be coprime to 15 (try 2, 4, 7, 8, 11, 13)")
    qc = shor_circuit(a, counting)
    probs = Statevector(qc).probabilities_dict(qargs=list(range(counting)))
    outcomes = []
    for bits, p in sorted(probs.items(), key=lambda kv: -kv[1]):
        if p < 1e-6:
            continue
        phase = int(bits, 2) / 2 ** counting
        # the phase is s/r; the continued-fraction step recovers r
        r = Fraction(phase).limit_denominator(N_SHOR).denominator if phase else 1
        outcomes.append({"measured": str(bits), "probability": round(float(p), 4),
                         "phase": phase, "candidate_order": r})
    # pick the order from the most likely informative outcome
    order = next((o["candidate_order"] for o in outcomes
                  if o["candidate_order"] > 1 and pow(a, o["candidate_order"], N_SHOR) == 1), None)
    factors = None
    if order and order % 2 == 0:
        half = pow(a, order // 2, N_SHOR)
        found = sorted({math.gcd(half - 1, N_SHOR), math.gcd(half + 1, N_SHOR)} - {1, N_SHOR})
        factors = found or None
    # What a classical computer would have to walk through: a^x mod 15 for x = 0, 1, 2, ...
    powers = [pow(a, x, N_SHOR) for x in range(13)]
    # Simulated measurements: 1024 shots drawn from the exact circuit probabilities.
    rng = random.Random(15)
    shots = {}
    keys, weights = zip(*[(o["measured"], o["probability"]) for o in outcomes])
    for bits in rng.choices(keys, weights=weights, k=SHOTS):
        shots[bits] = shots.get(bits, 0) + 1
    half = pow(a, order // 2, N_SHOR) if order and order % 2 == 0 else None
    return {"N": N_SHOR, "a": a, "qubits": qc.num_qubits, "gates": sum(qc.count_ops().values()),
            "outcomes": outcomes, "order": order, "factors": factors,
            "check": f"{a}^{order} mod 15 = {pow(a, order, N_SHOR)}" if order else None,
            "powers": powers, "shots": SHOTS,
            "histogram": [{"measured": k, "count": shots.get(k, 0),
                           "phase": int(k, 2) / 2 ** counting}
                          for k in (format(i, f"0{counting}b") for i in range(2 ** counting))],
            "half_power": half,
            "gcds": [math.gcd(half - 1, N_SHOR), math.gcd(half + 1, N_SHOR)] if half else None,
            "circuit_text": str(qc.draw("text", fold=110))}


# --------------------------------------------------------------------------- #
# Grover
# --------------------------------------------------------------------------- #
def _phase_flip(qc, bits):
    """Flip the sign of the basis state `bits` (a string like '1011')."""
    n = len(bits)
    for i, b in enumerate(reversed(bits)):      # qiskit qubit 0 = rightmost bit
        if b == "0":
            qc.x(i)
    qc.h(n - 1)
    qc.mcx(list(range(n - 1)), n - 1)
    qc.h(n - 1)
    for i, b in enumerate(reversed(bits)):
        if b == "0":
            qc.x(i)


def grover_circuit(secret, iterations=None):
    n = len(secret)
    iterations = iterations if iterations is not None else max(1, int(math.pi / 4 * math.sqrt(2 ** n)))
    qc = QuantumCircuit(n)
    qc.h(range(n))
    for _ in range(iterations):
        _phase_flip(qc, secret)                 # oracle: marks the secret key
        qc.h(range(n))                          # diffuser: reflect about the mean
        _phase_flip(qc, "0" * n)
        qc.h(range(n))
    return qc, iterations


def grover_demo(secret="1011"):
    """Search all 2^n keys for `secret` and report the success probability."""
    qc, iterations = grover_circuit(secret)
    probs = Statevector(qc).probabilities_dict()
    top = sorted(probs.items(), key=lambda kv: -kv[1])[:4]
    n = len(secret)
    # Probability of every key after 0, 1, 2 ... iterations, so the UI can show the secret
    # growing while the other keys shrink.
    history = []
    for k in range(iterations + 1):
        qk, _ = grover_circuit(secret, k)
        history.append([round(float(p), 4) for p in Statevector(qk).probabilities()])
    one, _ = grover_circuit(secret, 1)
    return {"key_bits": n, "search_space": 2 ** n, "secret": secret, "iterations": iterations,
            "history": history, "secret_index": int(secret, 2),
            "qubits": n, "gates_per_iteration": sum(one.count_ops().values()) - n,
            "circuit_text": str(one.draw("text", fold=110)),
            "classical_expected_guesses": 2 ** n // 2, "top_outcomes":
            [{"key": str(k), "probability": round(float(p), 4)} for k, p in top],
            "success_probability": round(float(probs.get(secret, 0.0)), 4),
            "found": str(top[0][0]) == secret}


def key_strength_table():
    """Effective security after Grover for common key sizes (halved exponent)."""
    rows = []
    for name, bits in [("AES-128", 128), ("AES-192", 192), ("AES-256", 256),
                       ("SHA-256 preimage", 256), ("SHA3-256 preimage", 256)]:
        rows.append({"primitive": name, "classical_bits": bits, "vs_grover_bits": bits // 2,
                     "verdict": "weakened" if bits // 2 < 128 else "still strong"})
    return rows


def scale_note(bits=2048):
    """Qubits an RSA key of `bits` needs, against what these toy circuits use."""
    return {"rsa_bits": bits, "logical_qubits": 2 * bits + 3, "toy_qubits": 7}


def run_all(a=7, secret="1011"):
    return {"shor": shor_demo(a), "grover": grover_demo(secret),
            "grover_table": key_strength_table(), "scale": scale_note()}