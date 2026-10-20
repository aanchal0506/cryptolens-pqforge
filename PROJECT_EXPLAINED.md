# CryptoLens / PQ-Forge — Project Explanation Guide

A reference to explain the project to your teacher. Read sections 1 to 3 first for the story, use section 5 as a stage-by-stage walkthrough, section 12 for likely questions, and section 14 for the sample code to run in front of your teacher.

---

## 1. The project in one minute

**Problem.** Almost all software today protects data with RSA, elliptic curves, Diffie-Hellman, AES and SHA hashes. A large quantum computer will break some of these completely and weaken others. Companies have thousands of source files that use these algorithms and no list of where.

**What the tool does.** CryptoLens takes Python code and automatically:

1. **Finds** every cryptographic primitive (which algorithm, in which function, on which line).
2. **Classifies the quantum risk** of each one (broken, weakened, already weak, or safe).
3. **Rewrites** it using a post-quantum or stronger alternative, using a prompt that already contains the classifier's label.
4. **Verifies** the rewrite automatically (syntax, re-scan, rules, sandbox run) and retries once if it fails.
5. **Reports**: a CBOM (cryptographic bill of materials) and a CI pass/fail gate.

**Core idea.** An LLM that rewrites crypto code usually has to *guess* what the old code uses. Here the classifier tells it exactly: "this is RSA signing, replace with ML-DSA-87". The result is then checked by running the same classifier on the new code. So the pipeline is **classify, then migrate, then verify**.

**Basis.** A 2026 paper (arXiv:2606.07341) and its dataset (reported DOI 10.21950/7GK4MJ). The paper's real dataset is **not** used here. I built a synthetic stand-in dataset to test the pipeline (see section 9).

**Course link.** Quantum computing: the project is built around *why* Shor's and Grover's algorithms force this migration, and a Qiskit demo shows both.

---

## 2. Background: why classical crypto is in danger

Two quantum algorithms matter.

### Shor's algorithm (breaks public-key crypto)
- Finds the **period** of a function quickly. That solves **factoring** and **discrete logarithms** in polynomial time.
- RSA depends on factoring. Diffie-Hellman, DSA, ECDSA, ECDH, X25519 and Ed25519 depend on discrete logs (on numbers or on elliptic curves).
- A longer key does **not** save these. The attack is fast at any realistic size.
- Everything affected is labelled **`broken_by_shor`**.

### Grover's algorithm (weakens symmetric crypto and hashes)
- Searches N possibilities in about the square root of N steps.
- A 128-bit key behaves like a 64-bit key. A 256-bit key still behaves like 128 bits, which is fine.
- Affected: AES-128, SHA-256 and friends, HMAC-SHA256. They are labelled **`weakened_by_grover`**. The fix is larger sizes, not new maths.

### Already deprecated (no quantum needed)
MD5, SHA-1, DES, 3DES, RC4, Blowfish are weak today. Labelled **`already_deprecated`**.

### Harvest now, decrypt later
An attacker can record encrypted traffic today and decrypt it when quantum computers exist. So data that must stay secret for many years needs migration **before** the break.

### Scale (be honest about this)
Breaking RSA-2048 with Shor needs about 4,099 *logical* qubits (2n + 3 for an n-bit modulus). Published estimates of the physical qubits needed range from about 20 million (2019) down to under one million (Gidney, arXiv:2505.15917, 2025). Nobody can do this today. The demos in my project use 7 qubits on a simulator.

---

## 3. The replacement algorithms

### Public-key side: lattice-based standards (NIST FIPS, August 2024)

| New standard | Replaces | Job | Based on |
|---|---|---|---|
| **ML-KEM** (FIPS 203, from Kyber) | RSA key transport, DH, ECDH, X25519 | Agree on a shared secret | Module-LWE (lattices) |
| **ML-DSA** (FIPS 204, from Dilithium) | RSA, DSA, ECDSA, Ed25519 signatures | Sign and verify | Module-LWE / SIS (lattices) |
| **SLH-DSA** (FIPS 205, from SPHINCS+) | Same as ML-DSA, conservative backup | Signatures | Only hash functions |

My project's targets: **ML-KEM-1024** and **ML-DSA-87** (the highest security level of each).

**Lattice idea in easy words.** Take a huge grid of points in hundreds of dimensions. Give someone a point that is *almost* on the grid. Finding the nearest grid point is easy in 2 dimensions and very hard in 500. No quantum algorithm is known that solves this efficiently.

**How ML-KEM differs from Diffie-Hellman.**
1. The receiver publishes a public key.
2. The sender calls `encapsulate(public_key)` and gets a random shared secret plus a ciphertext, and sends the ciphertext.
3. The receiver calls `decapsulate(private_key, ciphertext)` and gets the same secret.
4. That secret becomes an AES key.

So the old `exchange()` call becomes `encapsulate` / `decapsulate`.

**Other standards to mention:** FN-DSA (Falcon) is a smaller-signature lattice scheme (draft FIPS 206 at my last knowledge, so check its status). HQC was selected by NIST in 2025 as a backup key-exchange method, based on error-correcting codes.

**Trade-off: sizes.** RSA-2048 public key and signature are about 256 bytes. ML-KEM-1024 public key is 1,568 bytes. ML-DSA-87 signature is about 4,627 bytes. The new algorithms are fast but much bigger, so migration needs testing.

**Hybrid mode in real life.** Production systems often combine classic and post-quantum (for example X25519 together with ML-KEM) so that if either is broken the connection stays safe. My templates use pure post-quantum for simplicity.

### Symmetric and hash side

| Old | New | Why |
|---|---|---|
| AES-128, AES-ECB, Fernet, DES, 3DES, RC4, Blowfish | **AES-256-GCM** | 256-bit key keeps about 128 bits against Grover. GCM also authenticates data. ECB mode leaks patterns. |
| MD5, SHA-1, SHA-256, SHA-512 | **SHA3-256 / SHA3-512** | Newer NIST hash family |
| HMAC-SHA1 / HMAC-SHA256 | **HMAC-SHA3-256** | Same structure, safer inner hash |

**Honest note:** SHA3-256 is *not* stronger than SHA-256 against quantum attacks at the same output size. In this project the move is a **policy choice** (newer design, no length-extension weakness). MD5 and SHA-1 must go regardless. The UI states this.

---

## 4. Architecture

```
                 Python source file(s)
                          |
        [1] Ingestion  ->  units (function / method / module code),
                           each with the imports it needs
                          |
          +---------------+----------------+
          |                                |
 [2a] AST features (136 numbers)   [2b] Neural encoding (96 numbers)
          |                                |
          +---------------+----------------+
                          |
        [3] Fusion (232 numbers) -> family head -> algorithm head
                          |
        [3b] Arbiter:  rules (73) + model -> final decision
                          |
        one unit -> one or more THREATS (one per weak primitive family)
                          |
        [4] Migration prompt (one per threat) -> migrator -> new code
                          |
        [5] Verification: syntax -> re-scan -> category rules -> sandbox
              | fail: retry once with the error message in the prompt
                          |
        [6] Report: CBOM (JSON) + Markdown + CI gate (PASS / FAIL)
```

Project layout:

```
cryptolens/
  extractor.py, stage1_ingestion.py     parsing into units
  rules.py, detector.py                 73 rules, rule-based detection, threats
  stage2a_ast_features.py               136-number AST vector
  stage2b_neural_encoding.py            TF-IDF + SVD (96 numbers); CodeBERT optional
  stage3_classifier.py                  fusion, two-stage head, arbiter, Decision
  stage4_migration.py                   prompt builder + template / LLM migrators
  stage5_verification.py                the four checks, sandbox
  stage6_report.py                      CBOM, CI gate, Markdown
  explain.py                            "why it must change" texts
  quantum_demo.py                       Qiskit Shor + Grover
  pipeline.py                           wires all stages together
  ci.py, cli.py, train.py               command-line entry points
webapp/                                 Flask UI (Analyze, Evaluation, Quantum demo)
scripts/                                synthetic dataset generators
tests/                                  56 automated tests
```

---

## 5. Stage by stage

### Stage 1 — Ingestion
- Parses the file with Python's `ast` module.
- Splits it into **units**: each function, each method, class-body code, module-level code.
- Each unit gets only the import lines it actually uses, so it can be re-scanned and executed on its own.
- Methods are de-indented so they are valid code on their own.

### Stage 2a — AST features (136 numbers)
Counts of which crypto-related calls, modes, keywords and structures appear in the unit. Gives the model structure that plain text misses.

### Stage 2b — Neural encoding (96 numbers)
TF-IDF followed by SVD turns the code text into a dense vector. This is a **stand-in for CodeBERT**. A CodeBERT trainer exists (`train_codebert.py`) but I have **not tested it**.

### Stage 3 — Fusion and classification
- The two vectors are joined (232 numbers).
- **Family head** (logistic regression): hash, mac, symmetric, aead, signature, key_exchange, combined, none.
- **Algorithm head** (logistic regression): which algorithm inside that family.

### Stage 3b — The arbiter
Combines the rules and the model with fixed precedence:
1. A clear rule hit wins.
2. If the model disagrees (confidence at least 0.55), the unit is marked **contested**, but the rule label is kept.
3. An ambiguous rule hit (EC key: sign or exchange?) is settled by the model.
4. If no rule fired, the model decides only if the function name looks crypto-related (threshold 0.55), or with very high confidence otherwise (0.80). That is labelled `model_only`.
5. If nothing is confident, it **abstains** instead of guessing.

Output per unit: families, algorithm, risk class, target, status, source, confidence.

### Threats (new: one prompt per weak primitive)
A single function can use several weak primitives. The detector groups its detections by family. Each group is one **threat** with its own risk, target and line.

Example: `secure_upload` uses MD5, AES-ECB and RSA, so it has three threats:

| Threat | Risk | Target |
|---|---|---|
| hash: MD5 | already_deprecated | SHA3-256 |
| symmetric: AES (ECB) | weakened_by_grover | AES-256-GCM |
| signature: RSA | broken_by_shor | ML-DSA-87 |

Before this change a mixed function ended as "migration failed". Now each threat is handled on its own.

### Stage 4 — Migration prompt and migrator
For **each threat** a ChatML prompt is built:

```
system:  You are a cryptography migration engineer ... (rules)
user:    MIGRATION CATEGORY: hash
         DETECTED ALGORITHM: MD5
         TARGET: SHA3-256
         FOCUS: fix only the hash primitive (MD5) near line 7;
                other threats are handled separately
         PRE-QUANTUM CODE:
         ...
```

The `FOCUS` line appears only when the unit has more than one threat.

Two interchangeable backends:
- **TemplateMigrator** (default, offline, deterministic)
  - Hash/MAC: renames the hash in place (for example `hashlib.md5` becomes `hashlib.sha3_256`).
  - Symmetric/AEAD: replaces the code with an AES-256-GCM (or ChaCha20-Poly1305) module that has a fresh random nonce and a self-test.
  - Signature: ML-DSA-87 module.
  - Key exchange: ML-KEM-1024 module (`encapsulate` / `decapsulate`).
- **AnthropicMigrator** calls a Claude model through the API. It exists in code but is **untested** here and has been removed from the UI.

### Stage 5 — Verification (category-specific)
A fix is accepted only if all four checks pass:

1. **Syntax:** the new code parses.
2. **Re-scan:** the same classifier scans the new code. For that threat's family, every primitive found must be `quantum_safe` (at least one must be present). Symmetric and AEAD count as interchangeable.
3. **Category rules** (examples): no MD5/SHA-1 left; no ECB mode; no fixed nonce or IV literal; no hard-coded key; no classical key generation or `.exchange(` left; digests are not compared with `==`.
4. **Sandbox run:** the code runs in a separate process with limited resources and a clean environment, and its `_selftest()` (or the dataset's test) must pass.

If a check fails, the failure text is added to the prompt and the migrator tries once more. Maximum attempts: **2**. After that: *migration failed*, reported honestly.

A unit is **verified** only when **all** its actionable threats are verified.

### Stage 6 — Report and CI gate
- **CBOM** (CycloneDX-style JSON): one component per **threat** with algorithm, primitive family, risk, target, file, lines, classification source and confidence, migration state and attempts.
- **Markdown** summary table.
- **CI gate** (exit code 0 or 1):
  - FAIL while any `broken_by_shor` or `already_deprecated` finding is not `migrated_verified`.
  - `weakened_by_grover` findings never block (warnings only).

Migration states: `safe`, `migrated_verified`, `migration_failed`, `needs_human_review`, `pending`.

### Final code
For each unit the pipeline assembles all verified fixes into one block: hash and MAC fixes are applied inside the original code, and cipher, signature and key-exchange fixes appear as labelled helper sections. A threat that could not be verified is listed as a `# NOT FIXED` comment, not hidden. This combined block is a convenience view and was not run as one program. Each fix was verified separately.

---

## 6. Worked example

Input:

```python
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def secure_upload(data, key):
    digest = hashlib.md5(data).hexdigest()
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return digest, enc, priv
```

What happens:
1. Stage 1 makes one unit, `secure_upload`, with the three imports it uses.
2. The rule layer finds 3 detections (MD5, AES, RSA), so 3 threats in 3 families.
3. Three prompts are built, each with a different category and a `FOCUS` line.
4. Hash: `hashlib.md5` becomes `hashlib.sha3_256` in place. Verified.
5. Symmetric: replaced by the AES-256-GCM module. Verified (self-test encrypts, decrypts and rejects a tampered message).
6. Signature: replaced by the ML-DSA-87 module. Verified (signs and verifies).
7. The CBOM gets 3 rows, the gate passes, and the Final code tab shows everything together.

---

## 7. The web interface (Flask)

- **Analyze tab:** paste or upload code, click Analyze. The pipeline stepper animates. The result shows a gate verdict, a risk bar with filters, and a findings list. The detail panel has these tabs:
  - **Classification:** the threats, "why it must change", model confidence by family, the code analysed.
  - **Prompt:** the exact prompt for each threat.
  - **Migration:** before and after code, with a Copy button.
  - **Verification:** each check, pass or fail, for each attempt.
  - **Final code:** all verified fixes in one block.
- **Evaluation tab:** metrics for rules only, model only and hybrid, a per-family table and a confusion matrix.
- **Quantum demo tab:** animated Shor and Grover demos (section 8).
- **Download CBOM** button.

---

## 8. The Qiskit quantum demo

Runs on Qiskit's exact statevector simulator.

**Shor (N = 15, base a = 7)**
1. The sequence 7^x mod 15 is 1, 7, 4, 13, 1, 7, 4, 13, ... and the period is **r = 4**.
2. A 7-qubit phase-estimation circuit (3 counting qubits, 4 working qubits) finds the period using superposition and an inverse QFT.
3. 1,024 simulated measurements land on 0, 1/4, 1/2 and 3/4, which are multiples of 1/r.
4. From r = 4: 7^(4/2) mod 15 = 4, gcd(3, 15) = 3 and gcd(5, 15) = 5, so **15 = 3 x 5**.
5. Meaning: the same idea at large scale factors RSA moduli. Discrete logs on curves fall to the same family of methods.

**Grover (4-bit key, secret 1011)**
1. All 16 keys start equally likely (6.3% each).
2. The oracle flips the sign of the secret. The diffuser boosts it.
3. After 3 iterations the secret has about a 96% chance (6%, 47%, 91%, 96%).
4. Classical search needs about 8 guesses on average. This is a square-root speed-up, not a break, which is why AES-128 is weakened and AES-256 is fine.

The tab also shows a key-strength table after Grover and the scale note from section 2.

---

## 9. Dataset and evaluation (be careful here)

- The real paper dataset is **not** used. `scripts/make_standin_dataset.py` builds a **synthetic** dataset of template-generated code (800 entries across the six families). `scripts/add_reference_solutions.py` adds a post-quantum reference solution and a functional test to each entry and **runs every solution against its test**. All 800 pass.
- Training: 839 training items, 94 test items, plus 133 non-crypto functions as negatives. Encoder: TF-IDF + SVD.

Current stand-in results on the held-out split:

| Method | Accuracy | Macro F1 |
|---|---|---|
| Rules only | 0.904 | 0.902 |
| Model only | 1.000 | 1.000 |
| Hybrid (rules + model arbiter) | 0.936 | 0.930 |

**How to present this honestly:**
- The code is generated from templates, so the model can memorise the templates. Perfect model-only accuracy shows **the pipeline works**, not that it would do 100% on real-world code.
- "Algorithm accuracy" is measured against labels that came from the rule layer (weak labels), not human labels.
- Real claims need the paper's dataset. Put it in `data/` and run `python -m cryptolens.train`.

---

## 10. What is new or interesting

1. **Label-conditioned prompts.** The classifier's result (family, algorithm, target) is injected into the migration prompt, so the model does not have to guess.
2. **Verification by re-classification.** The migrated code is scanned by the *same* classifier and must come out `quantum_safe` in the right family. That closes the loop.
3. **Hybrid arbiter.** Rules are precise, the model generalises, and the arbiter keeps the rule label, flags disagreements, and abstains when unsure.
4. **Per-threat handling.** Each weak primitive in a function gets its own prompt, retries and verification.
5. **Actionable output.** A CBOM and a CI gate, so it plugs into a pull-request workflow.
6. **Quantum grounding.** The risk classes are tied to Shor and Grover with real circuits.

---

## 11. Limitations (say these before they are asked)

1. **Synthetic data.** Metrics are for pipeline testing only, not research claims.
2. **Verification proves self-consistency, not behavioural equivalence.** The new code runs and uses a safe primitive. It does not prove your old function's inputs, outputs and data formats are preserved.
3. **Template fixes replace functions.** Cipher, signature and key-exchange fixes are reference modules with standard names, not surgical edits of the original function. In a mixed function, you apply each fix yourself. The Final code view is not a runnable merge.
4. **Wrapper functions are invisible.** If crypto is hidden inside a helper, the calling unit looks clean.
5. **SHA-256 to SHA3-256** is a policy choice, not extra quantum strength.
6. **JWT HS256** cannot be fully migrated by the template, so it ends as an honest failure.
7. **Not tested:** CodeBERT training and the real LLM backend.
8. **Pure post-quantum templates.** Real deployments often use hybrid mode.
9. **Quantum demo is toy scale.**
10. Python only; static analysis only (no runtime tracing).

---

## 12. Likely questions from the teacher, with answers

**Q. Why not just use an LLM directly?**
A. Without a label, the LLM must guess which algorithm is used and may rewrite the wrong thing or use an unsafe mode. Giving it the classifier's label makes the task specific, and the verifier checks the result instead of trusting it.

**Q. Why both rules and a model?**
A. Rules are exact on known API calls but cannot see unknown or renamed patterns. The model generalises but can be wrong. The arbiter takes the rule result when there is one, flags disagreement, and abstains when neither is sure.

**Q. Why are RSA and ECC broken but AES only weakened?**
A. RSA and ECC rest on factoring and discrete logs, which Shor's algorithm solves in polynomial time. AES has no such structure, and Grover only gives a square-root speed-up, so doubling the key size restores the margin.

**Q. Why ML-KEM and ML-DSA?**
A. They are the NIST standards (FIPS 203 and 204, 2024), based on lattice problems with no known efficient quantum attack. I used the highest levels (1024 and 87).

**Q. Your accuracy is almost 100%. Is that real?**
A. It is on synthetic template data, where the model can memorise templates. It shows the pipeline works. I do not claim it as real-world accuracy.

**Q. How do you know the fix is correct?**
A. Four checks: it parses, the classifier re-scan sees only quantum-safe primitives of that family, category rules pass, and it runs in a sandbox and passes a self-test. This proves it is safe and working, but not that it behaves exactly like the old code.

**Q. Why does the gate not fail on AES-128?**
A. It is weakened but not broken. It is reported as a warning. Only Shor-broken and already-deprecated findings block the build.

**Q. Why SHA3 instead of SHA-256?**
A. Honestly, no extra quantum strength at the same size. It is a policy choice for a newer design. MD5 and SHA-1 must be replaced anyway.

**Q. What happens if the migration fails?**
A. After 2 attempts (the second with the error message added to the prompt) it is reported as `migration_failed` and the CI gate stays failed for blocking risks.

**Q. Can it run on a whole repository?**
A. Yes: `python -m cryptolens.ci path/to/repo`. It scans every `.py` file, writes `cbom.json` and `report.md`, and exits 1 if risky crypto remains.

**Q. What is a CBOM?**
A. A cryptographic bill of materials: an inventory of every cryptographic asset in the code, in a CycloneDX-style JSON format.

**Q. What would you do next?**
A. Use the real dataset, test CodeBERT, test the real LLM backend, handle wrapper functions with call-graph analysis, produce surgical edits instead of replacement modules, and add hybrid-mode output.

---

## 13. Demo script (3 to 5 minutes)

1. **Quantum demo tab.** Open it and let it animate. Say: "Shor finds the period and factors 15. Grover finds a key in about the square root of the tries. That is why I have the risk classes."
2. **Analyze tab, Load sample.** Click Analyze. Show the stepper, the gate verdict and the risk bar.
3. Click a **Broken by Shor** finding. Show Classification, then "Why it must change".
4. Open **Prompt**: "This is what the LLM receives, including the label."
5. Open **Migration**: before and after. Then **Verification**: the four checks.
6. Paste the `secure_upload` example from section 6. Show three threats, three prompts, and the **Final code** tab.
7. **Download CBOM** and mention the CI gate.
8. Open the **Evaluation** tab. Say upfront it uses synthetic data.

---

## 14. Sample code for the live demo

Save this as `demo\teacher_demo.py` (it is already in the project folder), or paste it straight into the Analyze tab. It has **10 functions**: 7 with problems, 2 already safe and 1 with no cryptography. Function 7 has three problems at once, which shows the per-threat feature.

```python
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
```

### 14.1 Expected result in the web UI (Analyze tab)

Click **Analyze** with "Migrate and verify" ticked. Expected numbers:

- Pipeline stepper: `70 lines parsed into 11 code units`, `9 crypto units; 9 detected`, `9 threats in 7 units, one prompt each`, `9 of 9 threat migrations verified`, `gate PASS, 11 components in the CBOM`.
- Gate banner: **Gate passed**, "9 crypto units found, 7 of 7 migrations verified, 2 already quantum safe".
- Risk bar and filters (one count per function, using its worst threat): Broken by Shor 3, Already deprecated 1, Weakened by Grover 3, Quantum safe 2. The CBOM download counts per threat instead, so it has 11 components: 3 Shor, 2 deprecated, 4 Grover, 2 safe.

What each function should show:

| # | Function | What it does | Detected as | Risk | Replaced by |
|---|---|---|---|---|---|
| 1 | `file_checksum` | MD5 hash | hash: MD5 | already deprecated | SHA3-256 |
| 2 | `content_fingerprint` | SHA-256 hash | hash: SHA-256 | weakened by Grover | SHA3-256 |
| 3 | `sign_message` | RSA-PSS signature | signature: RSA | broken by Shor | ML-DSA-87 |
| 4 | `make_session_key` | X25519 key exchange | key_exchange: X25519 | broken by Shor | ML-KEM-1024 |
| 5 | `encrypt_record` | AES in ECB mode | symmetric: AES | weakened by Grover | AES-256-GCM |
| 6 | `api_tag` | HMAC-SHA256 | mac: HMAC-SHA256 | weakened by Grover | HMAC-SHA3-256 |
| 7 | `secure_upload` | MD5 + AES-ECB + RSA | **3 threats**: hash, symmetric, signature | broken by Shor (worst) | SHA3-256 + AES-256-GCM + ML-DSA-87 |
| 8 | `seal_modern` | AES-256-GCM | aead: AES-256-GCM | quantum safe | nothing to do |
| 9 | `modern_hash` | SHA3-256 | hash: SHA3-256 | quantum safe | nothing to do |
| 10 | `add_numbers` | a + b | not cryptography | (not listed) | (not listed) |

Functions 1 to 7 should say **Migrated and verified**. Functions 8 and 9 say **Already safe**. Function 10 does not appear in the findings, which proves it does not flag everything.

### 14.2 Suggested live demo steps (about 5 minutes)

1. **Analyze** the file. Point at the stepper, then the gate banner.
2. Click **`secure_upload`**.
   - *Classification:* "3 separate threats", each with a "Why it must change" box.
   - *Prompt:* three different prompts, each with its own `FOCUS:` line.
   - *Migration:* before and after code for each threat.
   - *Verification:* the four checks (syntax, re-scan, rules, sandbox).
   - *Final code:* everything together.
3. Click **`make_session_key`**, then **Migration**. Show that `X25519 .exchange()` became ML-KEM `encapsulate` and `decapsulate`.
4. Click **`encrypt_record`**. Explain why ECB mode is rejected and AES-GCM with a fresh nonce is used.
5. **Show the gate failing.** Untick "Migrate and verify" and click Analyze again. The banner turns to **Gate failed** with 5 blocking findings:
   - `file_checksum` (MD5)
   - `sign_message` (RSA)
   - `make_session_key` (X25519)
   - `secure_upload` (MD5 and RSA)

   Say: "This is what CI would do to a pull request." Then tick the box again and re-run.
6. **Edit live.** In the text box change `hashlib.md5` to `hashlib.sha3_256` in `file_checksum` and Analyze again. That function becomes **Already safe**. Expected: 3 safe findings, 8 migrated, gate passed.
7. Click **Download CBOM (JSON)** and open it. Show one component per threat.

### 14.3 The same demo from the command line

```powershell
# with migration: exit code 0 (gate passed)
python -m cryptolens.ci demo\teacher_demo.py
echo $LASTEXITCODE

# scan only, no migration: exit code 1 (gate failed)
python -m cryptolens.ci demo\teacher_demo.py --no-migrate
echo $LASTEXITCODE
```

Both write `reports\cbom.json` and `reports\report.md`.

### 14.4 Honest points to mention during the demo

- "Verified" means the new code parses, the classifier re-scan sees only quantum-safe primitives of that family, the category rules pass and its self-test runs in a sandbox. It does **not** mean the new function behaves exactly like the old one.
- Function 7's three fixes are three separate pieces of code. The Final code tab puts them in one block, but that block was not run as one program.
- Function 8 uses a 256-bit key made inside the function, so the tool can see it is AES-256. If the key came in as a parameter, the tool cannot know its size and would flag plain AES-GCM as weakened. That is deliberate caution.
- Function 4 creates its key inside the function. If a key is passed in as an argument and the code only calls `.exchange(...)`, the tool may not recognise it. That is a known gap with wrapper and helper functions.
- Results are the same with or without the trained model on this file, because the rules decide. The model matters for code the rules do not recognise.

### 14.5 If something goes wrong during the demo

| Problem | Fix |
|---|---|
| Page looks old or a tab is missing | Press Ctrl+F5 (CSS and JS are cached) |
| Python changes do not show | Stop the server with Ctrl+C and run `python webapp\app.py` again |
| "Could not reach the server" | The server is not running. Start it again |
| Banner says "rule layer only" | The trained model did not load (often Windows Smart App Control blocking scipy). The demo still works and gives the same results on this file |
| Quantum tab does nothing | Wait a second, then click **Run again** |

---

## 15. How to run

```powershell
# one-time setup (Windows PowerShell, Python 3.13)
py -3.13 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

python scripts\make_standin_dataset.py
python scripts\add_reference_solutions.py
python -m cryptolens.train          # trains the classifier, writes reports\metrics.json

python -m pytest tests -q           # 56 tests
python webapp\app.py                # UI at http://127.0.0.1:5000  (Ctrl+F5 after changes)
python -m cryptolens.ci path\to\repo   # CI mode: exit 0 = pass, 1 = fail
```

Notes:
- Flask runs with `debug=False`, so restart the server after changing Python or template files. Use Ctrl+F5 for CSS and JS.
- If scipy is blocked by Windows Smart App Control, the app falls back to rules-only.

---

## 16. Glossary

- **PQC:** post-quantum cryptography, algorithms believed safe against quantum computers.
- **Shor's algorithm:** quantum algorithm for factoring and discrete logs.
- **Grover's algorithm:** quantum search with a square-root speed-up.
- **Lattice / LWE:** the maths problem behind ML-KEM and ML-DSA.
- **KEM:** key encapsulation mechanism, a way to agree on a shared secret.
- **AEAD:** authenticated encryption with associated data (AES-GCM, ChaCha20-Poly1305).
- **CBOM:** cryptographic bill of materials.
- **AST:** abstract syntax tree, the parsed structure of code.
- **Arbiter:** the component that combines rule and model results.
- **Threat (in this project):** one weak primitive family inside a code unit.
- **Harvest now, decrypt later:** recording encrypted data today to break it later.
- **Statevector simulator:** Qiskit's exact classical simulation of a small quantum circuit.
