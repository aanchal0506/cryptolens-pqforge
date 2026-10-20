"""Project-wide settings. Everything tunable lives here so stages stay free of magic numbers."""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
MODEL_DIR = ROOT / "models"
REPORT_DIR = ROOT / "reports"

# Primitive families used by the source paper, plus two helper labels:
#   combined - one snippet that uses more than one family
#   none     - code that has no cryptography at all (needed so the model can say "not crypto")
FAMILIES = ["symmetric", "hash", "mac", "aead", "signature", "key_exchange"]
FAMILY_LABELS = FAMILIES + ["combined", "none"]

RANDOM_SEED = 42
TEST_FRACTION = 0.10          # the paper also uses a 720 / 80 split of the 800 entries

# Arbiter: below this model confidence we refuse to guess and mark the unit for review.
ABSTAIN_THRESHOLD = 0.55

# When no rule fired AND the function name gives no hint, a model-only label needs more
# confidence, because the model alone can produce false positives on ordinary code.
MODEL_ONLY_NO_HINT_THRESHOLD = 0.80

# Weak algorithm labels with fewer examples than this are merged into "other".
MIN_ALGO_SUPPORT = 3

# Verification sandbox limits
SANDBOX_TIMEOUT_S = 20
SANDBOX_MEMORY_MB = 1024

# Migration retry loop (diagram: "fail, retry with error context")
MAX_MIGRATION_ATTEMPTS = 2

# Default targets from the project document (FIPS names). Used when no algorithm-specific
# target is known.
FAMILY_TARGETS = {
    "hash": "SHA3-256",
    "mac": "HMAC-SHA3-256",
    "symmetric": "AES-256-GCM",
    "aead": "ChaCha20-Poly1305",
    "signature": "ML-DSA-87",
    "key_exchange": "ML-KEM-1024",
}