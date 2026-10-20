"""Stage 3 - Fusion, two-stage classification head, and the arbiter.

  fusion      AST feature vector (stage 2a) + neural embedding (stage 2b), joined side by side
  head 1      family classifier       -> symmetric / hash / mac / aead / signature /
                                         key_exchange / combined / none
  head 2      algorithm classifier    -> conditioned on the family from head 1
  arbiter     decides between the rule engine and the model for each code unit and can
              say "I am not sure" instead of guessing
"""
from collections import Counter
from dataclasses import dataclass, field, asdict

import joblib
import numpy as np

from .config import (ABSTAIN_THRESHOLD, FAMILY_LABELS, FAMILY_TARGETS, MIN_ALGO_SUPPORT,
                     MODEL_ONLY_NO_HINT_THRESHOLD, RANDOM_SEED)
from .rules import RISK
from .stage2a_ast_features import extract_matrix
from .stage2b_neural_encoding import build_encoder


# --------------------------------------------------------------------------- #
# Model
# --------------------------------------------------------------------------- #
@dataclass
class ModelPrediction:
    family: str
    family_conf: float
    family_probs: dict
    algorithm: str
    algorithm_conf: float


class FusionClassifier:
    """Fusion + two-stage head. Train with fit(), use with predict()."""

    def __init__(self, encoder_kind="tfidf", **encoder_kwargs):
        # imported here so the rule-only parts of the tool still run if scikit-learn/scipy
        # cannot be loaded on a machine (for example when a Windows policy blocks scipy)
        from sklearn.linear_model import LogisticRegression
        from sklearn.preprocessing import StandardScaler
        self.encoder = build_encoder(encoder_kind, **encoder_kwargs)
        self.scaler = StandardScaler()
        self.family_head = LogisticRegression(C=2.0, max_iter=4000, class_weight="balanced",
                                              random_state=RANDOM_SEED)
        self.algo_head = LogisticRegression(C=2.0, max_iter=4000, class_weight="balanced",
                                            random_state=RANDOM_SEED)
        self.algo_classes_seen = []
    # -- fusion ------------------------------------------------------------- #
    def _fuse(self, texts, fit=False):
        """Concatenate the scaled AST vector with the neural embedding."""
        ast_part = extract_matrix(texts)
        ast_part = self.scaler.fit_transform(ast_part) if fit else self.scaler.transform(ast_part)
        return np.hstack([ast_part, self.encoder.transform(texts)])

    @staticmethod
    def _family_onehot(families):
        out = np.zeros((len(families), len(FAMILY_LABELS)), dtype=np.float32)
        for row, fam in enumerate(families):
            out[row, FAMILY_LABELS.index(fam)] = 1.0
        return out

    # -- training ----------------------------------------------------------- #
    def fit(self, texts, families, algorithms):
        """`algorithms` are labels per snippet; rare ones are merged into 'other'."""
        self.encoder.fit(texts)
        X = self._fuse(texts, fit=True)
        self.family_head.fit(X, families)

        counts = Counter(algorithms)
        merged = [a if counts[a] >= MIN_ALGO_SUPPORT else "other" for a in algorithms]
        self.algo_classes_seen = sorted(set(merged))
        # The algorithm head also sees the (true) family: that is the "conditioned on family" part.
        self.algo_head.fit(np.hstack([X, self._family_onehot(families)]), merged)
        return self

    # -- inference ---------------------------------------------------------- #
    def predict(self, texts):
        X = self._fuse(texts)
        fam_probs = self.family_head.predict_proba(X)
        fam_idx = fam_probs.argmax(axis=1)
        fam_names = [self.family_head.classes_[i] for i in fam_idx]

        algo_probs = self.algo_head.predict_proba(
            np.hstack([X, self._family_onehot(fam_names)]))
        algo_idx = algo_probs.argmax(axis=1)

        results = []
        for row in range(len(texts)):
            results.append(ModelPrediction(
                family=fam_names[row],
                family_conf=float(fam_probs[row, fam_idx[row]]),
                family_probs={c: round(float(p), 4)
                              for c, p in zip(self.family_head.classes_, fam_probs[row])},
                algorithm=str(self.algo_head.classes_[algo_idx[row]]),
                algorithm_conf=float(algo_probs[row, algo_idx[row]])))
        return results

    # -- persistence -------------------------------------------------------- #
    def save(self, path):
        joblib.dump(self, path)

    @staticmethod
    def load(path):
        return joblib.load(path)


# --------------------------------------------------------------------------- #
# Arbiter
# --------------------------------------------------------------------------- #
@dataclass
class Decision:
    families: list
    algorithm: str
    risk: str
    target: str
    status: str        # detected | contested | model_only | ambiguous | abstain | no_crypto
    source: str        # rule | model | rule+model | none
    confidence: float
    note: str = ""
    model: dict = field(default_factory=dict)   # raw model output, kept for the report
    threats: list = field(default_factory=list)  # one entry per weak primitive family

    def to_dict(self):
        return asdict(self)


def threats_for(rule, dec):
    """The threats of one unit: what the rules found, or else what the decision says."""
    if dec.status == "no_crypto":
        return []
    if dec.source in ("rule", "rule+model") and rule.threats and \
            sorted(dec.families) == sorted(t["family"] for t in rule.threats):
        return [dict(t) for t in rule.threats]
    return fallback_threats(dec, rule.start)


def fallback_threats(dec, line):
    """One threat built from the unit-level decision (used when no rule listed threats)."""
    if dec.status == "no_crypto":
        return []
    return [{"family": ",".join(dec.families) or "combined",
             "algorithms": [a for a in dec.algorithm.split(", ") if a],
             "risk": dec.risk, "target": dec.target, "line": line}]


def _risk_for(algorithm, family):
    """Risk class and target for a model-predicted algorithm."""
    if algorithm in RISK:
        risk, target = RISK[algorithm]
        return risk, target or ""
    return "needs_review", FAMILY_TARGETS.get(family, "")


def arbitrate(rule, model_pred):
    """Combine one rule result (UnitResult) with one model prediction (or None).

    Precedence, in plain words:
      1. a clear rule hit wins; the model can only flag a disagreement
      2. an ambiguous rule hit (EC key: sign or exchange?) is settled by the model
      3. if no rule fired, a confident model label is used, marked 'model_only'
      4. if nothing is confident, abstain rather than guess
    """
    tau = ABSTAIN_THRESHOLD
    model_info = asdict(model_pred) if model_pred else {}

    # No trained model available: the rule layer decides alone.
    if model_pred is None:
        status = {"needs_model": "abstain"}.get(rule.status, rule.status)
        return Decision(rule.families, ", ".join(rule.algorithms), rule.risk, rule.target,
                        status, "rule" if rule.status in ("detected", "ambiguous") else "none",
                        rule.confidence, "no trained model loaded; rule layer only")

    fam, conf = model_pred.family, model_pred.family_conf

    # 1. rule hit
    if rule.status == "detected":
        agrees = fam in rule.families or fam == "combined"
        if conf >= tau and not agrees:
            return Decision(rule.families, ", ".join(rule.algorithms), rule.risk, rule.target,
                            "contested", "rule", rule.confidence,
                            f"model predicts '{fam}' ({conf:.0%}); keeping the rule label",
                            model_info)
        return Decision(rule.families, ", ".join(rule.algorithms), rule.risk, rule.target,
                        "detected", "rule+model" if agrees and conf >= tau else "rule",
                        rule.confidence, "", model_info)

    # 2. ambiguous rule hit
    if rule.status == "ambiguous":
        if conf >= tau and fam in ("signature", "key_exchange"):
            algo = "ECDSA" if fam == "signature" else "ECDH"
            target = FAMILY_TARGETS[fam]
            return Decision([fam], algo, rule.risk, target, "detected", "rule+model", conf,
                            "rule could not tell sign from exchange; the model decided", model_info)
        return Decision(rule.families, ", ".join(rule.algorithms), rule.risk, rule.target,
                        "ambiguous", "rule", rule.confidence,
                        "EC key use is unclear and the model is not confident", model_info)

    # 3 + 4. no rule fired
    hinted = rule.status == "needs_model"
    needed = tau if hinted else MODEL_ONLY_NO_HINT_THRESHOLD
    if fam == "none" and conf >= tau:
        return Decision([], "", "not_crypto", "", "no_crypto", "model", conf, "", model_info)
    if fam != "none" and conf >= needed:
        algo = model_pred.algorithm if model_pred.algorithm not in ("other", "unknown") else ""
        risk, target = _risk_for(algo, fam)
        families = [] if fam == "combined" else [fam]
        return Decision(families, algo, risk, target, "model_only", "model", conf,
                        "no rule matched; label comes from the model only", model_info)
    if hinted:
        return Decision([], "", "unknown", "", "abstain", "none", conf,
                        "name looks crypto-related but neither layer is confident", model_info)
    return Decision([], "", "not_crypto", "", "no_crypto", "rule", rule.confidence, "", model_info)