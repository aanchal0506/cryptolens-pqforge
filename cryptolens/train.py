"""Train and evaluate the classifier.

    python -m cryptolens.train                       # uses the real dataset if present
    python -m cryptolens.train --dataset data/x.jsonl --encoder codebert

What it does
  1. load the dataset (real one from data/ if present, otherwise the synthetic stand-in)
  2. add "none" examples: real standard-library functions with no cryptography
  3. build algorithm labels (see weak_algorithm_label)
  4. stratified 90 / 10 split, fixed seed
  5. fit the fusion classifier on the training part
  6. evaluate three ways on the held-out part: rules only, model only, hybrid (arbiter)
  7. save models/classifier.joblib and reports/metrics.json
"""
import argparse
import json
from collections import Counter
from pathlib import Path

import numpy as np
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score
from sklearn.model_selection import train_test_split

from .config import DATA_DIR, FAMILY_LABELS, MODEL_DIR, RANDOM_SEED, REPORT_DIR, TEST_FRACTION
from .detector import scan_snippet
from .stage1_ingestion import load_dataset, sample_negative_snippets
from .stage3_classifier import FusionClassifier, arbitrate

STANDIN_NAME = "standin_dataset.jsonl"


def find_dataset(explicit=None):
    """Return (path, is_standin). Real data wins over the stand-in when both exist."""
    if explicit:
        path = Path(explicit)
        return path, path.name == STANDIN_NAME
    real = [p for p in sorted(DATA_DIR.rglob("*"))
            if p.suffix.lower() in {".jsonl", ".json", ".csv"} and p.name != STANDIN_NAME]
    if real:
        return (real[0] if len(real) == 1 else DATA_DIR), False
    return DATA_DIR / STANDIN_NAME, True


def rule_family(snippet):
    """Family the rule layer alone would output ('abstain' if it cannot decide)."""
    r = scan_snippet(snippet)
    if r.status == "detected":
        return "combined" if len(r.families) > 1 else r.families[0]
    if r.status == "ambiguous":
        return "abstain"
    return "none"


def weak_algorithm_label(entry, rule_result):
    """Algorithm label for training.

    The paper's dataset labels the primitive FAMILY, not the exact algorithm. Unless the
    dataset has an algorithm column, we take the algorithm from the rule layer on the
    pre-quantum code. That is weak supervision, so the algorithm score from this run says
    how well the model copies the rules, not how well it matches human labels.
    """
    if entry.algorithm:
        return entry.algorithm
    if entry.family == "none":
        return "none"
    if entry.family == "combined" or len(rule_result.algorithms) != 1:
        return "combined" if entry.family == "combined" else "unknown"
    return rule_result.algorithms[0]


def hybrid_family(decision):
    if decision.status == "no_crypto":
        return "none"
    if decision.status in ("abstain", "ambiguous"):
        return "abstain"
    return "combined" if len(decision.families) > 1 else (decision.families or ["abstain"])[0]


def scores(y_true, y_pred):
    return {"accuracy": round(accuracy_score(y_true, y_pred), 4),
            "macro_f1": round(f1_score(y_true, y_pred, average="macro", zero_division=0), 4)}


def build_examples(entries, seed=RANDOM_SEED):
    """Dataset rows plus negatives -> parallel lists of text, family, algorithm."""
    texts, families, algos = [], [], []
    for e in entries:
        texts.append(e.pre_code)
        families.append(e.family)
        algos.append(weak_algorithm_label(e, scan_snippet(e.pre_code)))
    n_neg = max(20, len(entries) // 6)
    for code in sample_negative_snippets(n_neg, seed):
        texts.append(code)
        families.append("none")
        algos.append("none")
    return texts, families, algos


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--dataset", help="file or folder; default: data/ (real) or the stand-in")
    ap.add_argument("--encoder", default="tfidf", choices=["tfidf", "codebert"])
    ap.add_argument("--codebert-path", default="microsoft/codebert-base")
    args = ap.parse_args()

    path, standin = find_dataset(args.dataset)
    if not path.exists():
        raise SystemExit(f"{path} not found. Put the real dataset in data/ or run "
                         "scripts/make_standin_dataset.py")
    entries, skipped = load_dataset(path)
    if standin:
        print("!! Training on the SYNTHETIC stand-in. Results below do not describe real code.")
    print(f"dataset: {path}  entries={len(entries)}  skipped={len(skipped)}")

    texts, families, algos = build_examples(entries)
    idx = np.arange(len(texts))
    train_idx, test_idx = train_test_split(idx, test_size=TEST_FRACTION, random_state=RANDOM_SEED,
                                           stratify=families)
    pick = lambda items, ids: [items[i] for i in ids]
    tr_x, tr_f, tr_a = (pick(v, train_idx) for v in (texts, families, algos))
    te_x, te_f, te_a = (pick(v, test_idx) for v in (texts, families, algos))

    kwargs = {"model_path": args.codebert_path} if args.encoder == "codebert" else {}
    model = FusionClassifier(args.encoder, **kwargs).fit(tr_x, tr_f, tr_a)

    # --- evaluation on the held-out part ------------------------------------- #
    rule_pred = [rule_family(t) for t in te_x]
    preds = model.predict(te_x)
    model_pred = [p.family for p in preds]
    hybrid_pred = []
    for t, p in zip(te_x, preds):
        rule = scan_snippet(t)
        hybrid_pred.append(hybrid_family(arbitrate(rule, p)))

    labels = FAMILY_LABELS
    metrics = {
        "dataset": {"path": str(path), "standin": standin, "entries": len(entries),
                    "train": len(train_idx), "test": len(test_idx),
                    "negatives_added": families.count("none"),
                    "encoder": model.encoder.name},
        "family": {"rules_only": scores(te_f, rule_pred), "model_only": scores(te_f, model_pred),
                   "hybrid": scores(te_f, hybrid_pred)},
        "abstain_rate": {"rules_only": round(rule_pred.count("abstain") / len(te_f), 4),
                         "hybrid": round(hybrid_pred.count("abstain") / len(te_f), 4)},
        "algorithm_vs_weak_labels": {"model_only": round(accuracy_score(
            te_a, [p.algorithm if p.algorithm in set(te_a) else "other" for p in preds]), 4),
            "note": "labels come from the rule layer, so rules-only is not reported"},
        "per_family_hybrid": classification_report(te_f, hybrid_pred, labels=labels,
                                                   output_dict=True, zero_division=0),
        "confusion_hybrid": {"labels": labels + ["abstain"],
                             "matrix": confusion_matrix(te_f, hybrid_pred,
                                                        labels=labels + ["abstain"]).tolist()},
        "class_counts_test": dict(Counter(te_f)),
    }

    MODEL_DIR.mkdir(exist_ok=True)
    REPORT_DIR.mkdir(exist_ok=True)
    model.save(MODEL_DIR / "classifier.joblib")
    (REPORT_DIR / "metrics.json").write_text(json.dumps(metrics, indent=2))

    print(f"\n{'family accuracy / macro-F1 on held-out data':<45}")
    for name, s in metrics["family"].items():
        print(f"  {name:<12} acc={s['accuracy']:.3f}  macroF1={s['macro_f1']:.3f}")
    print(f"  abstain rate: {metrics['abstain_rate']}")
    print(f"saved {MODEL_DIR / 'classifier.joblib'} and {REPORT_DIR / 'metrics.json'}")


if __name__ == "__main__":
    main()