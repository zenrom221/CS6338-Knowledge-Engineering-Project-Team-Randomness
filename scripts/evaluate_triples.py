"""
Evaluate extracted triples against a gold triple dataset.

Gold format: the JSON you provided (list under "triples", each with
subject/predicate/object and a "decision" field).

Predicted format: either the same triple-list shape, or a plain list of
dicts with subject/predicate/object keys.
"""

import json
import argparse
from collections import Counter
from pathlib import Path


# ============================================================
# LOADING
# ============================================================
def load_gold(path: str) -> set[tuple[str, str, str]]:
    """Load gold triples where decision == 'accept_candidate'."""
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    triples = data.get("triples", [])
    gold = set()
    for t in triples:
        if t.get("decision") != "accept_candidate":
            continue
        subj = norm(t.get("subject", ""))
        pred = norm(t.get("predicate", ""))
        obj = norm(t.get("object", ""))
        if subj and pred and obj:
            gold.add((subj, pred, obj))
    return gold


def load_predicted(path: str) -> set[tuple[str, str, str]]:
    """Load predicted triples from JSON. Accepts the same shape as gold
    or a plain list of {subject, predicate, object} dicts."""
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if isinstance(data, dict):
        items = data.get("triples", data.get("predictions", []))
    else:
        items = data

    preds = set()
    for t in items:
        subj = norm(t.get("subject", ""))
        pred = norm(t.get("predicate", ""))
        obj = norm(t.get("object", ""))
        if subj and pred and obj:
            preds.add((subj, pred, obj))
    return preds


def norm(s: str) -> str:
    """Normalize a string: strip and lowercase. Keep case-sensitive
    comparison by removing this call if your IDs are case-sensitive."""
    return str(s).strip().lower()


# ============================================================
# METRICS
# ============================================================
def evaluate(gold: set, pred: set) -> dict:
    tp = len(gold & pred)
    fp = len(pred - gold)
    fn = len(gold - pred)

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "gold_size": len(gold),
        "pred_size": len(pred),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "true_positives": sorted(gold & pred),
        "false_positives": sorted(pred - gold),
        "false_negatives": sorted(gold - pred),
    }


# ============================================================
# PER-PREDICATE BREAKDOWN
# ============================================================
def per_predicate_report(gold: set, pred: set) -> dict:
    """Compute P/R/F1 grouped by predicate type."""
    gold_by_pred = {}
    pred_by_pred = {}
    for s, p, o in gold:
        gold_by_pred.setdefault(p, set()).add((s, p, o))
    for s, p, o in pred:
        pred_by_pred.setdefault(p, set()).add((s, p, o))

    all_preds = set(gold_by_pred) | set(pred_by_pred)
    report = {}
    for p in sorted(all_preds):
        g = gold_by_pred.get(p, set())
        pr = pred_by_pred.get(p, set())
        tp = len(g & pr)
        fp = len(pr - g)
        fn = len(g - pr)
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
        report[p] = {
            "gold": len(g),
            "pred": len(pr),
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
        }
    return report


# ============================================================
# MAIN
# ============================================================
def main():
    ap = argparse.ArgumentParser(description="Evaluate triple extraction against gold.")
    ap.add_argument("--gold", required=True, help="Path to gold JSON")
    ap.add_argument("--pred", required=True, help="Path to predicted JSON")
    ap.add_argument("--out", default="eval_report.json", help="Output report path")
    args = ap.parse_args()

    gold = load_gold(args.gold)
    pred = load_predicted(args.pred)

    overall = evaluate(gold, pred)
    per_pred = per_predicate_report(gold, pred)

    report = {
        "overall": overall,
        "per_predicate": per_pred,
        "confusion": {
            "true_positives": overall["true_positives"],
            "false_positives": overall["false_positives"],
            "false_negatives": overall["false_negatives"],
        },
    }

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    # Print summary
    print(f"Gold triples:      {overall['gold_size']}")
    print(f"Predicted triples: {overall['pred_size']}")
    print(f"TP={overall['tp']}  FP={overall['fp']}  FN={overall['fn']}")
    print(f"Precision: {overall['precision']:.4f}")
    print(f"Recall:    {overall['recall']:.4f}")
    print(f"F1:        {overall['f1']:.4f}")
    print(f"\nPer-predicate breakdown:")
    for p, m in per_pred.items():
        print(f"  {p}: P={m['precision']:.3f} R={m['recall']:.3f} F1={m['f1']:.3f} "
              f"(TP={m['tp']} FP={m['fp']} FN={m['fn']})")
    print(f"\nFull report saved to {args.out}")


if __name__ == "__main__":
    main()