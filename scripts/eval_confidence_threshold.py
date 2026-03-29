#!/usr/bin/env python3
"""
信心度門檻實驗：
1. Threshold sweep：最高機率 < threshold → 判定為 Unknown（拒絕歸因）
2. 產出 threshold vs precision/recall/coverage 曲線資料
3. 排除 OilRig 的 14-org 結果
"""

import json
import logging
import warnings
from pathlib import Path

import numpy as np
from sklearn.model_selection import StratifiedKFold
from sklearn.preprocessing import LabelEncoder
from sklearn.impute import SimpleImputer
from sklearn.metrics import f1_score, precision_score, recall_score, confusion_matrix
from xgboost import XGBClassifier

warnings.filterwarnings("ignore")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S")
logger = logging.getLogger(__name__)

FEATURE_DIR = Path("scripts/features")
OUTPUT_DIR = Path("scripts/results")


def balanced_weights(y):
    classes, counts = np.unique(y, return_counts=True)
    n, k = len(y), len(classes)
    w_map = {c: n / (k * cnt) for c, cnt in zip(classes, counts)}
    return np.array([w_map[yi] for yi in y])


def main():
    # ── Load ──
    data = np.load(FEATURE_DIR / "features_all.npz", allow_pickle=True)
    with open(FEATURE_DIR / "feature_names.json") as f:
        names = json.load(f)

    X_raw, y_raw = data["X"], data["y"]
    le = LabelEncoder()
    y = le.fit_transform(y_raw)
    classes = list(le.classes_)

    imp = SimpleImputer(strategy="median")
    X = imp.fit_transform(X_raw)

    logger.info(f"Data: {X.shape}, {len(classes)} classes")

    # ── 5-fold CV: collect probabilities ──
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    all_true = np.zeros(len(y), dtype=int)
    all_probs = np.zeros((len(y), len(classes)), dtype=np.float32)

    for fold, (tr, te) in enumerate(skf.split(X, y)):
        clf = XGBClassifier(
            n_estimators=500, max_depth=8, learning_rate=0.05,
            subsample=0.8, colsample_bytree=0.8, min_child_weight=3,
            eval_metric="mlogloss", random_state=42, n_jobs=-1, verbosity=0,
        )
        clf.fit(X[tr], y[tr], sample_weight=balanced_weights(y[tr]))
        all_probs[te] = clf.predict_proba(X[te])
        all_true[te] = y[te]

    all_pred = np.argmax(all_probs, axis=1)
    all_conf = np.max(all_probs, axis=1)

    # ════════════════════════════════════════════════════════════
    # Part 1: Threshold Sweep
    # ════════════════════════════════════════════════════════════
    thresholds = np.arange(0.05, 0.95, 0.05)

    print(f"\n{'='*90}")
    print(f"{'Threshold':>10} {'Coverage':>10} {'Micro-F1':>10} {'Macro-F1':>10} "
          f"{'Precision':>10} {'Recall':>10} {'Unknown':>10}")
    print(f"{'='*90}")

    sweep_results = []
    for thr in thresholds:
        # 高於門檻的才歸因，低於的判為 Unknown
        mask = all_conf >= thr
        n_attributed = mask.sum()
        n_unknown = (~mask).sum()
        coverage = n_attributed / len(y)

        if n_attributed == 0:
            sweep_results.append({
                "threshold": float(thr), "coverage": 0.0,
                "micro_f1": 0.0, "macro_f1": 0.0,
                "precision": 0.0, "recall": 0.0,
                "n_attributed": 0, "n_unknown": int(n_unknown),
            })
            print(f"{thr:>10.2f} {0:>10.1%} {'N/A':>10} {'N/A':>10} {'N/A':>10} {'N/A':>10} {n_unknown:>10}")
            continue

        y_true_sub = all_true[mask]
        y_pred_sub = all_pred[mask]

        micro = f1_score(y_true_sub, y_pred_sub, average="micro")
        macro = f1_score(y_true_sub, y_pred_sub, average="macro", zero_division=0)
        prec = precision_score(y_true_sub, y_pred_sub, average="micro")
        rec = recall_score(y_true_sub, y_pred_sub, average="micro")

        sweep_results.append({
            "threshold": float(thr), "coverage": float(coverage),
            "micro_f1": float(micro), "macro_f1": float(macro),
            "precision": float(prec), "recall": float(rec),
            "n_attributed": int(n_attributed), "n_unknown": int(n_unknown),
        })
        print(f"{thr:>10.2f} {coverage:>10.1%} {micro:>10.4f} {macro:>10.4f} "
              f"{prec:>10.4f} {rec:>10.4f} {n_unknown:>10}")

    print(f"{'='*90}")

    # ════════════════════════════════════════════════════════════
    # Part 2: Key threshold analysis (0.3)
    # ════════════════════════════════════════════════════════════
    thr = 0.30
    mask = all_conf >= thr
    logger.info(f"\n=== Threshold = {thr} 詳細分析 ===")
    logger.info(f"Coverage: {mask.sum()}/{len(y)} ({mask.mean():.1%})")
    logger.info(f"Rejected as Unknown: {(~mask).sum()}")

    y_true_sub = all_true[mask]
    y_pred_sub = all_pred[mask]

    micro = f1_score(y_true_sub, y_pred_sub, average="micro")
    macro = f1_score(y_true_sub, y_pred_sub, average="macro", zero_division=0)
    logger.info(f"Micro-F1: {micro:.4f}, Macro-F1: {macro:.4f}")

    # Per-class at threshold 0.3
    print(f"\nPer-class results at threshold={thr}:")
    print(f"{'APT':<22} {'n_total':>8} {'n_kept':>8} {'kept%':>8} {'F1':>8} {'Prec':>8} {'Recall':>8}")
    print("-" * 70)

    per_class_thr = {}
    for i, cls in enumerate(classes):
        total_mask = all_true == i
        kept_mask = total_mask & mask
        n_total = total_mask.sum()
        n_kept = kept_mask.sum()

        if n_kept > 0:
            cls_pred = all_pred[kept_mask]
            cls_true = all_true[kept_mask]
            tp = ((cls_pred == i) & (cls_true == i)).sum()
            # For this class: precision among all predicted as this class (within threshold)
            pred_as_cls = (all_pred[mask] == i)
            true_of_pred = (all_true[mask][pred_as_cls] == i)
            prec_cls = true_of_pred.mean() if pred_as_cls.sum() > 0 else 0.0
            rec_cls = tp / n_total if n_total > 0 else 0.0
            f1_cls = 2 * prec_cls * rec_cls / (prec_cls + rec_cls) if (prec_cls + rec_cls) > 0 else 0.0
        else:
            prec_cls = rec_cls = f1_cls = 0.0

        per_class_thr[cls] = {"n_total": int(n_total), "n_kept": int(n_kept),
                               "precision": float(prec_cls), "recall": float(rec_cls), "f1": float(f1_cls)}
        print(f"{cls:<22} {n_total:>8} {n_kept:>8} {n_kept/n_total:>8.1%} "
              f"{f1_cls:>8.3f} {prec_cls:>8.3f} {rec_cls:>8.3f}")

    # ════════════════════════════════════════════════════════════
    # Part 3: Confusion matrix at threshold=0.3
    # ════════════════════════════════════════════════════════════
    cm = confusion_matrix(y_true_sub, y_pred_sub, labels=list(range(len(classes))))
    print(f"\nConfusion Matrix at threshold={thr} (rejected samples excluded):")
    print(f"\nTop-10 confused pairs:")
    pairs = []
    for i in range(len(classes)):
        for j in range(len(classes)):
            if i != j and cm[i, j] > 0:
                pairs.append((classes[i], classes[j], int(cm[i, j])))
    pairs.sort(key=lambda x: -x[2])
    for true_c, pred_c, cnt in pairs[:10]:
        print(f"  {true_c:<20} → {pred_c:<20} {cnt:>4}")

    # OilRig false positive count at threshold
    oilrig_idx = classes.index("OilRig")
    oilrig_pred_total = (all_pred[mask] == oilrig_idx).sum()
    oilrig_pred_correct = cm[oilrig_idx, oilrig_idx] if oilrig_idx < len(cm) else 0
    print(f"\nOilRig at threshold={thr}:")
    print(f"  Predicted as OilRig: {oilrig_pred_total} (was {(all_pred == oilrig_idx).sum()} without threshold)")
    print(f"  True positives: {oilrig_pred_correct}")
    print(f"  False positives: {oilrig_pred_total - oilrig_pred_correct}")
    if oilrig_pred_total > 0:
        print(f"  Precision: {oilrig_pred_correct/oilrig_pred_total:.3f} (was 0.148 without threshold)")

    # ════════════════════════════════════════════════════════════
    # Part 4: 14-org results (exclude OilRig)
    # ════════════════════════════════════════════════════════════
    print(f"\n{'='*70}")
    print(f"14-org results (excluding OilRig)")
    print(f"{'='*70}")

    non_oilrig = all_true != oilrig_idx
    y14_true = all_true[non_oilrig]
    y14_pred = all_pred[non_oilrig]

    # Without threshold
    micro14 = f1_score(y14_true, y14_pred, average="micro")
    macro14 = f1_score(y14_true, y14_pred, average="macro", zero_division=0)
    print(f"Without threshold: Micro-F1={micro14:.4f}, Macro-F1={macro14:.4f}")

    # Fix: predictions that pointed to OilRig are wrong for 14-org
    # Actually just compute normally — if a non-OilRig sample is predicted as OilRig, it's wrong
    # That's already captured in the F1 calculation

    # With threshold=0.3
    mask14 = non_oilrig & mask
    if mask14.sum() > 0:
        micro14t = f1_score(all_true[mask14], all_pred[mask14], average="micro")
        macro14t = f1_score(all_true[mask14], all_pred[mask14], average="macro", zero_division=0)
        cov14 = mask14.sum() / non_oilrig.sum()
        print(f"With threshold=0.3: Micro-F1={micro14t:.4f}, Macro-F1={macro14t:.4f}, Coverage={cov14:.1%}")

    # ── Save ──
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    report = {
        "threshold_sweep": sweep_results,
        "threshold_0.3_per_class": per_class_thr,
        "fourteen_org": {
            "micro_f1_no_threshold": float(micro14),
            "macro_f1_no_threshold": float(macro14),
        },
    }
    with open(OUTPUT_DIR / "confidence_threshold.json", "w") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    logger.info(f"Saved to {OUTPUT_DIR}/confidence_threshold.json")


if __name__ == "__main__":
    main()
