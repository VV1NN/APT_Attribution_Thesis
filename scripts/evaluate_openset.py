#!/usr/bin/env python3
"""Actor holdout open-set evaluation for unknown detection."""

from __future__ import annotations

import json
import pickle
import sys
from collections import Counter
from pathlib import Path

import numpy as np
from sklearn.impute import SimpleImputer
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import StratifiedShuffleSplit
from sklearn.preprocessing import LabelEncoder
from xgboost import XGBClassifier

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR / "model"))

from calibration_utils import apply_temperature_to_probs, fpr_at_target_tpr

FEATURE_PATH = SCRIPT_DIR / "features/features_all.npz"
CALIBRATOR_PATH = SCRIPT_DIR / "model/calibrator.pkl"
OUTPUT_PATH = SCRIPT_DIR / "results/evaluate_openset.json"


def balanced_weights(y):
    classes, counts = np.unique(y, return_counts=True)
    n, k = len(y), len(classes)
    w_map = {c: n / (k * cnt) for c, cnt in zip(classes, counts)}
    return np.array([w_map[yi] for yi in y])


def main():
    if not FEATURE_PATH.exists():
        raise FileNotFoundError(FEATURE_PATH)
    if not CALIBRATOR_PATH.exists():
        raise FileNotFoundError(
            f"{CALIBRATOR_PATH} not found. Run: uv run python scripts/model/calibrate_probs.py"
        )

    with open(CALIBRATOR_PATH, "rb") as f:
        calibrator = pickle.load(f)

    temperature = float(calibrator.get("temperature", 1.0))
    open_set_thr = float(calibrator.get("open_set_conf_threshold", 0.45))

    data = np.load(FEATURE_PATH, allow_pickle=True)
    X = data["X"]
    y = data["y"].astype(str)
    class_counts = Counter(y.tolist())
    actors = sorted(class_counts.keys())

    per_actor = []

    for holdout_actor in actors:
        unknown_mask = y == holdout_actor
        known_mask = ~unknown_mask

        X_known = X[known_mask]
        y_known = y[known_mask]
        X_unknown = X[unknown_mask]

        # Split known into train/test
        sss = StratifiedShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
        tr_rel, te_rel = next(sss.split(X_known, y_known))
        Xtr_raw, Xte_known_raw = X_known[tr_rel], X_known[te_rel]
        ytr_raw, yte_known_raw = y_known[tr_rel], y_known[te_rel]

        le = LabelEncoder()
        ytr = le.fit_transform(ytr_raw)
        yte_known = le.transform(yte_known_raw)

        imputer = SimpleImputer(strategy="median")
        Xtr = imputer.fit_transform(Xtr_raw)
        Xte_known = imputer.transform(Xte_known_raw)
        Xte_unknown = imputer.transform(X_unknown)

        clf = XGBClassifier(
            n_estimators=300,
            max_depth=8,
            learning_rate=0.05,
            subsample=0.8,
            colsample_bytree=0.8,
            min_child_weight=3,
            eval_metric="mlogloss",
            random_state=42,
            n_jobs=-1,
            verbosity=0,
        )
        clf.fit(Xtr, ytr, sample_weight=balanced_weights(ytr))

        probs_known_raw = clf.predict_proba(Xte_known)
        probs_unknown_raw = clf.predict_proba(Xte_unknown)
        probs_known_cal = apply_temperature_to_probs(probs_known_raw, temperature=temperature)
        probs_unknown_cal = apply_temperature_to_probs(probs_unknown_raw, temperature=temperature)

        conf_known = np.max(probs_known_cal, axis=1)
        conf_unknown = np.max(probs_unknown_cal, axis=1)

        # Unknown detection score: higher = more likely unknown
        score_known = 1.0 - conf_known
        score_unknown = 1.0 - conf_unknown

        y_bin = np.concatenate(
            [np.zeros(len(score_known), dtype=np.int32), np.ones(len(score_unknown), dtype=np.int32)]
        )
        score_bin = np.concatenate([score_known, score_unknown])

        auroc = float(roc_auc_score(y_bin, score_bin))
        fpr95 = float(fpr_at_target_tpr(y_bin, score_bin, target_tpr=0.95))

        # Unknown misattribution with open-set abstain threshold
        unknown_predicted_known = conf_unknown >= open_set_thr
        unknown_misattribution_rate = float(np.mean(unknown_predicted_known))

        per_actor.append(
            {
                "holdout_actor": holdout_actor,
                "n_unknown": int(len(X_unknown)),
                "n_known_test": int(len(Xte_known)),
                "auroc": auroc,
                "fpr_at_95_tpr": fpr95,
                "unknown_misattribution_rate": unknown_misattribution_rate,
                "unknown_abstain_rate": float(1.0 - unknown_misattribution_rate),
            }
        )

        print(
            f"{holdout_actor:<20} AUROC={auroc:.4f} "
            f"FPR@95TPR={fpr95:.4f} "
            f"Unknown-MisAttr={unknown_misattribution_rate:.4f}"
        )

    summary = {
        "auroc_mean": float(np.mean([r["auroc"] for r in per_actor])),
        "auroc_std": float(np.std([r["auroc"] for r in per_actor])),
        "fpr95_mean": float(np.mean([r["fpr_at_95_tpr"] for r in per_actor])),
        "fpr95_std": float(np.std([r["fpr_at_95_tpr"] for r in per_actor])),
        "unknown_misattribution_mean": float(np.mean([r["unknown_misattribution_rate"] for r in per_actor])),
        "unknown_misattribution_std": float(np.std([r["unknown_misattribution_rate"] for r in per_actor])),
        "open_set_conf_threshold": open_set_thr,
        "temperature": temperature,
    }

    payload = {
        "summary": summary,
        "per_actor": per_actor,
    }
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_PATH, "w") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)

    print("\nOpen-set evaluation complete")
    print(f"  AUROC mean: {summary['auroc_mean']:.4f} ± {summary['auroc_std']:.4f}")
    print(f"  FPR@95TPR mean: {summary['fpr95_mean']:.4f} ± {summary['fpr95_std']:.4f}")
    print(
        "  Unknown misattribution mean: "
        f"{summary['unknown_misattribution_mean']:.4f} ± {summary['unknown_misattribution_std']:.4f}"
    )
    print(f"  Saved: {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
