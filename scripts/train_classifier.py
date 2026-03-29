#!/usr/bin/env python3
"""
訓練分類器 + 5-fold Stratified CV 評估。
Exp1: L1 only, Exp2: L1+L3。
"""

import json
import logging
import warnings
from pathlib import Path

import numpy as np
from sklearn.model_selection import StratifiedKFold
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.impute import SimpleImputer
from sklearn.metrics import f1_score, classification_report
from sklearn.ensemble import RandomForestClassifier
from sklearn.neural_network import MLPClassifier
from xgboost import XGBClassifier

warnings.filterwarnings("ignore", category=UserWarning)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S")
logger = logging.getLogger(__name__)

FEATURE_DIR = Path("scripts/features")
OUTPUT_DIR = Path("scripts/results")


def load_data():
    for fname in ["features_all.npz", "features_l1_l2_l3.npz", "features_l1_l3.npz"]:
        p = FEATURE_DIR / fname
        if p.exists():
            data = np.load(p, allow_pickle=True)
            break
    with open(FEATURE_DIR / "feature_names.json") as f:
        names = json.load(f)
    return data["X"], data["y"], names


def balanced_weights(y):
    """回傳 sample_weight（balanced）。"""
    classes, counts = np.unique(y, return_counts=True)
    n = len(y)
    k = len(classes)
    w_map = {c: n / (k * cnt) for c, cnt in zip(classes, counts)}
    return np.array([w_map[yi] for yi in y])


def evaluate(y_true, y_prob):
    y_pred = np.argmax(y_prob, axis=1)
    micro = f1_score(y_true, y_pred, average="micro")
    macro = f1_score(y_true, y_pred, average="macro")
    top3 = np.mean([1.0 if y_true[i] in np.argsort(y_prob[i])[-3:] else 0.0 for i in range(len(y_true))])
    top5 = np.mean([1.0 if y_true[i] in np.argsort(y_prob[i])[-5:] else 0.0 for i in range(len(y_true))])
    return {"micro_f1": micro, "macro_f1": macro, "top3_acc": top3, "top5_acc": top5, "y_pred": y_pred}


def run_cv(X, y_enc, le, feat_idx, exp_name):
    """5-fold CV，回傳三個分類器的結果。"""
    X_sub = X[:, feat_idx]

    # Impute NaN → median（fit on full data for imputer, per-fold for scaler is below）
    imputer = SimpleImputer(strategy="median")
    X_imp = imputer.fit_transform(X_sub)

    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

    classifiers = {
        "XGBoost": lambda: XGBClassifier(
            n_estimators=500, max_depth=8, learning_rate=0.05,
            subsample=0.8, colsample_bytree=0.8, min_child_weight=3,
            eval_metric="mlogloss", random_state=42, n_jobs=-1, verbosity=0,
        ),
        "RandomForest": lambda: RandomForestClassifier(
            n_estimators=500, class_weight="balanced", random_state=42, n_jobs=-1,
        ),
        "MLP": lambda: MLPClassifier(
            hidden_layer_sizes=(256, 128, 64), early_stopping=True,
            max_iter=500, random_state=42,
        ),
    }

    results = {}
    for clf_name, clf_fn in classifiers.items():
        fold_metrics = []
        all_true, all_pred = [], []

        for fold, (tr, te) in enumerate(skf.split(X_imp, y_enc)):
            Xtr, Xte = X_imp[tr], X_imp[te]
            ytr, yte = y_enc[tr], y_enc[te]

            clf = clf_fn()

            if clf_name == "MLP":
                sc = StandardScaler()
                Xtr = sc.fit_transform(Xtr)
                Xte = sc.transform(Xte)
                clf.fit(Xtr, ytr)
            elif clf_name == "XGBoost":
                sw = balanced_weights(ytr)
                clf.fit(Xtr, ytr, sample_weight=sw)
            else:
                clf.fit(Xtr, ytr)

            prob = clf.predict_proba(Xte)
            m = evaluate(yte, prob)
            fold_metrics.append(m)
            all_true.extend(yte.tolist())
            all_pred.extend(m["y_pred"].tolist())

        # 彙總
        avg = {}
        for key in ["micro_f1", "macro_f1", "top3_acc", "top5_acc"]:
            vals = [fm[key] for fm in fold_metrics]
            avg[key] = float(np.mean(vals))
            avg[f"{key}_std"] = float(np.std(vals))

        report = classification_report(all_true, all_pred,
                                       target_names=le.classes_,
                                       output_dict=True, zero_division=0)
        avg["per_class_f1"] = {c: round(report[c]["f1-score"], 4) for c in le.classes_ if c in report}

        results[clf_name] = avg
        logger.info(f"  {clf_name}: Micro={avg['micro_f1']:.4f}±{avg['micro_f1_std']:.4f}  "
                     f"Macro={avg['macro_f1']:.4f}  Top3={avg['top3_acc']:.4f}  Top5={avg['top5_acc']:.4f}")

    return results


def main():
    X, y, names = load_data()
    le = LabelEncoder()
    y_enc = le.fit_transform(y)

    n_l1 = len(names["l1"])
    n_l2 = len(names.get("l2", []))
    n_l3 = len(names["l3"])
    n_l4 = len(names.get("l4", []))
    logger.info(f"Dataset: {X.shape[0]} samples, {X.shape[1]} features "
                f"({n_l1} L1 + {n_l2} L2 + {n_l3} L3 + {n_l4} L4), {len(le.classes_)} classes")

    l1_idx = list(range(n_l1))
    l2_idx = list(range(n_l1, n_l1 + n_l2))
    l3_idx = list(range(n_l1 + n_l2, n_l1 + n_l2 + n_l3))
    l4_idx = list(range(n_l1 + n_l2 + n_l3, n_l1 + n_l2 + n_l3 + n_l4))

    experiments = {
        "Exp1_L1":           l1_idx,
        "Exp2_L1_L2":        l1_idx + l2_idx,
        "Exp3_L1_L2_L3":     l1_idx + l2_idx + l3_idx,
        "Exp4_L1_L2_L3_L4":  l1_idx + l2_idx + l3_idx + l4_idx,
    }

    all_results = {}
    for exp, idx in experiments.items():
        logger.info(f"\n{'='*60}\n{exp} ({len(idx)} features)\n{'='*60}")
        all_results[exp] = run_cv(X, y_enc, le, idx, exp)

    # ── 儲存 ──
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_DIR / "results_ablation.json", "w") as f:
        json.dump(all_results, f, indent=2, default=lambda x: x.tolist() if isinstance(x, np.ndarray) else x,
                  ensure_ascii=False)

    # ── 輸出摘要表 ──
    print(f"\n{'='*90}")
    print(f"{'Experiment':<18} {'Classifier':<14} {'Micro-F1':>10} {'Macro-F1':>10} {'Top-3':>10} {'Top-5':>10}")
    print(f"{'='*90}")
    for exp, res in all_results.items():
        for clf, m in res.items():
            print(f"{exp:<18} {clf:<14} "
                  f"{m['micro_f1']:>9.4f}  {m['macro_f1']:>9.4f}  "
                  f"{m['top3_acc']:>9.4f}  {m['top5_acc']:>9.4f}")
    print(f"{'='*90}")

    # Per-class F1 for best config
    best_exp = "Exp4_L1_L2_L3_L4" if "Exp4_L1_L2_L3_L4" in all_results else "Exp3_L1_L2_L3"
    best = all_results.get(best_exp, {}).get("XGBoost", {})
    if best:
        print(f"\nPer-class F1 ({best_exp} / XGBoost):")
        pcf = best.get("per_class_f1", {})
        for org in sorted(pcf, key=lambda x: -pcf[x]):
            print(f"  {org:<25} {pcf[org]:.4f}")

    # Marginal contributions
    xgb = {exp: res.get("XGBoost", {}).get("micro_f1", 0) for exp, res in all_results.items()}
    exps = list(xgb.keys())
    if len(exps) >= 2:
        print(f"\nMarginal contributions (XGBoost Micro-F1):")
        for i in range(1, len(exps)):
            delta = xgb[exps[i]] - xgb[exps[i-1]]
            print(f"  {exps[i-1]} → {exps[i]}: {xgb[exps[i-1]]:.4f} → {xgb[exps[i]]:.4f} ({delta:+.4f})")

    logger.info(f"\nResults saved to {OUTPUT_DIR}/results_ablation.json")


if __name__ == "__main__":
    main()
