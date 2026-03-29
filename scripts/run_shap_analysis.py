#!/usr/bin/env python3
"""
SHAP 分析：解釋四層特徵對 APT 歸因的貢獻。
1. 全域 feature importance（mean |SHAP|）
2. Per-class top features（每個 APT 最重要的特徵）
3. 儲存 SHAP values 供後續視覺化
"""

import json
import logging
import warnings
from pathlib import Path

import numpy as np
import shap
from sklearn.preprocessing import LabelEncoder
from sklearn.impute import SimpleImputer
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
    # ── 載入資料 ──
    for fname in ["features_all.npz", "features_l1_l2_l3.npz"]:
        p = FEATURE_DIR / fname
        if p.exists():
            data = np.load(p, allow_pickle=True)
            break
    with open(FEATURE_DIR / "feature_names.json") as f:
        names = json.load(f)

    X_raw = data["X"]
    y_raw = data["y"]
    feature_names = names["all"]
    org_list = names["org_list"]

    le = LabelEncoder()
    y = le.fit_transform(y_raw)
    class_names = list(le.classes_)

    logger.info(f"Data: {X_raw.shape}, {len(class_names)} classes")

    # ── Impute ──
    imputer = SimpleImputer(strategy="median")
    X = imputer.fit_transform(X_raw)

    # ── 訓練最終模型 ──
    logger.info("Training final XGBoost model on full data...")
    sw = balanced_weights(y)
    model = XGBClassifier(
        n_estimators=500, max_depth=8, learning_rate=0.05,
        subsample=0.8, colsample_bytree=0.8, min_child_weight=3,
        eval_metric="mlogloss", random_state=42, n_jobs=-1, verbosity=0,
    )
    model.fit(X, y, sample_weight=sw)
    logger.info("Model trained.")

    # ── SHAP TreeExplainer ──
    logger.info("Computing SHAP values (this may take a few minutes)...")

    # Patch: XGBoost 3.x multi-class base_score 是 vector string，SHAP 0.49 會炸
    # 直接 patch SHAP 的 _tree 模組，讓 base_score 遇到 vector 時取平均
    import shap.explainers._tree as _shap_tree
    _orig_loader_init = _shap_tree.XGBTreeModelLoader.__init__

    def _patched_loader_init(self, xgb_model):
        # Temporarily patch float to handle vector base_score
        import builtins
        _orig_float = builtins.float

        def _safe_float(x):
            try:
                return _orig_float(x)
            except (ValueError, TypeError):
                if isinstance(x, str) and x.startswith("["):
                    # vector base_score — parse and take mean (≈0 for softmax)
                    vals = [_orig_float(v) for v in x.strip("[]").split(",")]
                    return _orig_float(np.mean(vals))
                raise

        builtins.float = _safe_float
        try:
            _orig_loader_init(self, xgb_model)
        finally:
            builtins.float = _orig_float

    _shap_tree.XGBTreeModelLoader.__init__ = _patched_loader_init

    explainer = shap.TreeExplainer(model)
    shap_values = explainer.shap_values(X)

    # shap_values: list of K arrays (n_samples, n_features)
    # or ndarray (n_samples, n_features, n_classes)
    if isinstance(shap_values, list):
        shap_array = np.array(shap_values)  # (K, n_samples, n_features)
    elif shap_values.ndim == 3:
        shap_array = np.moveaxis(shap_values, -1, 0)  # → (K, n_samples, n_features)
    else:
        raise ValueError(f"Unexpected shap_values shape: {shap_values.shape}")

    n_classes, n_samples, n_features = shap_array.shape
    logger.info(f"SHAP values shape: {shap_array.shape}")

    # ── 1. Global feature importance (mean |SHAP| across all classes) ──
    global_importance = np.mean(np.abs(shap_array), axis=(0, 1))  # (n_features,)
    ranked_idx = np.argsort(-global_importance)

    print(f"\n{'='*70}")
    print(f"Global Feature Importance (mean |SHAP|, top 30)")
    print(f"{'='*70}")
    for rank, idx in enumerate(ranked_idx[:30], 1):
        fname = feature_names[idx]
        val = global_importance[idx]
        # 標記所屬 layer
        if idx < len(names["l1"]):
            layer = "L1"
        elif idx < len(names["l1"]) + len(names.get("l2", [])):
            layer = "L2"
        elif idx < len(names["l1"]) + len(names.get("l2", [])) + len(names["l3"]):
            layer = "L3"
        else:
            layer = "L4"
        print(f"  {rank:2d}. [{layer}] {fname:<35} {val:.4f}")

    # ── 2. Layer-level importance ──
    n_l1 = len(names["l1"])
    n_l2 = len(names.get("l2", []))
    n_l3 = len(names["l3"])
    n_l4 = len(names.get("l4", []))

    layer_ranges = {
        "L1 (Node Self)":    (0, n_l1),
        "L2 (Neighborhood)": (n_l1, n_l1 + n_l2),
        "L3 (Overlap)":      (n_l1 + n_l2, n_l1 + n_l2 + n_l3),
        "L4 (Node2Vec)":     (n_l1 + n_l2 + n_l3, n_l1 + n_l2 + n_l3 + n_l4),
    }

    print(f"\n{'='*70}")
    print(f"Layer-level SHAP Importance")
    print(f"{'='*70}")
    layer_totals = {}
    for layer_name, (start, end) in layer_ranges.items():
        layer_imp = np.sum(global_importance[start:end])
        layer_totals[layer_name] = layer_imp

    total_imp = sum(layer_totals.values())
    for layer_name, imp in layer_totals.items():
        pct = imp / total_imp * 100
        bar = "█" * int(pct / 2)
        print(f"  {layer_name:<25} {imp:.4f}  ({pct:5.1f}%) {bar}")

    # ── 3. Per-class top features ──
    print(f"\n{'='*70}")
    print(f"Per-class Top-5 Features (mean |SHAP| for each APT)")
    print(f"{'='*70}")

    per_class_top = {}
    for c_idx, c_name in enumerate(class_names):
        class_shap = np.mean(np.abs(shap_array[c_idx]), axis=0)  # (n_features,)
        top_idx = np.argsort(-class_shap)[:5]
        top_features = [(feature_names[i], float(class_shap[i])) for i in top_idx]
        per_class_top[c_name] = top_features

        print(f"\n  {c_name}:")
        for rank, (fname, val) in enumerate(top_features, 1):
            print(f"    {rank}. {fname:<35} {val:.4f}")

    # ── 4. Per-class layer contribution ──
    print(f"\n{'='*70}")
    print(f"Per-class Layer Contribution (%)")
    print(f"{'='*70}")
    print(f"  {'APT':<22} {'L1':>6} {'L2':>6} {'L3':>6} {'L4':>6}")
    print(f"  {'-'*46}")

    per_class_layers = {}
    for c_idx, c_name in enumerate(class_names):
        class_shap = np.mean(np.abs(shap_array[c_idx]), axis=0)
        layer_vals = {}
        for layer_name, (start, end) in layer_ranges.items():
            layer_vals[layer_name] = float(np.sum(class_shap[start:end]))
        total = sum(layer_vals.values())
        pcts = {k: v / total * 100 if total > 0 else 0 for k, v in layer_vals.items()}
        per_class_layers[c_name] = pcts
        print(f"  {c_name:<22} {pcts['L1 (Node Self)']:>5.1f}% {pcts['L2 (Neighborhood)']:>5.1f}% "
              f"{pcts['L3 (Overlap)']:>5.1f}% {pcts['L4 (Node2Vec)']:>5.1f}%")

    # ── 儲存結果 ──
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    results = {
        "global_top30": [
            {"rank": i + 1, "feature": feature_names[idx], "importance": float(global_importance[idx])}
            for i, idx in enumerate(ranked_idx[:30])
        ],
        "layer_importance": {k: float(v) for k, v in layer_totals.items()},
        "layer_importance_pct": {k: float(v / total_imp * 100) for k, v in layer_totals.items()},
        "per_class_top5": per_class_top,
        "per_class_layer_pct": per_class_layers,
    }

    with open(OUTPUT_DIR / "shap_analysis.json", "w") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    # 儲存 SHAP values 供視覺化
    np.savez_compressed(
        OUTPUT_DIR / "shap_values.npz",
        shap_values=shap_array.astype(np.float32),
        X=X.astype(np.float32),
        feature_names=np.array(feature_names),
        class_names=np.array(class_names),
    )

    logger.info(f"Results saved to {OUTPUT_DIR}/shap_analysis.json")
    logger.info(f"SHAP values saved to {OUTPUT_DIR}/shap_values.npz")


if __name__ == "__main__":
    main()
