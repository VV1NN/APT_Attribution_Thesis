#!/usr/bin/env python3
"""
L1-only GroupKFold CV 評估：驗證 63.8% F1 是否受 same-campaign contamination 影響。

比較：
  1. StratifiedKFold（random split）→ 原始 63.8%
  2. GroupKFold（by report）→ honest baseline

如果兩者差距 <3%，L1 baseline 是 honest 的。
如果差距 >10%，說明有 campaign-level memorization。
"""

import json
import logging
import warnings
from pathlib import Path

import numpy as np
from sklearn.model_selection import StratifiedKFold, GroupKFold
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.impute import SimpleImputer
from sklearn.metrics import f1_score, classification_report
from xgboost import XGBClassifier

warnings.filterwarnings("ignore")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S")
logger = logging.getLogger(__name__)

FEATURE_DIR = Path("scripts/features")
KG_JSON = Path("knowledge_graphs/master/merged_kg.json")


def load_data():
    data = np.load(FEATURE_DIR / "features_all.npz", allow_pickle=True)
    with open(FEATURE_DIR / "feature_names.json") as f:
        names = json.load(f)
    return data["X"], data["y"], data["node_ids"], names


def load_has_ioc_reports() -> dict[str, list[str]]:
    """從 merged_kg.json 提取 has_ioc 邊的 source_reports。"""
    logger.info("Loading source_reports from KG edges...")
    with open(KG_JSON) as f:
        data = json.load(f)

    node_reports: dict[str, list[str]] = {}
    for e in data["edges"]:
        if e.get("relationship") != "has_ioc":
            continue
        tgt = e["target"]
        reports = (e.get("attributes") or {}).get("source_reports", [])
        if reports:
            if tgt in node_reports:
                existing = set(node_reports[tgt])
                existing.update(reports)
                node_reports[tgt] = sorted(existing)
            else:
                node_reports[tgt] = sorted(reports)

    logger.info(f"  {len(node_reports)} IoCs have source_reports")
    return node_reports


def build_report_groups(sample_nids, node_reports):
    """為每個 sample 分配 report group ID。"""
    report_to_id = {}
    next_id = 0
    groups = []

    for nid in sample_nids:
        reports = node_reports.get(nid)
        if reports:
            key = reports[0]  # 用第一個 report 作為 group key
            if key not in report_to_id:
                report_to_id[key] = next_id
                next_id += 1
            groups.append(report_to_id[key])
        else:
            groups.append(next_id)
            next_id += 1

    return np.array(groups, dtype=np.int32), next_id


def balanced_weights(y):
    classes, counts = np.unique(y, return_counts=True)
    n, k = len(y), len(classes)
    w_map = {c: n / (k * cnt) for c, cnt in zip(classes, counts)}
    return np.array([w_map[yi] for yi in y])


def run_cv(X_imp, y_enc, le, splitter, label):
    """跑一次 CV，回傳 metrics。"""
    n_classes = len(le.classes_)
    all_true, all_pred, all_prob = [], [], []

    for fold, (tr, te) in enumerate(splitter):
        Xtr, Xte = X_imp[tr], X_imp[te]
        ytr, yte = y_enc[tr], y_enc[te]

        # GroupKFold 可能導致某些 class 不在 train 中
        # 跳過 test 中出現但 train 中沒有的 class 的樣本
        train_classes = set(ytr)
        valid_mask = np.array([y in train_classes for y in yte])
        if not valid_mask.all():
            n_skip = (~valid_mask).sum()
            missing = set(yte) - train_classes
            missing_names = [le.classes_[c] for c in missing]
            logger.warning(f"  Fold {fold}: skipping {n_skip} test samples "
                          f"(classes {missing_names} not in train)")
            Xte = Xte[valid_mask]
            yte = yte[valid_mask]
            if len(yte) == 0:
                continue

        # Re-encode to contiguous labels for this fold
        fold_classes = sorted(set(ytr))
        class_map = {c: i for i, c in enumerate(fold_classes)}
        inv_map = {i: c for c, i in class_map.items()}
        ytr_re = np.array([class_map[c] for c in ytr])

        clf = XGBClassifier(
            n_estimators=500, max_depth=8, learning_rate=0.05,
            subsample=0.8, colsample_bytree=0.8, min_child_weight=3,
            eval_metric="mlogloss", random_state=42, n_jobs=-1, verbosity=0,
        )
        sw = balanced_weights(ytr_re)
        clf.fit(Xtr, ytr_re, sample_weight=sw)

        prob_raw = clf.predict_proba(Xte)
        # 對齊到全 class 的 prob matrix（fold 的 re-encoded labels → 原始 labels）
        prob = np.zeros((len(yte), n_classes))
        for j in range(prob_raw.shape[1]):
            orig_class = inv_map[j]
            prob[:, orig_class] = prob_raw[:, j]

        pred = np.argmax(prob, axis=1)

        all_true.extend(yte.tolist())
        all_pred.extend(pred.tolist())
        all_prob.append(prob)

    all_true = np.array(all_true)
    all_pred = np.array(all_pred)
    all_prob = np.vstack(all_prob)

    micro = f1_score(all_true, all_pred, average="micro")
    macro = f1_score(all_true, all_pred, average="macro")
    top3 = np.mean([1.0 if all_true[i] in np.argsort(all_prob[i])[-3:] else 0.0
                     for i in range(len(all_true))])

    report = classification_report(all_true, all_pred,
                                   target_names=le.classes_,
                                   output_dict=True, zero_division=0)
    per_class = {c: round(report[c]["f1-score"], 4) for c in le.classes_}

    return {
        "micro_f1": micro, "macro_f1": macro, "top3_acc": top3,
        "per_class_f1": per_class,
    }


def main():
    # ── 載入資料 ──
    X, y, node_ids, names = load_data()
    le = LabelEncoder()
    y_enc = le.fit_transform(y)

    n_l1 = len(names["l1"])
    X_l1 = X[:, :n_l1]

    logger.info(f"Dataset: {X_l1.shape[0]} samples, {n_l1} L1 features, {len(le.classes_)} classes")

    # Impute
    imputer = SimpleImputer(strategy="median")
    X_imp = imputer.fit_transform(X_l1)

    # ── 載入 report mapping ──
    node_reports = load_has_ioc_reports()
    groups, n_groups = build_report_groups(node_ids, node_reports)
    n_unique = len(set(groups))
    logger.info(f"Report groups: {n_unique} unique groups for {len(node_ids)} samples")

    # 統計 report 分布
    from collections import Counter
    group_sizes = Counter(groups)
    size_dist = Counter(group_sizes.values())
    logger.info(f"Group size distribution:")
    for sz in sorted(size_dist.keys()):
        logger.info(f"  size={sz}: {size_dist[sz]} groups")

    # Per-org report 統計
    org_groups = {}
    for i, nid in enumerate(node_ids):
        org = y[i]
        if org not in org_groups:
            org_groups[org] = set()
        org_groups[org].add(groups[i])
    logger.info(f"\nPer-org report groups:")
    for org in sorted(org_groups.keys()):
        logger.info(f"  {org}: {len(org_groups[org])} groups, "
                     f"{sum(1 for i in range(len(y)) if y[i] == org)} IoCs")

    # ── CV 1: StratifiedKFold（baseline） ──
    logger.info(f"\n{'='*60}")
    logger.info("CV 1: StratifiedKFold (random split)")
    logger.info(f"{'='*60}")

    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    res_strat = run_cv(X_imp, y_enc, le, skf.split(X_imp, y_enc), "StratifiedKFold")

    logger.info(f"  Micro-F1: {res_strat['micro_f1']:.4f}")
    logger.info(f"  Macro-F1: {res_strat['macro_f1']:.4f}")
    logger.info(f"  Top-3:    {res_strat['top3_acc']:.4f}")

    # ── CV 2: GroupKFold（by report） ──
    logger.info(f"\n{'='*60}")
    logger.info("CV 2: GroupKFold (by report)")
    logger.info(f"{'='*60}")

    n_splits = min(5, n_unique)
    if n_unique < 5:
        logger.warning(f"Only {n_unique} unique groups, using {n_splits}-fold")

    gkf = GroupKFold(n_splits=n_splits)

    # 診斷：每個 fold 的 class 分布
    logger.info("\n  GroupKFold 各 fold 的 class 分布:")
    for fold, (tr, te) in enumerate(gkf.split(X_imp, y_enc, groups)):
        tr_classes = set(y_enc[tr])
        te_classes = set(y_enc[te])
        missing_in_train = te_classes - tr_classes
        te_orgs = Counter(y[te])
        logger.info(f"  Fold {fold}: train={len(tr)}, test={len(te)}, "
                     f"train_classes={len(tr_classes)}, test_classes={len(te_classes)}")
        if missing_in_train:
            missing_names = [le.classes_[c] for c in missing_in_train]
            logger.warning(f"    ⚠️ test has classes not in train: {missing_names}")
        # 顯示 test 中較大的 org
        top3_te = te_orgs.most_common(3)
        logger.info(f"    top test orgs: {top3_te}")

    # 重新跑 GroupKFold（generator 已消耗，要重建）
    gkf = GroupKFold(n_splits=n_splits)
    res_group = run_cv(X_imp, y_enc, le, gkf.split(X_imp, y_enc, groups), "GroupKFold")

    # ── CV 3: GroupKFold，只評估有 ≥5 groups 的 org ──
    logger.info(f"\n{'='*60}")
    logger.info("CV 3: GroupKFold (filtered: orgs with ≥5 report groups)")
    logger.info(f"{'='*60}")

    # 找出 ≥5 groups 的 org
    fair_orgs = {org for org, gs in org_groups.items() if len(gs) >= 5}
    logger.info(f"  Fair orgs (≥5 groups): {sorted(fair_orgs)}")
    fair_mask = np.array([y[i] in fair_orgs for i in range(len(y))])
    X_fair = X_imp[fair_mask]
    y_fair = y_enc[fair_mask]
    groups_fair = groups[fair_mask]
    node_ids_fair = node_ids[fair_mask] if isinstance(node_ids, np.ndarray) else \
                     np.array(node_ids)[fair_mask]

    le_fair = LabelEncoder()
    y_fair_re = le_fair.fit_transform(y[fair_mask])
    n_fair_groups = len(set(groups_fair))
    logger.info(f"  {len(X_fair)} samples, {len(le_fair.classes_)} classes, {n_fair_groups} groups")

    # StratifiedKFold on fair subset
    skf2 = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    res_fair_strat = run_cv(X_fair, y_fair_re, le_fair,
                            skf2.split(X_fair, y_fair_re), "Stratified-Fair")
    logger.info(f"  Stratified: Micro-F1={res_fair_strat['micro_f1']:.4f}")

    # GroupKFold on fair subset
    gkf2 = GroupKFold(n_splits=5)
    res_fair_group = run_cv(X_fair, y_fair_re, le_fair,
                            gkf2.split(X_fair, y_fair_re, groups_fair), "GroupKFold-Fair")
    logger.info(f"  GroupKFold: Micro-F1={res_fair_group['micro_f1']:.4f}")

    logger.info(f"  Micro-F1: {res_group['micro_f1']:.4f}")
    logger.info(f"  Macro-F1: {res_group['macro_f1']:.4f}")
    logger.info(f"  Top-3:    {res_group['top3_acc']:.4f}")

    # ── 比較 ──
    print(f"\n{'='*70}")
    print("L1-only XGBoost: StratifiedKFold vs GroupKFold (ALL 15 orgs)")
    print(f"{'='*70}")
    print(f"{'Metric':<15} {'Stratified':>12} {'GroupKFold':>12} {'Δ':>10}")
    print(f"{'-'*15} {'-'*12} {'-'*12} {'-'*10}")
    for metric in ["micro_f1", "macro_f1", "top3_acc"]:
        s = res_strat[metric]
        g = res_group[metric]
        delta = g - s
        print(f"{metric:<15} {s:>11.4f}  {g:>11.4f}  {delta:>+9.4f}")

    print(f"\n{'='*70}")
    print(f"L1-only XGBoost: Fair Subset (orgs with ≥5 report groups)")
    print(f"{'='*70}")
    print(f"{'Metric':<15} {'Stratified':>12} {'GroupKFold':>12} {'Δ':>10}")
    print(f"{'-'*15} {'-'*12} {'-'*12} {'-'*10}")
    for metric in ["micro_f1", "macro_f1", "top3_acc"]:
        s = res_fair_strat[metric]
        g = res_fair_group[metric]
        delta = g - s
        print(f"{metric:<15} {s:>11.4f}  {g:>11.4f}  {delta:>+9.4f}")

    delta_all = res_group["micro_f1"] - res_strat["micro_f1"]
    delta_fair = res_fair_group["micro_f1"] - res_fair_strat["micro_f1"]
    print(f"\n判定:")
    print(f"  全體 15 org: Δ = {delta_all:+.1%}")
    print(f"  Fair subset (≥5 groups): Δ = {delta_fair:+.1%}")
    if abs(delta_fair) < 0.03:
        print(f"  ✅ Fair subset 差距 <3%: L1 baseline honest")
    elif abs(delta_fair) < 0.10:
        print(f"  ⚠️ Fair subset 差距 {abs(delta_fair):.1%}: 輕微 campaign memorization")
    elif abs(delta_fair) < 0.20:
        print(f"  ⚠️ Fair subset 差距 {abs(delta_fair):.1%}: 中等 campaign memorization")
    else:
        print(f"  ❌ Fair subset 差距 {abs(delta_fair):.1%}: 嚴重 campaign memorization")

    # Per-class 比較
    print(f"\nPer-class F1:")
    print(f"  {'Org':<25} {'Stratified':>10} {'GroupKFold':>10} {'Δ':>8}")
    print(f"  {'-'*25} {'-'*10} {'-'*10} {'-'*8}")
    for org in sorted(le.classes_):
        s = res_strat["per_class_f1"][org]
        g = res_group["per_class_f1"][org]
        d = g - s
        flag = " ⚠️" if d < -0.10 else ""
        print(f"  {org:<25} {s:>9.4f}  {g:>9.4f}  {d:>+7.4f}{flag}")

    # Fair subset per-class
    print(f"\nFair Subset Per-class F1:")
    print(f"  {'Org':<25} {'Stratified':>10} {'GroupKFold':>10} {'Δ':>8}")
    print(f"  {'-'*25} {'-'*10} {'-'*10} {'-'*8}")
    for org in sorted(le_fair.classes_):
        s = res_fair_strat["per_class_f1"].get(org, 0)
        g = res_fair_group["per_class_f1"].get(org, 0)
        d = g - s
        flag = " ⚠️" if d < -0.10 else ""
        print(f"  {org:<25} {s:>9.4f}  {g:>9.4f}  {d:>+7.4f}{flag}")

    # 儲存
    output = {
        "stratified_kfold": res_strat,
        "group_kfold": res_group,
        "delta_micro_f1_all": float(delta_all),
        "fair_subset": {
            "stratified_kfold": res_fair_strat,
            "group_kfold": res_fair_group,
            "delta_micro_f1": float(delta_fair),
            "fair_orgs": sorted(fair_orgs),
        },
        "n_samples": int(X_l1.shape[0]),
        "n_features": int(n_l1),
        "n_groups": int(n_unique),
    }
    out_path = Path("scripts/results/eval_groupkfold_l1.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    logger.info(f"\nSaved to {out_path}")


if __name__ == "__main__":
    main()
