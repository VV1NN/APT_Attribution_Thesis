#!/usr/bin/env python3
"""
GroupKFold 全層消融實驗（honest evaluation）。

- L3 每 fold 重算（移除 test IoC 的 overlap）
- L1/L2/L4 靜態（不依賴 org label）
- GroupKFold by source report（防止 same-campaign contamination）
"""

import json
import logging
import math
import sys
import argparse
import warnings
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
from sklearn.model_selection import StratifiedKFold, GroupKFold
from sklearn.preprocessing import LabelEncoder
from sklearn.impute import SimpleImputer
from sklearn.metrics import f1_score, classification_report
from xgboost import XGBClassifier

warnings.filterwarnings("ignore")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S")
logger = logging.getLogger(__name__)

FEATURE_DIR = Path("scripts/features")
KG_JSON = Path("knowledge_graphs/master/merged_kg.json")

sys.path.insert(0, str(Path(__file__).parent))
from build_features import (
    load_kg, build_overlap_dict, extract_l3, get_l3_names,
    _node_attrs, _org_sizes,
)
import build_features
from split_utils import build_report_connected_groups, assert_no_report_leak


def load_static_features():
    """載入預計算的特徵矩陣（L1/L2/L3/L4 全部），以及 node_ids。"""
    data = np.load(FEATURE_DIR / "features_all.npz", allow_pickle=True)
    with open(FEATURE_DIR / "feature_names.json") as f:
        names = json.load(f)
    return data["X"], data["y"], data["node_ids"], names


def load_has_ioc_reports() -> dict[str, list[str]]:
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


def balanced_weights(y):
    classes, counts = np.unique(y, return_counts=True)
    n, k = len(y), len(classes)
    w_map = {c: n / (k * cnt) for c, cnt in zip(classes, counts)}
    return np.array([w_map[yi] for yi in y])


def recompute_l3_for_fold(sample_nids, test_idx, adj, overlap_dict_full, org_list):
    """
    移除 test IoC 後重算所有樣本的 L3 特徵。
    - test IoC 從 overlap_dict 中移除
    - 所有樣本（train + test）重算 L3（test 不用 exclude_org）
    """
    test_set = set(sample_nids[i] for i in test_idx)

    # 移除 test IoC 的 overlap
    fold_dict = {
        nid: orgs for nid, orgs in overlap_dict_full.items()
        if nid not in test_set
    }

    n_features = 7 + len(org_list)
    L3 = np.zeros((len(sample_nids), n_features), dtype=np.float32)

    for i, nid in enumerate(sample_nids):
        # test samples: no exclude_org (simulate real inference)
        # train samples: exclude own org to prevent trivial self-match
        L3[i] = extract_l3(nid, adj, fold_dict, org_list, exclude_org=None)

    return L3


def run_experiment(X_static, l3_col_start, l3_col_end, y_enc, le, sample_nids,
                   splitter_fn, adj, overlap_dict, org_list, feat_idx, exp_name,
                   needs_l3_recompute=False, groups=None, node_reports=None,
                   check_report_leak=False, l4_mode="transductive"):
    """
    跑一個實驗配置。
    如果 feat_idx 包含 L3 columns 且 needs_l3_recompute=True，
    則每 fold 重算 L3。
    """
    n_classes = len(le.classes_)
    all_true, all_pred, all_prob = [], [], []

    # 判斷 feat_idx 是否包含 L3
    l3_in_feat = any(l3_col_start <= i < l3_col_end for i in feat_idx)
    non_l3_idx = [i for i in feat_idx if i < l3_col_start or i >= l3_col_end]
    l3_local_idx = [i for i in feat_idx if l3_col_start <= i < l3_col_end]

    splits = list(splitter_fn(groups))

    for fold, (tr, te) in enumerate(splits):
        if check_report_leak:
            leak_stats = assert_no_report_leak(tr, te, sample_nids, node_reports or {})
            logger.info(
                f"  {exp_name} Fold {fold}: leak check PASS "
                f"(train_reports={leak_stats['train_report_count']}, "
                f"test_reports={leak_stats['test_report_count']})"
            )

        # 建立本 fold 的特徵矩陣
        if l3_in_feat and needs_l3_recompute:
            # 重算 L3
            L3_fold = recompute_l3_for_fold(sample_nids, te, adj, overlap_dict, org_list)
            # 組裝：非 L3 特徵 + 重算的 L3 特徵
            X_non_l3 = X_static[:, non_l3_idx] if non_l3_idx else np.empty((len(y_enc), 0))
            # L3 的相對 index
            l3_relative = [i - l3_col_start for i in l3_local_idx]
            X_l3 = L3_fold[:, l3_relative]
            X_fold = np.hstack([X_non_l3, X_l3])
        else:
            X_fold = X_static[:, feat_idx]

        # Impute per fold
        imputer = SimpleImputer(strategy="median")
        X_fold_imp = imputer.fit_transform(X_fold)

        Xtr, Xte = X_fold_imp[tr], X_fold_imp[te]
        ytr, yte = y_enc[tr], y_enc[te]

        # 跳過 test 中 train 沒有的 class
        train_classes = set(ytr)
        valid_mask = np.array([y in train_classes for y in yte])
        if not valid_mask.all():
            n_skip = (~valid_mask).sum()
            missing_names = [le.classes_[c] for c in set(yte) - train_classes]
            logger.warning(f"  {exp_name} Fold {fold}: skip {n_skip} samples ({missing_names})")
            Xte = Xte[valid_mask]
            yte = yte[valid_mask]
            if len(yte) == 0:
                continue

        # Re-encode to contiguous labels
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
    all_prob_arr = np.vstack(all_prob)

    micro = f1_score(all_true, all_pred, average="micro")
    macro = f1_score(all_true, all_pred, average="macro")
    top3 = np.mean([1.0 if all_true[i] in np.argsort(all_prob_arr[i])[-3:] else 0.0
                     for i in range(len(all_true))])
    top5 = np.mean([1.0 if all_true[i] in np.argsort(all_prob_arr[i])[-5:] else 0.0
                     for i in range(len(all_true))])

    report = classification_report(all_true, all_pred,
                                   target_names=le.classes_,
                                   output_dict=True, zero_division=0)
    per_class = {c: round(report[c]["f1-score"], 4) for c in le.classes_}

    return {
        "micro_f1": round(micro, 4),
        "macro_f1": round(macro, 4),
        "top3_acc": round(top3, 4),
        "top5_acc": round(top5, 4),
        "per_class_f1": per_class,
        "n_evaluated": len(all_true),
        "n_features": int(len(feat_idx)),
        "l4_mode": l4_mode,
    }


def parse_args():
    parser = argparse.ArgumentParser(description="GroupKFold ablation with optional L4 mode")
    parser.add_argument(
        "--l4-mode",
        choices=["off", "transductive"],
        default="off",
        help="off=drop L4 from features (honest main setting); transductive=use original L4",
    )
    return parser.parse_args()


def apply_l4_mode(feat_idx, l4_idx, l4_mode):
    if l4_mode == "transductive":
        return feat_idx
    l4_set = set(l4_idx)
    return [i for i in feat_idx if i not in l4_set]


def main():
    args = parse_args()
    l4_mode = args.l4_mode

    # ── 載入靜態特徵 ──
    X, y, node_ids, names = load_static_features()
    le = LabelEncoder()
    y_enc = le.fit_transform(y)

    n_l1 = len(names["l1"])
    n_l2 = len(names.get("l2", []))
    n_l3 = len(names["l3"])
    n_l4 = len(names.get("l4", []))
    total_feat = n_l1 + n_l2 + n_l3 + n_l4

    l1_idx = list(range(n_l1))
    l2_start = n_l1
    l2_idx = list(range(l2_start, l2_start + n_l2))
    l3_start = l2_start + n_l2
    l3_end = l3_start + n_l3
    l3_idx = list(range(l3_start, l3_end))
    l4_start = l3_end
    l4_idx = list(range(l4_start, l4_start + n_l4))

    logger.info(f"Dataset: {X.shape[0]} samples, {total_feat} features "
                f"(L1={n_l1}, L2={n_l2}, L3={n_l3}, L4={n_l4}), {len(le.classes_)} classes")
    logger.info(f"L4 mode: {l4_mode}")

    # ── 載入 KG（for per-fold L3 recomputation）──
    logger.info("Loading KG for L3 recomputation...")
    nodes, adj, edge_by_node, has_ioc_orgs = load_kg()
    build_features._node_attrs = {nid: nd["attributes"] for nid, nd in nodes.items()}
    overlap_dict = build_overlap_dict(has_ioc_orgs)
    org_list = names.get("org_list", sorted(le.classes_))

    # Compute org sizes for L3
    build_features._org_sizes = Counter()
    for nid, orgs in overlap_dict.items():
        for org in orgs:
            build_features._org_sizes[org] += 1

    # ── 載入 report groups ──
    node_reports = load_has_ioc_reports()
    groups = build_report_connected_groups(node_ids, node_reports)
    n_groups = len(set(groups))
    logger.info(f"Report-connected groups: {n_groups} unique groups")

    sample_nids = list(node_ids) if not isinstance(node_ids, list) else node_ids

    # ── 定義實驗 ──
    experiments = [
        ("L1",           l1_idx,                             False),
        ("L1+L2",        l1_idx + l2_idx,                    False),
        ("L1+L2+L3",     l1_idx + l2_idx + l3_idx,           True),
        ("L1+L2+L3+L4",  l1_idx + l2_idx + l3_idx + l4_idx,  True),
        ("L1+L3",        l1_idx + l3_idx,                    True),
        ("L3",           l3_idx,                             True),
    ]

    # ── 跑兩種 CV ──
    all_results = {}

    for cv_name, splitter_factory, use_groups in [
        ("StratifiedKFold", lambda g: StratifiedKFold(5, shuffle=True, random_state=42).split(X, y_enc), False),
        ("GroupKFold", lambda g: GroupKFold(5).split(X, y_enc, g), True),
    ]:
        logger.info(f"\n{'='*70}")
        logger.info(f"CV: {cv_name}")
        logger.info(f"{'='*70}")

        cv_results = {}
        for exp_name, base_feat_idx, needs_l3 in experiments:
            feat_idx = apply_l4_mode(base_feat_idx, l4_idx, l4_mode)
            logger.info(f"  {exp_name} ({len(feat_idx)}d, l4_mode={l4_mode})...")

            g = groups if use_groups else None
            res = run_experiment(
                X, l3_start, l3_end, y_enc, le, sample_nids,
                splitter_fn=lambda g, sf=splitter_factory: sf(g),
                adj=adj, overlap_dict=overlap_dict, org_list=org_list,
                feat_idx=feat_idx, exp_name=f"{cv_name}/{exp_name}",
                needs_l3_recompute=(needs_l3 and cv_name == "GroupKFold"),
                groups=g, node_reports=node_reports,
                check_report_leak=(cv_name == "GroupKFold"),
                l4_mode=l4_mode,
            )
            cv_results[exp_name] = res
            logger.info(f"    Micro-F1={res['micro_f1']:.4f}, Macro-F1={res['macro_f1']:.4f}, "
                        f"Top-3={res['top3_acc']:.4f}")

        all_results[cv_name] = cv_results

    # ── 結果表格 ──
    print(f"\n{'='*90}")
    print(f"Ablation: StratifiedKFold vs GroupKFold (XGBoost) | l4_mode={l4_mode}")
    print(f"{'='*90}")
    print(f"{'Experiment':<16} │ {'Stratified':>10} │ {'GroupKFold':>10} │ {'Δ':>8} │ {'Top3-S':>7} {'Top3-G':>7}")
    print(f"{'-'*16} │ {'-'*10} │ {'-'*10} │ {'-'*8} │ {'-'*7} {'-'*7}")

    strat = all_results["StratifiedKFold"]
    group = all_results["GroupKFold"]

    for exp_name, _, _ in experiments:
        s = strat[exp_name]["micro_f1"]
        g = group[exp_name]["micro_f1"]
        d = g - s
        t3s = strat[exp_name]["top3_acc"]
        t3g = group[exp_name]["top3_acc"]
        print(f"{exp_name:<16} │ {s:>9.4f}  │ {g:>9.4f}  │ {d:>+7.4f} │ {t3s:>6.4f} {t3g:>6.4f}")

    # Marginal contributions
    print(f"\n{'='*90}")
    print("Marginal Contributions (GroupKFold Micro-F1)")
    print(f"{'='*90}")
    marginal_pairs = [
        ("L1", "L1+L2", "+L2"),
        ("L1+L2", "L1+L2+L3", "+L3"),
        ("L1+L2+L3", "L1+L2+L3+L4", "+L4"),
        ("L1", "L1+L3", "+L3 (skip L2)"),
    ]
    for base, full, label in marginal_pairs:
        b = group[base]["micro_f1"]
        f_val = group[full]["micro_f1"]
        d = f_val - b
        print(f"  {base:<16} → {full:<16}: {b:.4f} → {f_val:.4f} ({d:+.4f}) {label}")

    # Per-class for best config
    print(f"\n{'='*90}")
    print(f"Per-class F1: GroupKFold L1+L2+L3+L4 | l4_mode={l4_mode}")
    print(f"{'='*90}")
    best_s = strat.get("L1+L2+L3+L4", strat["L1+L2+L3"])
    best_g = group.get("L1+L2+L3+L4", group["L1+L2+L3"])
    print(f"  {'Org':<25} {'Strat':>7} {'Group':>7} {'Δ':>7}")
    print(f"  {'-'*25} {'-'*7} {'-'*7} {'-'*7}")
    for org in sorted(le.classes_):
        s = best_s["per_class_f1"].get(org, 0)
        g = best_g["per_class_f1"].get(org, 0)
        d = g - s
        flag = " ⚠️" if d < -0.15 else ""
        print(f"  {org:<25} {s:>6.4f} {g:>6.4f} {d:>+6.4f}{flag}")

    # ── 儲存 ──
    out_path = Path("scripts/results/eval_groupkfold_ablation.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "metadata": {
            "l4_mode": l4_mode,
            "notes": "off=drop L4 features; transductive=use original L4 features",
        },
        "results": all_results,
    }
    with open(out_path, "w") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
    logger.info(f"\nSaved to {out_path}")


if __name__ == "__main__":
    main()
