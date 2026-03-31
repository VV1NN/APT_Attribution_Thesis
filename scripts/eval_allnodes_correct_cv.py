#!/usr/bin/env python3
"""
ALL-nodes dict + per-fold test removal + no exclude_org。
最接近真實推論的 CV 設定。
"""

import json, logging, warnings, math
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
from sklearn.model_selection import StratifiedKFold
from sklearn.preprocessing import LabelEncoder
from sklearn.impute import SimpleImputer
from sklearn.metrics import f1_score, classification_report
from xgboost import XGBClassifier

warnings.filterwarnings("ignore")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S")
logger = logging.getLogger(__name__)

import sys
sys.path.insert(0, str(Path(__file__).parent))
from build_features import (
    load_kg, load_node2vec,
    extract_l1, extract_l2, extract_l3, extract_l4,
    L1_NAMES, L2_NAMES, L4_NAMES, get_l3_names,
    MIN_IOCS, VOCAB_PATH,
)
import build_features as bf

OUTPUT_DIR = Path("scripts/results")


def build_allnodes_overlap_dict(nodes):
    """ALL-nodes: 所有帶 org label 的非 apt 節點。"""
    return {nid: nd["orgs"] for nid, nd in nodes.items()
            if nd["type"] != "apt" and nd["orgs"]}


def balanced_weights(y):
    classes, counts = np.unique(y, return_counts=True)
    n, k = len(y), len(classes)
    return np.array([n / (k * cnt) for cnt in counts])[y]


def evaluate(y_true, y_prob):
    y_pred = np.argmax(y_prob, axis=1)
    return {
        "micro_f1": float(f1_score(y_true, y_pred, average="micro")),
        "macro_f1": float(f1_score(y_true, y_pred, average="macro", zero_division=0)),
        "top3_acc": float(np.mean([1.0 if y_true[i] in np.argsort(y_prob[i])[-3:] else 0.0
                                    for i in range(len(y_true))])),
        "top5_acc": float(np.mean([1.0 if y_true[i] in np.argsort(y_prob[i])[-5:] else 0.0
                                    for i in range(len(y_true))])),
    }


def main():
    nodes, adj, edge_by_node, has_ioc_orgs = load_kg()
    bf._node_attrs = {nid: nd["attributes"] for nid, nd in nodes.items()}

    with open(VOCAB_PATH) as f:
        vdata = json.load(f)
    vocabs, value_counts, freq_tables = vdata["vocabs"], vdata["value_counts"], vdata["freq"]

    # ALL-nodes overlap dict
    overlap_dict_full = build_allnodes_overlap_dict(nodes)
    logger.info(f"ALL-nodes overlap dict: {len(overlap_dict_full)} nodes")

    # 設定 org-size normalization 用的全域變數
    bf._org_sizes = Counter()
    for nid, orgs in overlap_dict_full.items():
        for org in orgs:
            bf._org_sizes[org] += 1

    n2v = load_node2vec()

    # Collect samples (L0 IoCs only)
    org_counts = Counter()
    for nid, nd in nodes.items():
        if nd["type"] != "apt" and nd.get("depth") == 0 and nd["orgs"]:
            for org in nd["orgs"]:
                org_counts[org] += 1
    org_list = sorted([o for o, c in org_counts.items() if c >= MIN_IOCS])
    l3_names = get_l3_names(org_list)
    n_l1, n_l2, n_l3, n_l4 = len(L1_NAMES), len(L2_NAMES), len(l3_names), len(L4_NAMES)
    n_total = n_l1 + n_l2 + n_l3 + n_l4

    sample_nids, sample_orgs = [], []
    for nid, nd in nodes.items():
        if nd["type"] == "apt" or nd.get("depth") != 0:
            continue
        if len(nd["orgs"]) != 1:
            continue
        org = list(nd["orgs"])[0]
        if org not in org_list:
            continue
        sample_nids.append(nid)
        sample_orgs.append(org)
    sample_nids = np.array(sample_nids)
    sample_orgs = np.array(sample_orgs)

    le = LabelEncoder()
    y = le.fit_transform(sample_orgs)
    logger.info(f"Samples: {len(y)}, Classes: {len(le.classes_)}")

    # Pre-compute L1+L2+L4
    logger.info("Pre-computing L1+L2+L4...")
    X_static = np.full((len(y), n_l1 + n_l2 + n_l4), np.nan, dtype=np.float32)
    for i, nid in enumerate(sample_nids):
        nd = nodes[nid]
        l1 = extract_l1(nid, nd, vocabs, value_counts, freq_tables)
        l2 = extract_l2(nid, adj, edge_by_node, nodes)
        l4 = extract_l4(nid, adj, n2v)
        X_static[i] = np.array(l1 + l2 + list(l4), dtype=np.float32)

    # 5-fold CV
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    fold_results = []
    all_true, all_pred, all_conf = [], [], []

    for fold, (tr_idx, te_idx) in enumerate(skf.split(sample_nids, y)):
        logger.info(f"Fold {fold+1}/5 (train={len(tr_idx)}, test={len(te_idx)})")

        # Per-fold dict: remove test IoCs only
        test_set = set(sample_nids[te_idx])
        fold_dict = {nid: orgs for nid, orgs in overlap_dict_full.items()
                     if nid not in test_set}
        logger.info(f"  fold_dict: {len(fold_dict)} (full={len(overlap_dict_full)}, removed={len(overlap_dict_full)-len(fold_dict)})")

        # Compute L3 for ALL samples: no exclude_org
        X = np.full((len(y), n_total), np.nan, dtype=np.float32)
        for i in range(len(y)):
            nid = sample_nids[i]
            l3 = extract_l3(nid, adj, fold_dict, org_list, exclude_org=None)
            X[i] = np.concatenate([X_static[i, :n_l1+n_l2], l3, X_static[i, n_l1+n_l2:]])

        imp = SimpleImputer(strategy="median")
        X_imp = imp.fit_transform(X)
        Xtr, Xte = X_imp[tr_idx], X_imp[te_idx]
        ytr, yte = y[tr_idx], y[te_idx]

        clf = XGBClassifier(
            n_estimators=500, max_depth=8, learning_rate=0.05,
            subsample=0.8, colsample_bytree=0.8, min_child_weight=3,
            eval_metric="mlogloss", random_state=42, n_jobs=-1, verbosity=0,
        )
        clf.fit(Xtr, ytr, sample_weight=balanced_weights(ytr))
        prob = clf.predict_proba(Xte)
        m = evaluate(yte, prob)
        fold_results.append(m)

        all_true.extend(yte.tolist())
        all_pred.extend(np.argmax(prob, axis=1).tolist())
        all_conf.extend(np.max(prob, axis=1).tolist())

        logger.info(f"  Micro={m['micro_f1']:.4f}  Macro={m['macro_f1']:.4f}  "
                     f"Top3={m['top3_acc']:.4f}  Top5={m['top5_acc']:.4f}")

    # Summary
    avg = {k: float(np.mean([r[k] for r in fold_results])) for k in fold_results[0]}
    std = {k: float(np.std([r[k] for r in fold_results])) for k in fold_results[0]}
    all_true_arr, all_pred_arr, all_conf_arr = np.array(all_true), np.array(all_pred), np.array(all_conf)

    print(f"\n{'='*70}")
    print(f"ALL-nodes + per-fold test removal + no exclude_org")
    print(f"{'='*70}")
    print(f"Micro-F1:  {avg['micro_f1']:.4f} ± {std['micro_f1']:.4f}")
    print(f"Macro-F1:  {avg['macro_f1']:.4f} ± {std['macro_f1']:.4f}")
    print(f"Top-3:     {avg['top3_acc']:.4f} ± {std['top3_acc']:.4f}")
    print(f"Top-5:     {avg['top5_acc']:.4f} ± {std['top5_acc']:.4f}")

    # Per-class
    report = classification_report(all_true_arr, all_pred_arr,
                                   target_names=le.classes_, output_dict=True, zero_division=0)
    print(f"\nPer-class F1:")
    for org in sorted(le.classes_, key=lambda x: -report[x]["f1-score"]):
        print(f"  {org:<22} F1={report[org]['f1-score']:.4f}  "
              f"Prec={report[org]['precision']:.4f}  Rec={report[org]['recall']:.4f}")

    # Confidence threshold sweep
    print(f"\nConfidence threshold sweep:")
    print(f"{'Threshold':>10} {'Coverage':>10} {'Micro-F1':>10} {'Macro-F1':>10}")
    for thr in [0.15, 0.20, 0.25, 0.30, 0.40, 0.50, 0.70]:
        mask = all_conf_arr >= thr
        if mask.sum() == 0:
            continue
        mi = f1_score(all_true_arr[mask], all_pred_arr[mask], average="micro")
        ma = f1_score(all_true_arr[mask], all_pred_arr[mask], average="macro", zero_division=0)
        print(f"{thr:>10.2f} {mask.mean():>10.1%} {mi:>10.4f} {ma:>10.4f}")

    # OilRig
    oi = list(le.classes_).index("OilRig")
    oi_pred = (all_pred_arr == oi).sum()
    oi_correct = ((all_pred_arr == oi) & (all_true_arr == oi)).sum()
    print(f"\nOilRig: predicted={oi_pred}, correct={oi_correct}, precision={oi_correct/max(oi_pred,1):.3f}")

    # Save
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_DIR / "allnodes_correct_cv.json", "w") as f:
        json.dump({"avg": avg, "std": std}, f, indent=2)
    logger.info(f"Saved to {OUTPUT_DIR}/allnodes_correct_cv.json")


if __name__ == "__main__":
    main()
