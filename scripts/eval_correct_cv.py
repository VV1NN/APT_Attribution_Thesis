#!/usr/bin/env python3
"""
正確的 CV 評估：per-fold 移除 test IoC，不做 exclude_org。
跟 eval_simulated_inference.py 的差別：train 和 test 都不用 exclude_org。
"""

import json
import logging
import warnings
from collections import Counter
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
    load_kg, build_overlap_dict, load_node2vec,
    extract_l1, extract_l2, extract_l3, extract_l4,
    L1_NAMES, L2_NAMES, L4_NAMES, get_l3_names,
    MIN_IOCS, VOCAB_PATH,
)
import build_features as bf

FEATURE_DIR = Path("scripts/features")
OUTPUT_DIR = Path("scripts/results")


def balanced_weights(y):
    classes, counts = np.unique(y, return_counts=True)
    n, k = len(y), len(classes)
    w_map = {c: n / (k * cnt) for c, cnt in zip(classes, counts)}
    return np.array([w_map[yi] for yi in y])


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
    # ── Load ──
    nodes, adj, edge_by_node, has_ioc_orgs = load_kg()
    bf._node_attrs = {nid: nd["attributes"] for nid, nd in nodes.items()}

    with open(VOCAB_PATH) as f:
        vdata = json.load(f)
    vocabs = vdata["vocabs"]
    value_counts = vdata["value_counts"]
    freq_tables = vdata["freq"]

    overlap_dict_full = build_overlap_dict(has_ioc_orgs)
    n2v = load_node2vec()

    # ── Collect samples ──
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
        orgs = nd["orgs"]
        if len(orgs) != 1:
            continue
        org = list(orgs)[0]
        if org not in org_list:
            continue
        sample_nids.append(nid)
        sample_orgs.append(org)
    sample_nids = np.array(sample_nids)
    sample_orgs = np.array(sample_orgs)

    le = LabelEncoder()
    y = le.fit_transform(sample_orgs)
    logger.info(f"Samples: {len(y)}, Classes: {len(le.classes_)}")

    # ── Pre-compute L1 + L2 + L4 (不依賴 overlap_dict) ──
    logger.info("Pre-computing L1+L2+L4...")
    X_static = np.full((len(y), n_l1 + n_l2 + n_l4), np.nan, dtype=np.float32)
    for i, nid in enumerate(sample_nids):
        nd = nodes[nid]
        l1 = extract_l1(nid, nd, vocabs, value_counts, freq_tables)
        l2 = extract_l2(nid, adj, edge_by_node, nodes)
        l4 = extract_l4(nid, adj, n2v)
        X_static[i] = np.array(l1 + l2 + list(l4), dtype=np.float32)

    # ── 5-fold CV ──
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

    fold_results = []
    all_true, all_pred, all_prob = [], [], []

    for fold, (tr_idx, te_idx) in enumerate(skf.split(sample_nids, y)):
        logger.info(f"Fold {fold+1}/5 (train={len(tr_idx)}, test={len(te_idx)})")

        # 建立 fold-specific overlap_dict：移除 test IoC
        test_nid_set = set(sample_nids[te_idx])
        fold_dict = {nid: orgs for nid, orgs in overlap_dict_full.items()
                     if nid not in test_nid_set}
        logger.info(f"  fold_dict: {len(fold_dict)} (removed {len(overlap_dict_full) - len(fold_dict)} test IoCs)")

        # 計算所有樣本的 L3 特徵（train + test 都用 fold_dict，都不 exclude_org）
        X = np.full((len(y), n_total), np.nan, dtype=np.float32)
        for i in range(len(y)):
            nid = sample_nids[i]
            l3 = extract_l3(nid, adj, fold_dict, org_list, exclude_org=None)
            X[i] = np.concatenate([X_static[i, :n_l1+n_l2], l3, X_static[i, n_l1+n_l2:]])

        # Impute + Train + Eval
        imp = SimpleImputer(strategy="median")
        X_imp = imp.fit_transform(X)
        Xtr, Xte = X_imp[tr_idx], X_imp[te_idx]
        ytr, yte = y[tr_idx], y[te_idx]

        clf = XGBClassifier(
            n_estimators=500, max_depth=8, learning_rate=0.05,
            subsample=0.8, colsample_bytree=0.8, min_child_weight=3,
            eval_metric="mlogloss", random_state=42, n_jobs=-1, verbosity=0,
        )
        sw = balanced_weights(ytr)
        clf.fit(Xtr, ytr, sample_weight=sw)
        prob = clf.predict_proba(Xte)
        m = evaluate(yte, prob)
        fold_results.append(m)

        all_true.extend(yte.tolist())
        all_pred.extend(np.argmax(prob, axis=1).tolist())
        all_prob.append(prob)

        logger.info(f"  Micro={m['micro_f1']:.4f}  Macro={m['macro_f1']:.4f}  "
                     f"Top3={m['top3_acc']:.4f}  Top5={m['top5_acc']:.4f}")

    # ── Summary ──
    avg = {k: float(np.mean([r[k] for r in fold_results])) for k in fold_results[0]}
    std = {k: float(np.std([r[k] for r in fold_results])) for k in fold_results[0]}

    print(f"\n{'='*70}")
    print(f"Correct CV (per-fold test removal, no exclude_org)")
    print(f"{'='*70}")
    print(f"Micro-F1:  {avg['micro_f1']:.4f} ± {std['micro_f1']:.4f}")
    print(f"Macro-F1:  {avg['macro_f1']:.4f} ± {std['macro_f1']:.4f}")
    print(f"Top-3:     {avg['top3_acc']:.4f} ± {std['top3_acc']:.4f}")
    print(f"Top-5:     {avg['top5_acc']:.4f} ± {std['top5_acc']:.4f}")

    # Per-class F1
    all_true_arr = np.array(all_true)
    all_pred_arr = np.array(all_pred)
    print(f"\nPer-class F1:")
    report = classification_report(all_true_arr, all_pred_arr,
                                   target_names=le.classes_, output_dict=True, zero_division=0)
    for org in sorted(le.classes_, key=lambda x: -report[x]["f1-score"]):
        print(f"  {org:<22} F1={report[org]['f1-score']:.4f}  "
              f"Prec={report[org]['precision']:.4f}  Rec={report[org]['recall']:.4f}")

    # Confidence threshold = 0.3
    all_prob_arr = np.vstack(all_prob)
    # Reorder to match all_true order (folds are sequential)
    all_conf = np.max(all_prob_arr, axis=1)
    # Wait, all_prob is per-fold, need to reconstruct order
    # Actually all_true/all_pred are in fold order (te_idx per fold)
    # all_prob is list of fold probs, concat them
    all_conf_list = []
    for prob in all_prob:
        all_conf_list.extend(np.max(prob, axis=1).tolist())
    all_conf_arr = np.array(all_conf_list)

    thr = 0.3
    mask = all_conf_arr >= thr
    if mask.sum() > 0:
        micro_thr = f1_score(all_true_arr[mask], all_pred_arr[mask], average="micro")
        macro_thr = f1_score(all_true_arr[mask], all_pred_arr[mask], average="macro", zero_division=0)
        coverage = mask.mean()
        print(f"\nWith confidence threshold = {thr}:")
        print(f"  Coverage: {coverage:.1%}")
        print(f"  Micro-F1: {micro_thr:.4f}")
        print(f"  Macro-F1: {macro_thr:.4f}")

    # OilRig check
    oilrig_idx = list(le.classes_).index("OilRig")
    oilrig_pred = (all_pred_arr == oilrig_idx).sum()
    oilrig_correct = ((all_pred_arr == oilrig_idx) & (all_true_arr == oilrig_idx)).sum()
    print(f"\nOilRig: predicted {oilrig_pred} times, correct {oilrig_correct}, "
          f"precision={oilrig_correct/max(oilrig_pred,1):.3f}")

    # ── Save ──
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_DIR / "correct_cv.json", "w") as f:
        json.dump({"avg": avg, "std": std, "per_class": {
            org: {"f1": report[org]["f1-score"], "precision": report[org]["precision"],
                  "recall": report[org]["recall"]}
            for org in le.classes_
        }}, f, indent=2, ensure_ascii=False)
    logger.info(f"Saved to {OUTPUT_DIR}/correct_cv.json")


if __name__ == "__main__":
    main()
