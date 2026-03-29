#!/usr/bin/env python3
"""
Simulated Inference 評估：
  Standard CV:  L3 用 exclude_org（移除自己的 org label，但測試 IoC 本身仍在 overlap_dict）
  Simulated:    每個 fold 把整個 test set 從 overlap_dict 移除，重算 L3

如果 F1 掉幅 < 8%，模型可信。如果掉 > 25%，有嚴重 leakage。
"""

import json
import logging
import warnings
from pathlib import Path

import numpy as np
from sklearn.model_selection import StratifiedKFold
from sklearn.preprocessing import LabelEncoder
from sklearn.impute import SimpleImputer
from sklearn.metrics import f1_score
from xgboost import XGBClassifier

warnings.filterwarnings("ignore")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S")
logger = logging.getLogger(__name__)

# 從 build_features 直接匯入特徵提取函數
import sys
sys.path.insert(0, str(Path(__file__).parent))
from build_features import (
    load_kg, build_overlap_dict, load_node2vec,
    extract_l1, extract_l3, extract_l2, extract_l4,
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
    micro = f1_score(y_true, y_pred, average="micro")
    macro = f1_score(y_true, y_pred, average="macro")
    top3 = np.mean([1.0 if y_true[i] in np.argsort(y_prob[i])[-3:] else 0.0 for i in range(len(y_true))])
    top5 = np.mean([1.0 if y_true[i] in np.argsort(y_prob[i])[-5:] else 0.0 for i in range(len(y_true))])
    return {"micro_f1": micro, "macro_f1": macro, "top3_acc": top3, "top5_acc": top5}


def main():
    # ── 載入所有資料 ──
    nodes, adj, edge_by_node, has_ioc_orgs = load_kg()
    bf._node_attrs = {nid: nd["attributes"] for nid, nd in nodes.items()}

    with open(VOCAB_PATH) as f:
        vdata = json.load(f)
    vocabs = vdata["vocabs"]
    value_counts = vdata["value_counts"]
    freq_tables = vdata["freq"]

    overlap_dict_full = build_overlap_dict(has_ioc_orgs)
    n2v_embeddings = load_node2vec()

    # ── 決定 org_list 和收集 L0 IoC ──
    from collections import Counter
    org_counts = Counter()
    for nid, nd in nodes.items():
        if nd["type"] != "apt" and nd.get("depth") == 0 and nd["orgs"]:
            for org in nd["orgs"]:
                org_counts[org] += 1

    org_list = sorted([o for o, c in org_counts.items() if c >= MIN_IOCS])
    l3_names = get_l3_names(org_list)
    n_l1, n_l2, n_l3, n_l4 = len(L1_NAMES), len(L2_NAMES), len(l3_names), len(L4_NAMES)
    n_total = n_l1 + n_l2 + n_l3 + n_l4

    logger.info(f"Orgs: {len(org_list)}, Features: {n_total} ({n_l1}+{n_l2}+{n_l3}+{n_l4})")

    # 收集所有 L0 IoC
    sample_nids = []
    sample_orgs = []
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

    # ── 預計算 L1, L2, L4（不依賴 overlap_dict）──
    logger.info("Pre-computing L1 + L2 + L4 features...")
    X_l1l2l4 = np.full((len(y), n_l1 + n_l2 + n_l4), np.nan, dtype=np.float32)
    for i, nid in enumerate(sample_nids):
        nd = nodes[nid]
        l1 = extract_l1(nid, nd, vocabs, value_counts, freq_tables)
        l2 = extract_l2(nid, adj, edge_by_node, nodes)
        l4 = extract_l4(nid, adj, n2v_embeddings)
        X_l1l2l4[i] = np.array(l1 + l2 + list(l4), dtype=np.float32)

    # ── 5-fold CV ──
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

    # 方法 A: Standard CV（跟 train_classifier.py 一致，用 exclude_org）
    # 方法 B: Simulated inference（test set 從 overlap_dict 完全移除）

    results_a = []  # standard
    results_b = []  # simulated

    for fold, (tr_idx, te_idx) in enumerate(skf.split(sample_nids, y)):
        logger.info(f"Fold {fold+1}/5 (train={len(tr_idx)}, test={len(te_idx)})")

        # ── 方法 A: Standard — L3 用 exclude_org ──
        X_a = np.full((len(y), n_total), np.nan, dtype=np.float32)
        for i in range(len(y)):
            nid = sample_nids[i]
            org = sample_orgs[i]
            l3 = extract_l3(nid, adj, overlap_dict_full, org_list, exclude_org=org)
            X_a[i] = np.concatenate([X_l1l2l4[i, :n_l1+n_l2], l3, X_l1l2l4[i, n_l1+n_l2:]])

        # ── 方法 B: Simulated — test set 從 overlap_dict 移除 ──
        # 建立 reduced overlap_dict：移除所有 test IoC
        test_nid_set = set(sample_nids[te_idx])
        overlap_dict_reduced = {}
        for nid, org_set in overlap_dict_full.items():
            if nid in test_nid_set:
                continue  # 完全移除 test IoC
            overlap_dict_reduced[nid] = org_set

        X_b = np.copy(X_a)  # train set L3 跟方法 A 一樣
        # 只重算 test set 的 L3
        for i in te_idx:
            nid = sample_nids[i]
            l3_sim = extract_l3(nid, adj, overlap_dict_reduced, org_list, exclude_org=None)
            X_b[i] = np.concatenate([X_l1l2l4[i, :n_l1+n_l2], l3_sim, X_l1l2l4[i, n_l1+n_l2:]])

        # ── Impute + Train + Eval ──
        for method_name, X_full, res_list in [("Standard", X_a, results_a), ("Simulated", X_b, results_b)]:
            imp = SimpleImputer(strategy="median")
            X_imp = imp.fit_transform(X_full)

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
            res_list.append(m)

        logger.info(f"  Standard:  Micro={results_a[-1]['micro_f1']:.4f}  Macro={results_a[-1]['macro_f1']:.4f}")
        logger.info(f"  Simulated: Micro={results_b[-1]['micro_f1']:.4f}  Macro={results_b[-1]['macro_f1']:.4f}")

    # ── 彙總 ──
    def avg(res_list, key):
        return float(np.mean([r[key] for r in res_list]))

    def std(res_list, key):
        return float(np.std([r[key] for r in res_list]))

    print(f"\n{'='*80}")
    print(f"{'Method':<20} {'Micro-F1':>12} {'Macro-F1':>12} {'Top-3':>12} {'Top-5':>12}")
    print(f"{'='*80}")
    for name, res in [("Standard CV", results_a), ("Simulated Inf.", results_b)]:
        print(f"{name:<20} {avg(res,'micro_f1'):>10.4f}±{std(res,'micro_f1'):.4f} "
              f"{avg(res,'macro_f1'):>10.4f}±{std(res,'macro_f1'):.4f} "
              f"{avg(res,'top3_acc'):>10.4f}±{std(res,'top3_acc'):.4f} "
              f"{avg(res,'top5_acc'):>10.4f}±{std(res,'top5_acc'):.4f}")
    print(f"{'='*80}")

    delta_micro = avg(results_b, 'micro_f1') - avg(results_a, 'micro_f1')
    delta_macro = avg(results_b, 'macro_f1') - avg(results_a, 'macro_f1')
    print(f"\nDelta (Simulated - Standard): Micro={delta_micro:+.4f}, Macro={delta_macro:+.4f}")

    if abs(delta_micro) < 0.08:
        verdict = "✅ 掉幅 < 8%，模型可信，無顯著 leakage"
    elif abs(delta_micro) < 0.25:
        verdict = "⚠️ 掉幅 8-25%，有部分 leakage，兩個數字分別代表上下界"
    else:
        verdict = "❌ 掉幅 > 25%，嚴重 leakage，模型過度依賴 test IoC 在 KG 中的存在"
    print(f"結論: {verdict}")

    # ── 儲存 ──
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    report = {
        "standard_cv": {k: avg(results_a, k) for k in results_a[0]},
        "simulated_inference": {k: avg(results_b, k) for k in results_b[0]},
        "delta_micro_f1": delta_micro,
        "delta_macro_f1": delta_macro,
        "verdict": verdict,
    }
    with open(OUTPUT_DIR / "simulated_inference.json", "w") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    logger.info(f"Saved to {OUTPUT_DIR}/simulated_inference.json")


if __name__ == "__main__":
    main()
