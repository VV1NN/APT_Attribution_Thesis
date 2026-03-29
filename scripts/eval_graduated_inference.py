#!/usr/bin/env python3
"""
漸進式 Simulated Inference 實驗：
模擬不同 KG 完整度下的歸因效能，產生 degradation curve。

Level A: Standard CV（exclude_org，IoC 在 KG 中）→ 上界
Level B: 移除 test IoC 本身（之前的 simulated inference）
Level C: 移除 test IoC + 其獨佔 L1 鄰居（IoC 從未被 VT 查過的情境）
Level D: Level B + 額外移除 25% train IoC 的 overlap（KG 75% 完整度）
Level E: Level B + 額外移除 50% train IoC 的 overlap（KG 50% 完整度）
"""

import json
import logging
import warnings
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
    load_kg, build_overlap_dict, load_node2vec,
    extract_l1, extract_l2, extract_l3, extract_l4,
    L1_NAMES, L2_NAMES, L4_NAMES, get_l3_names,
    MIN_IOCS, VOCAB_PATH,
)
import build_features as bf

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
        "macro_f1": float(f1_score(y_true, y_pred, average="macro")),
        "top3_acc": float(np.mean([1.0 if y_true[i] in np.argsort(y_prob[i])[-3:] else 0.0
                                    for i in range(len(y_true))])),
        "top5_acc": float(np.mean([1.0 if y_true[i] in np.argsort(y_prob[i])[-5:] else 0.0
                                    for i in range(len(y_true))])),
    }


def find_exclusive_l1_neighbors(test_nids, adj, nodes, all_l0_nids):
    """找出只被 test IoC 連到的 L1 鄰居（即移除 test IoC 後就沒有 L0 IoC 連到它們）。"""
    test_set = set(test_nids)
    train_l0 = set(all_l0_nids) - test_set

    exclusive = set()
    for nid in test_nids:
        for nb in adj.get(nid, set()):
            nd = nodes.get(nb)
            if not nd or nd.get("depth") != 1:
                continue
            # 檢查此 L1 鄰居是否只被 test IoC 連到
            nb_l0_parents = set()
            for nb2 in adj.get(nb, set()):
                nd2 = nodes.get(nb2)
                if nd2 and nd2.get("depth") == 0:
                    nb_l0_parents.add(nb2)
            if nb_l0_parents.issubset(test_set):
                exclusive.add(nb)
    return exclusive


def build_reduced_overlap_dict(overlap_dict_full, remove_nids):
    """從 overlap_dict 中移除指定節點。"""
    return {nid: orgs for nid, orgs in overlap_dict_full.items() if nid not in remove_nids}


def main():
    # ── 載入 ──
    nodes, adj, edge_by_node, has_ioc_orgs = load_kg()
    bf._node_attrs = {nid: nd["attributes"] for nid, nd in nodes.items()}

    with open(VOCAB_PATH) as f:
        vdata = json.load(f)
    vocabs = vdata["vocabs"]
    value_counts = vdata["value_counts"]
    freq_tables = vdata["freq"]

    overlap_dict_full = build_overlap_dict(has_ioc_orgs)
    n2v = load_node2vec()

    # ── 收集 L0 IoC ──
    org_counts = Counter()
    for nid, nd in nodes.items():
        if nd["type"] != "apt" and nd.get("depth") == 0 and nd["orgs"]:
            for org in nd["orgs"]:
                org_counts[org] += 1
    org_list = sorted([o for o, c in org_counts.items() if c >= MIN_IOCS])
    l3_names = get_l3_names(org_list)
    n_l1, n_l2, n_l3, n_l4 = len(L1_NAMES), len(L2_NAMES), len(l3_names), len(L4_NAMES)

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
    all_l0_nids = set(sample_nids)

    le = LabelEncoder()
    y = le.fit_transform(sample_orgs)
    logger.info(f"Samples: {len(y)}, Classes: {len(le.classes_)}, Orgs: {len(org_list)}")

    # ── 預計算 L1 + L2 + L4（不依賴 overlap_dict）──
    logger.info("Pre-computing L1+L2+L4 features...")
    X_static = np.full((len(y), n_l1 + n_l2 + n_l4), np.nan, dtype=np.float32)
    for i, nid in enumerate(sample_nids):
        nd = nodes[nid]
        l1 = extract_l1(nid, nd, vocabs, value_counts, freq_tables)
        l2 = extract_l2(nid, adj, edge_by_node, nodes)
        l4 = extract_l4(nid, adj, n2v)
        X_static[i] = np.array(l1 + l2 + list(l4), dtype=np.float32)
    logger.info(f"Static features: {X_static.shape}")

    # ── 定義實驗等級 ──
    levels = {
        "A_standard":        {"desc": "Standard CV (exclude_org)", "remove_test": False, "remove_exclusive_l1": False, "train_remove_pct": 0.0},
        "B_remove_test":     {"desc": "Remove test IoCs", "remove_test": True, "remove_exclusive_l1": False, "train_remove_pct": 0.0},
        "C_remove_test+L1":  {"desc": "Remove test + exclusive L1", "remove_test": True, "remove_exclusive_l1": True, "train_remove_pct": 0.0},
        "D_kg75":            {"desc": "Remove test + 25% train overlap", "remove_test": True, "remove_exclusive_l1": False, "train_remove_pct": 0.25},
        "E_kg50":            {"desc": "Remove test + 50% train overlap", "remove_test": True, "remove_exclusive_l1": False, "train_remove_pct": 0.50},
    }

    # ── 5-fold CV ──
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    all_results = {lv: [] for lv in levels}

    for fold, (tr_idx, te_idx) in enumerate(skf.split(sample_nids, y)):
        logger.info(f"\nFold {fold+1}/5 (train={len(tr_idx)}, test={len(te_idx)})")

        test_nid_set = set(sample_nids[te_idx])
        train_nid_set = set(sample_nids[tr_idx])

        # 預計算 exclusive L1 鄰居（Level C 需要）
        exclusive_l1 = find_exclusive_l1_neighbors(
            sample_nids[te_idx], adj, nodes, all_l0_nids)
        logger.info(f"  Exclusive L1 neighbors of test set: {len(exclusive_l1)}")

        for lv_name, lv_cfg in levels.items():
            # 決定要從 overlap_dict 移除的節點
            remove_set = set()
            if lv_cfg["remove_test"]:
                remove_set |= test_nid_set
            if lv_cfg["remove_exclusive_l1"]:
                remove_set |= exclusive_l1
            if lv_cfg["train_remove_pct"] > 0:
                rng = np.random.RandomState(42 + fold)
                train_nids_arr = sample_nids[tr_idx]
                n_remove = int(len(train_nids_arr) * lv_cfg["train_remove_pct"])
                remove_train = set(rng.choice(train_nids_arr, n_remove, replace=False))
                remove_set |= remove_train

            overlap_dict_reduced = build_reduced_overlap_dict(overlap_dict_full, remove_set)

            # 計算 L3 特徵
            n_total = n_l1 + n_l2 + n_l3 + n_l4
            X = np.full((len(y), n_total), np.nan, dtype=np.float32)

            for i in range(len(y)):
                nid = sample_nids[i]
                org = sample_orgs[i]

                if lv_cfg["remove_test"] and i in set(te_idx):
                    # test 樣本：用 reduced dict，不 exclude_org（模擬真實推論）
                    l3 = extract_l3(nid, adj, overlap_dict_reduced, org_list, exclude_org=None)
                elif not lv_cfg["remove_test"]:
                    # Level A: standard exclude_org
                    l3 = extract_l3(nid, adj, overlap_dict_full, org_list, exclude_org=org)
                else:
                    # train 樣本：用 reduced dict，exclude_org
                    l3 = extract_l3(nid, adj, overlap_dict_reduced, org_list, exclude_org=org)

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
            all_results[lv_name].append(m)

        # 印出此 fold 各 level 的結果
        for lv_name in levels:
            r = all_results[lv_name][-1]
            logger.info(f"  {lv_name:<22} Micro={r['micro_f1']:.4f}  Macro={r['macro_f1']:.4f}  "
                        f"Top3={r['top3_acc']:.4f}  Top5={r['top5_acc']:.4f}")

    # ── 彙總 ──
    print(f"\n{'='*95}")
    print(f"{'Level':<22} {'Description':<35} {'Micro-F1':>10} {'Macro-F1':>10} {'Top-3':>10} {'Top-5':>10}")
    print(f"{'='*95}")

    summary = {}
    for lv_name, lv_cfg in levels.items():
        res = all_results[lv_name]
        avg = {k: float(np.mean([r[k] for r in res])) for k in res[0]}
        std = {k: float(np.std([r[k] for r in res])) for k in res[0]}
        summary[lv_name] = {"avg": avg, "std": std, "desc": lv_cfg["desc"]}
        print(f"{lv_name:<22} {lv_cfg['desc']:<35} "
              f"{avg['micro_f1']:>8.4f}±{std['micro_f1']:.3f} "
              f"{avg['macro_f1']:>8.4f}±{std['macro_f1']:.3f} "
              f"{avg['top3_acc']:>8.4f}±{std['top3_acc']:.3f} "
              f"{avg['top5_acc']:>8.4f}±{std['top5_acc']:.3f}")
    print(f"{'='*95}")

    # Degradation from A
    base_micro = summary["A_standard"]["avg"]["micro_f1"]
    print(f"\nDegradation from Level A (Micro-F1 = {base_micro:.4f}):")
    for lv_name in levels:
        if lv_name == "A_standard":
            continue
        delta = summary[lv_name]["avg"]["micro_f1"] - base_micro
        print(f"  {lv_name:<22} Δ = {delta:+.4f} ({delta/base_micro*100:+.1f}%)")

    # Per-class F1 for Level B (most practical scenario)
    print(f"\nPer-class F1 comparison (A vs B vs C):")
    for lv_name in ["A_standard", "B_remove_test", "C_remove_test+L1"]:
        # Aggregate predictions across folds
        all_true, all_pred = [], []
        # Re-run is expensive; instead just print summary
        pass

    # ── 儲存 ──
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_DIR / "graduated_inference.json", "w") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    logger.info(f"\nSaved to {OUTPUT_DIR}/graduated_inference.json")


if __name__ == "__main__":
    main()
