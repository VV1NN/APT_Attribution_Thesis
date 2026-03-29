#!/usr/bin/env python3
"""
訓練最終模型並存檔，供 inference.py 使用。
使用 ALL-nodes overlap dict + 全部訓練資料（不做 CV split）。
輸出：scripts/model/ 目錄下的所有必要檔案。
"""

import json
import logging
import pickle
from collections import Counter
from pathlib import Path

import numpy as np
from sklearn.preprocessing import LabelEncoder
from sklearn.impute import SimpleImputer
from xgboost import XGBClassifier

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

MODEL_DIR = Path("scripts/model")


def main():
    # ── Load ──
    nodes, adj, edge_by_node, has_ioc_orgs = load_kg()
    bf._node_attrs = {nid: nd["attributes"] for nid, nd in nodes.items()}

    with open(VOCAB_PATH) as f:
        vdata = json.load(f)
    vocabs, value_counts, freq_tables = vdata["vocabs"], vdata["value_counts"], vdata["freq"]

    # ALL-nodes overlap dict
    overlap_dict = {nid: nd["orgs"] for nid, nd in nodes.items()
                    if nd["type"] != "apt" and nd["orgs"]}
    logger.info(f"Overlap dict: {len(overlap_dict)} nodes")

    n2v = load_node2vec()

    # ── Org list ──
    org_counts = Counter()
    for nid, nd in nodes.items():
        if nd["type"] != "apt" and nd.get("depth") == 0 and nd["orgs"]:
            for org in nd["orgs"]:
                org_counts[org] += 1
    org_list = sorted([o for o, c in org_counts.items() if c >= MIN_IOCS])
    l3_names = get_l3_names(org_list)

    # ── Collect training samples ──
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

    le = LabelEncoder()
    y = le.fit_transform(sample_orgs)
    logger.info(f"Training: {len(y)} samples, {len(le.classes_)} classes")

    # ── Extract features ──
    n_l1, n_l2, n_l3, n_l4 = len(L1_NAMES), len(L2_NAMES), len(l3_names), len(L4_NAMES)
    n_total = n_l1 + n_l2 + n_l3 + n_l4
    all_names = L1_NAMES + L2_NAMES + l3_names + L4_NAMES

    logger.info(f"Extracting {n_total} features...")
    X = np.full((len(y), n_total), np.nan, dtype=np.float32)
    for i, nid in enumerate(sample_nids):
        nd = nodes[nid]
        l1 = extract_l1(nid, nd, vocabs, value_counts, freq_tables)
        l2 = extract_l2(nid, adj, edge_by_node, nodes)
        l3 = extract_l3(nid, adj, overlap_dict, org_list, exclude_org=None)
        l4 = extract_l4(nid, adj, n2v)
        X[i] = np.array(l1 + l2 + list(l3) + list(l4), dtype=np.float32)

    # ── Impute + Train ──
    imputer = SimpleImputer(strategy="median")
    X_imp = imputer.fit_transform(X)

    classes, counts = np.unique(y, return_counts=True)
    n, k = len(y), len(classes)
    sw = np.array([n / (k * cnt) for cnt in counts])[y]

    logger.info("Training XGBoost...")
    clf = XGBClassifier(
        n_estimators=500, max_depth=8, learning_rate=0.05,
        subsample=0.8, colsample_bytree=0.8, min_child_weight=3,
        eval_metric="mlogloss", random_state=42, n_jobs=-1, verbosity=0,
    )
    clf.fit(X_imp, y, sample_weight=sw)

    # ── Save ──
    MODEL_DIR.mkdir(parents=True, exist_ok=True)

    clf.save_model(MODEL_DIR / "xgboost_model.json")
    with open(MODEL_DIR / "imputer.pkl", "wb") as f:
        pickle.dump(imputer, f)
    with open(MODEL_DIR / "label_encoder.pkl", "wb") as f:
        pickle.dump(le, f)
    with open(MODEL_DIR / "config.json", "w") as f:
        json.dump({
            "org_list": org_list,
            "feature_names": all_names,
            "n_l1": n_l1, "n_l2": n_l2, "n_l3": n_l3, "n_l4": n_l4,
            "n_total": n_total,
            "confidence_threshold": 0.3,
            "n_training_samples": len(y),
            "classes": list(le.classes_),
        }, f, indent=2, ensure_ascii=False)

    logger.info(f"Model saved to {MODEL_DIR}/")
    logger.info(f"  xgboost_model.json, imputer.pkl, label_encoder.pkl, config.json")


if __name__ == "__main__":
    main()
