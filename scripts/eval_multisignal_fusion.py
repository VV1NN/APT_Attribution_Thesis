#!/usr/bin/env python3
"""
Phase 6: Multi-Signal Fusion Evaluation（Experiment 5）。

Cascading 架構：
  Stage 1: Graph Overlap → clear winner → HIGH
  Stage 2: Graph tie → TTP tie-breaking → MEDIUM
  Stage 3: No match / unbroken tie → ML classifier → LOW

報告每 stage 的 coverage/accuracy 和累積效果。
"""

import hashlib
import json
import logging
import sqlite3
import sys
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
from scipy.sparse import load_npz
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.impute import SimpleImputer
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.model_selection import GroupKFold
from sklearn.preprocessing import LabelEncoder
from xgboost import XGBClassifier

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

DB_PATH = Path("knowledge_graphs/master/merged_kg.db")
KG_JSON = Path("knowledge_graphs/master/merged_kg.json")
FEATURE_DIR = Path("scripts/features")
TTP_DIR = Path("scripts/ttp_extraction")
OUTPUT = Path("scripts/results/eval_multisignal_fusion.json")

ENTITY_TYPES_FOR_TTP = ["Tool", "Way", "Exp"]


def url_to_ner_hash(url):
    return hashlib.sha1(url.encode()).hexdigest()[:10]


def load_graph():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    node_depth = {}
    for row in conn.execute("SELECT id, depth FROM nodes"):
        node_depth[row["id"]] = row["depth"]
    node_orgs = defaultdict(set)
    for row in conn.execute("SELECT node_id, org FROM node_orgs"):
        node_orgs[row["node_id"]].add(row["org"])
    adj = defaultdict(set)
    for row in conn.execute("SELECT source, target FROM edges WHERE relationship <> 'has_ioc'"):
        adj[row["source"]].add(row["target"])
        adj[row["target"]].add(row["source"])
    conn.close()
    return adj, node_depth, node_orgs


def load_has_ioc_reports():
    with open(KG_JSON) as f:
        data = json.load(f)
    node_reports = {}
    for e in data["edges"]:
        if e.get("relationship") != "has_ioc":
            continue
        tgt = e["target"]
        reports = (e.get("attributes") or {}).get("source_reports", [])
        if reports:
            if tgt in node_reports:
                node_reports[tgt] = sorted(set(node_reports[tgt]) | set(reports))
            else:
                node_reports[tgt] = sorted(reports)
    return node_reports


def load_ner_index():
    index = {}
    for org_dir in sorted(TTP_DIR.iterdir()):
        if not org_dir.is_dir() or org_dir.name.startswith("."):
            continue
        for f in sorted(org_dir.glob("*.json")):
            parts = f.stem.rsplit("_", 1)
            if len(parts) == 2 and len(parts[1]) == 10:
                with open(f) as fh:
                    data = json.load(fh)
                if "entities_normalized" in data:
                    index[parts[1]] = data
    return index


def balanced_weights(y):
    classes, counts = np.unique(y, return_counts=True)
    n, k = len(y), len(classes)
    w_map = {c: n / (k * cnt) for c, cnt in zip(classes, counts)}
    return np.array([w_map[yi] for yi in y])


def main():
    logger.info("Loading graph...")
    adj, node_depth, node_orgs = load_graph()

    logger.info("Loading reports...")
    node_reports = load_has_ioc_reports()

    logger.info("Loading NER index...")
    ner_index = load_ner_index()

    # Build TTP infrastructure (same as eval_ttp_tiebreak.py)
    url_to_doc = {}
    for nid, reports in node_reports.items():
        for url in reports:
            if url in url_to_doc:
                continue
            h = url_to_ner_hash(url)
            if h not in ner_index:
                continue
            ner = ner_index[h]
            entities = ner.get("entities_normalized", {})
            tokens = []
            for etype in ENTITY_TYPES_FOR_TTP:
                for e in entities.get(etype, []):
                    tokens.append(e.replace(" ", "_"))
            url_to_doc[url] = " ".join(tokens)

    org_reports_map = defaultdict(set)
    for nid, reports in node_reports.items():
        for org in node_orgs.get(nid, set()):
            for url in reports:
                org_reports_map[org].add(url)

    all_docs = [doc for doc in url_to_doc.values() if doc.strip()]
    vectorizer = TfidfVectorizer(min_df=1, token_pattern=r"[^\s]+", lowercase=False)
    vectorizer.fit(all_docs)

    # Load ML features (L1 + L5 for Cascade A)
    logger.info("Loading ML features...")
    static_data = np.load(FEATURE_DIR / "features_all.npz", allow_pickle=True)
    with open(FEATURE_DIR / "feature_names.json") as f:
        names = json.load(f)
    X_static = static_data["X"]
    y_labels = static_data["y"]
    ml_node_ids = list(static_data["node_ids"])

    X_l5 = load_npz(FEATURE_DIR / "features_l5_ttp_matrix.npz").toarray()

    l1_end = len(names["l1"])
    # Cascade A: L1 + L5 only
    X_ml_a = np.hstack([X_static[:, :l1_end], X_l5])
    # Cascade B: full L1-L4 + L5
    X_ml_b = np.hstack([X_static, X_l5])

    ml_nid_to_idx = {nid: i for i, nid in enumerate(ml_node_ids)}

    le = LabelEncoder()
    y_enc = le.fit_transform(y_labels)

    # Train ML classifiers using GroupKFold
    # We need per-fold predictions for IoCs that reach Stage 3
    groups = []
    report_to_id = {}
    next_id = 0
    for nid in ml_node_ids:
        reports = node_reports.get(nid)
        if reports:
            key = reports[0]
            if key not in report_to_id:
                report_to_id[key] = next_id
                next_id += 1
            groups.append(report_to_id[key])
        else:
            groups.append(next_id)
            next_id += 1
    groups = np.array(groups)

    logger.info("Training per-fold ML classifiers...")
    # Pre-compute per-fold predictions
    ml_pred_a = np.full(len(ml_node_ids), -1, dtype=np.int32)
    ml_pred_b = np.full(len(ml_node_ids), -1, dtype=np.int32)

    gkf = GroupKFold(n_splits=5)
    for fold, (tr, te) in enumerate(gkf.split(X_ml_a, y_enc, groups)):
        # Cascade A
        imp_a = SimpleImputer(strategy="median")
        Xtr_a = imp_a.fit_transform(X_ml_a[tr])
        Xte_a = imp_a.transform(X_ml_a[te])

        fold_classes = sorted(set(y_enc[tr]))
        cmap = {c: i for i, c in enumerate(fold_classes)}
        imap = {i: c for c, i in cmap.items()}
        ytr_re = np.array([cmap[c] for c in y_enc[tr]])

        clf_a = XGBClassifier(
            n_estimators=500, max_depth=8, learning_rate=0.05,
            subsample=0.8, colsample_bytree=0.8, min_child_weight=3,
            eval_metric="mlogloss", random_state=42, n_jobs=-1, verbosity=0,
        )
        clf_a.fit(Xtr_a, ytr_re, sample_weight=balanced_weights(ytr_re))
        pred_a = clf_a.predict(Xte_a)
        for i, idx in enumerate(te):
            p = pred_a[i]
            ml_pred_a[idx] = imap.get(p, -1)

        # Cascade B
        imp_b = SimpleImputer(strategy="median")
        Xtr_b = imp_b.fit_transform(X_ml_b[tr])
        Xte_b = imp_b.transform(X_ml_b[te])
        clf_b = XGBClassifier(
            n_estimators=500, max_depth=8, learning_rate=0.05,
            subsample=0.8, colsample_bytree=0.8, min_child_weight=3,
            eval_metric="mlogloss", random_state=42, n_jobs=-1, verbosity=0,
        )
        clf_b.fit(Xtr_b, ytr_re, sample_weight=balanced_weights(ytr_re))
        pred_b = clf_b.predict(Xte_b)
        for i, idx in enumerate(te):
            p = pred_b[i]
            ml_pred_b[idx] = imap.get(p, -1)

    logger.info("ML classifiers trained. Running cascade evaluation...")

    # ── Precompute LOO structures ──
    l0_set = {nid for nid, d in node_depth.items() if d == 0}
    l1_to_l0 = defaultdict(set)
    for n, neighbors in adj.items():
        if node_depth.get(n) != 1:
            continue
        for nb in neighbors:
            if nb in l0_set:
                l1_to_l0[n].add(nb)

    l0_iocs = []
    for nid, d in node_depth.items():
        if d != 0 or nid.startswith("apt_"):
            continue
        orgs = node_orgs.get(nid, set())
        if len(orgs) == 1:
            l0_iocs.append((nid, list(orgs)[0]))

    report_to_iocs = defaultdict(list)
    for v_id, v_org in l0_iocs:
        reports = node_reports.get(v_id, [])
        key = reports[0] if reports else f"__no_report_{v_id}"
        report_to_iocs[key].append((v_id, v_org))

    # ── Cascade evaluation ──
    stage_results = {
        "stage1_clear": {"correct": 0, "wrong": 0},
        "stage2_ttp": {"correct": 0, "wrong": 0},
        "stage3a_ml": {"correct": 0, "wrong": 0},
        "stage3b_ml": {"correct": 0, "wrong": 0},
        "unresolved": {"count": 0},
    }

    # Collect per-IoC predictions for F1 computation
    all_true_a = []  # true labels for cascade A
    all_pred_a = []  # predicted labels for cascade A
    all_true_b = []
    all_pred_b = []
    all_stage = []   # which stage decided each IoC

    for report_key, report_iocs in report_to_iocs.items():
        report_ioc_set = {v_id for v_id, _ in report_iocs}

        exclusive_l1 = set()
        for v_id in report_ioc_set:
            for n in adj.get(v_id, set()):
                if node_depth.get(n) != 1:
                    continue
                l0_parents = l1_to_l0.get(n, set())
                if l0_parents and l0_parents.issubset(report_ioc_set):
                    exclusive_l1.add(n)
        removed = report_ioc_set | exclusive_l1

        # Org TTP profiles (excluding this report)
        held_out_urls = set()
        for v_id in report_ioc_set:
            for url in node_reports.get(v_id, []):
                held_out_urls.add(url)

        org_profiles = {}
        for org, org_urls in org_reports_map.items():
            remaining = org_urls - held_out_urls
            docs = [url_to_doc[u] for u in remaining if u in url_to_doc and url_to_doc[u].strip()]
            if docs:
                org_profiles[org] = vectorizer.transform([" ".join(docs)])

        for v_id, v_org in report_iocs:
            v_neighbors = adj.get(v_id, set())
            matched = v_neighbors - removed

            # Stage 1: Graph Overlap
            if matched:
                org_votes = Counter()
                for n in matched:
                    for org in node_orgs.get(n, set()):
                        org_votes[org] += 1

                top_count = org_votes.most_common(1)[0][1]
                tied = [org for org, cnt in org_votes.items() if cnt == top_count]

                if len(tied) == 1:
                    # Clear winner
                    if tied[0] == v_org:
                        stage_results["stage1_clear"]["correct"] += 1
                    else:
                        stage_results["stage1_clear"]["wrong"] += 1
                    all_true_a.append(v_org)
                    all_pred_a.append(tied[0])
                    all_true_b.append(v_org)
                    all_pred_b.append(tied[0])
                    all_stage.append(1)
                    continue

                # Stage 2: TTP tie-breaking
                ioc_doc = ""
                for url in node_reports.get(v_id, []):
                    d = url_to_doc.get(url, "")
                    if d:
                        ioc_doc += " " + d

                if ioc_doc.strip():
                    ioc_vec = vectorizer.transform([ioc_doc])
                    best_org, best_sim, n_cmp = None, -1, 0
                    for org in tied:
                        if org in org_profiles:
                            sim = cosine_similarity(ioc_vec, org_profiles[org])[0][0]
                            n_cmp += 1
                            if sim > best_sim:
                                best_sim = sim
                                best_org = org

                    if best_org and n_cmp >= 2:
                        if best_org == v_org:
                            stage_results["stage2_ttp"]["correct"] += 1
                        else:
                            stage_results["stage2_ttp"]["wrong"] += 1
                        all_true_a.append(v_org)
                        all_pred_a.append(best_org)
                        all_true_b.append(v_org)
                        all_pred_b.append(best_org)
                        all_stage.append(2)
                        continue

            # Stage 3: ML classifier
            ml_idx = ml_nid_to_idx.get(v_id)
            if ml_idx is not None and ml_pred_a[ml_idx] >= 0:
                # Cascade A
                pred_cls_a = ml_pred_a[ml_idx]
                pred_org_a = le.classes_[pred_cls_a]
                if pred_cls_a == le.transform([v_org])[0]:
                    stage_results["stage3a_ml"]["correct"] += 1
                else:
                    stage_results["stage3a_ml"]["wrong"] += 1

                # Cascade B
                pred_cls_b = ml_pred_b[ml_idx]
                pred_org_b = le.classes_[pred_cls_b]
                if pred_cls_b == le.transform([v_org])[0]:
                    stage_results["stage3b_ml"]["correct"] += 1
                else:
                    stage_results["stage3b_ml"]["wrong"] += 1

                all_true_a.append(v_org)
                all_pred_a.append(pred_org_a)
                all_true_b.append(v_org)
                all_pred_b.append(pred_org_b)
                all_stage.append(3)
            else:
                stage_results["unresolved"]["count"] += 1

    # ── Print results ──
    total = len(l0_iocs)
    print(f"\n{'='*70}")
    print("Multi-Signal Fusion Results (Experiment 5)")
    print(f"{'='*70}")

    cumulative_correct_a = 0
    cumulative_correct_b = 0
    cumulative_decided = 0

    print(f"\n  Total IoCs: {total:,}\n")
    print(f"  {'Stage':<30} {'Decided':>8} {'Correct':>8} {'Acc%':>7} {'Cum.Cov%':>9} {'Cum.Acc-A%':>11} {'Cum.Acc-B%':>11}")
    print(f"  {'-'*30} {'-'*8} {'-'*8} {'-'*7} {'-'*9} {'-'*11} {'-'*11}")

    for stage_name, label in [
        ("stage1_clear", "S1: Graph clear winner"),
        ("stage2_ttp", "S2: TTP tie-breaking"),
    ]:
        s = stage_results[stage_name]
        decided = s["correct"] + s["wrong"]
        acc = s["correct"] / decided * 100 if decided else 0
        cumulative_correct_a += s["correct"]
        cumulative_correct_b += s["correct"]
        cumulative_decided += decided
        cum_cov = cumulative_decided / total * 100
        cum_acc_a = cumulative_correct_a / cumulative_decided * 100 if cumulative_decided else 0
        print(
            f"  {label:<30} {decided:>8,} {s['correct']:>8,} {acc:>6.1f}% {cum_cov:>8.1f}% "
            f"{cum_acc_a:>10.1f}% {cum_acc_a:>10.1f}%"
        )

    # Stage 3 splits into A and B
    s3a = stage_results["stage3a_ml"]
    s3b = stage_results["stage3b_ml"]
    decided_3 = s3a["correct"] + s3a["wrong"]
    acc_a = s3a["correct"] / decided_3 * 100 if decided_3 else 0
    acc_b = s3b["correct"] / decided_3 * 100 if decided_3 else 0

    cum_a = cumulative_correct_a + s3a["correct"]
    cum_b = cumulative_correct_b + s3b["correct"]
    cum_decided_3 = cumulative_decided + decided_3
    cum_cov_3 = cum_decided_3 / total * 100
    cum_acc_a_3 = cum_a / cum_decided_3 * 100 if cum_decided_3 else 0
    cum_acc_b_3 = cum_b / cum_decided_3 * 100 if cum_decided_3 else 0

    print(
        f"  {'S3: ML fallback':<30} {decided_3:>8,} {'':>8} {'':>7} {cum_cov_3:>8.1f}% "
        f"{cum_acc_a_3:>10.1f}% {cum_acc_b_3:>10.1f}%"
    )
    print(f"    {'A (L1+L5 clean)':<28} {'':>8} {s3a['correct']:>8,} {acc_a:>6.1f}%")
    print(f"    {'B (L1-L5 full)':<28} {'':>8} {s3b['correct']:>8,} {acc_b:>6.1f}%")

    unresolved = stage_results["unresolved"]["count"]
    if unresolved:
        print(f"  {'Unresolved':<30} {unresolved:>8,}")

    # ── F1 Scores ──
    from sklearn.metrics import f1_score as compute_f1

    micro_a = compute_f1(all_true_a, all_pred_a, average="micro", zero_division=0)
    macro_a = compute_f1(all_true_a, all_pred_a, average="macro", zero_division=0)
    micro_b = compute_f1(all_true_b, all_pred_b, average="micro", zero_division=0)
    macro_b = compute_f1(all_true_b, all_pred_b, average="macro", zero_division=0)

    # Per-stage F1
    stage_f1 = {}
    for stage_num, stage_label in [(1, "S1: Graph"), (2, "S2: TTP"), (3, "S3: ML")]:
        mask = [i for i, s in enumerate(all_stage) if s == stage_num]
        if mask:
            t = [all_true_a[i] for i in mask]
            p_a = [all_pred_a[i] for i in mask]
            p_b = [all_pred_b[i] for i in mask]
            stage_f1[stage_label] = {
                "n": len(mask),
                "micro_a": round(compute_f1(t, p_a, average="micro", zero_division=0), 4),
                "macro_a": round(compute_f1(t, p_a, average="macro", zero_division=0), 4),
                "micro_b": round(compute_f1(t, p_b, average="micro", zero_division=0), 4),
                "macro_b": round(compute_f1(t, p_b, average="macro", zero_division=0), 4),
            }

    # Final summary
    print(f"\n  {'─'*70}")
    print(f"  Cascade A (clean): {cum_a}/{cum_decided_3} = {cum_acc_a_3:.1f}% accuracy, {cum_cov_3:.1f}% coverage")
    print(f"  Cascade B (full):  {cum_b}/{cum_decided_3} = {cum_acc_b_3:.1f}% accuracy, {cum_cov_3:.1f}% coverage")
    print(f"  Graph-only:        {stage_results['stage1_clear']['correct']}/{total} = "
          f"{stage_results['stage1_clear']['correct']/total*100:.1f}% accuracy, "
          f"{(stage_results['stage1_clear']['correct']+stage_results['stage1_clear']['wrong'])/total*100:.1f}% coverage")

    print(f"\n  {'─'*70}")
    print(f"  F1 Scores (on {len(all_true_a):,} decided IoCs):")
    print(f"  {'Cascade A (L1+L5)':<22} micro-F1={micro_a:.1%}  macro-F1={macro_a:.1%}")
    print(f"  {'Cascade B (L1-L5)':<22} micro-F1={micro_b:.1%}  macro-F1={macro_b:.1%}")
    print()
    print(f"  Per-stage F1:")
    for label, sf in stage_f1.items():
        print(f"    {label:<14} n={sf['n']:>5,}  micro-F1(A)={sf['micro_a']:.1%}  macro-F1(A)={sf['macro_a']:.1%}")

    # Save
    output = {
        "stages": {k: dict(v) for k, v in stage_results.items()},
        "cascade_a": {
            "total_correct": cum_a,
            "total_decided": cum_decided_3,
            "accuracy": round(cum_acc_a_3 / 100, 4),
            "coverage": round(cum_cov_3 / 100, 4),
            "micro_f1": round(micro_a, 4),
            "macro_f1": round(macro_a, 4),
        },
        "cascade_b": {
            "total_correct": cum_b,
            "total_decided": cum_decided_3,
            "accuracy": round(cum_acc_b_3 / 100, 4),
            "coverage": round(cum_cov_3 / 100, 4),
            "micro_f1": round(micro_b, 4),
            "macro_f1": round(macro_b, 4),
        },
        "stage_f1": stage_f1,
    }

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT, "w") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    logger.info(f"Saved to {OUTPUT}")


if __name__ == "__main__":
    main()
