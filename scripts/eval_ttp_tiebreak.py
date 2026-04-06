#!/usr/bin/env python3
"""
Phase 5: TTP Tie-Breaking for Graph Overlap（Experiment 4）。

Graph overlap 的 per-report LOO 中有 46.4% 的 tie cases。
用 TTP cosine similarity 打破 tie：
  1. 對每個 org 建 TTP profile（TF-IDF vector）
  2. Per-report LOO 時排除 held-out report 的 entities 重建 org profile
  3. Tie 時取 IoC 的 TTP vector 跟各 tied org 的 profile 算 cosine similarity

回答：「TTP 能打破多少 graph overlap 的 tie？打破後 accuracy 多少？」
"""

import hashlib
import json
import logging
import sqlite3
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

DB_PATH = Path("knowledge_graphs/master/merged_kg.db")
KG_JSON = Path("knowledge_graphs/master/merged_kg.json")
TTP_DIR = Path("scripts/ttp_extraction")
OUTPUT = Path("scripts/results/eval_ttp_tiebreak.json")

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
    for row in conn.execute(
        "SELECT source, target FROM edges WHERE relationship <> 'has_ioc'"
    ):
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
    """Load NER outputs indexed by report hash."""
    index = {}
    for org_dir in sorted(TTP_DIR.iterdir()):
        if not org_dir.is_dir() or org_dir.name.startswith("."):
            continue
        for f in sorted(org_dir.glob("*.json")):
            parts = f.stem.rsplit("_", 1)
            if len(parts) == 2 and len(parts[1]) == 10:
                h = parts[1]
            else:
                continue
            with open(f) as fh:
                data = json.load(fh)
            if "entities_normalized" not in data:
                continue
            index[h] = data
    return index


def build_report_ttp_docs(ner_index, node_reports):
    """Build: report_url → TTP document string (for TF-IDF)."""
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
    return url_to_doc


def get_ioc_ttp_doc(ioc_id, node_reports, url_to_doc):
    """Get TTP document for an IoC (union of all its reports)."""
    reports = node_reports.get(ioc_id, [])
    tokens = []
    for url in reports:
        doc = url_to_doc.get(url, "")
        if doc:
            tokens.append(doc)
    return " ".join(tokens)


def build_org_report_mapping(node_reports, node_orgs):
    """Build: org → set of report URLs."""
    org_reports = defaultdict(set)
    for nid, reports in node_reports.items():
        orgs = node_orgs.get(nid, set())
        for org in orgs:
            for url in reports:
                org_reports[org].add(url)
    return org_reports


def main():
    logger.info("Loading graph...")
    adj, node_depth, node_orgs = load_graph()

    logger.info("Loading reports...")
    node_reports = load_has_ioc_reports()

    logger.info("Loading NER index...")
    ner_index = load_ner_index()
    logger.info(f"  {len(ner_index)} NER files")

    logger.info("Building report TTP docs...")
    url_to_doc = build_report_ttp_docs(ner_index, node_reports)
    logger.info(f"  {len(url_to_doc)} report docs")

    # Org → reports mapping
    org_reports = build_org_report_mapping(node_reports, node_orgs)

    # Build global TF-IDF vectorizer (fit on all report docs)
    all_docs = [doc for doc in url_to_doc.values() if doc.strip()]
    vectorizer = TfidfVectorizer(
        min_df=1, token_pattern=r"[^\s]+", lowercase=False,
    )
    vectorizer.fit(all_docs)
    logger.info(f"  TF-IDF vocabulary: {len(vectorizer.vocabulary_)} terms")

    # Precompute L1→L0 mapping
    l0_set = {nid for nid, d in node_depth.items() if d == 0}
    l1_to_l0 = defaultdict(set)
    for n, neighbors in adj.items():
        if node_depth.get(n) != 1:
            continue
        for nb in neighbors:
            if nb in l0_set:
                l1_to_l0[n].add(nb)

    # L0 IoCs (single-org)
    l0_iocs = []
    for nid, d in node_depth.items():
        if d != 0 or nid.startswith("apt_"):
            continue
        orgs = node_orgs.get(nid, set())
        if len(orgs) == 1:
            l0_iocs.append((nid, list(orgs)[0]))

    logger.info(f"L0 IoCs: {len(l0_iocs)}")

    # Report grouping
    report_to_iocs = defaultdict(list)
    for v_id, v_org in l0_iocs:
        reports = node_reports.get(v_id, [])
        key = reports[0] if reports else f"__no_report_{v_id}"
        report_to_iocs[key].append((v_id, v_org))

    # ── Per-Report LOO with TTP Tie-Breaking ──
    logger.info("Running per-report LOO with TTP tie-breaking...")

    n_total = 0
    n_match = 0
    n_clear_correct = 0
    n_tie = 0
    n_tie_broken = 0
    n_tie_broken_correct = 0
    n_tie_unbroken = 0
    n_no_match = 0

    org_stats = defaultdict(lambda: {
        "total": 0, "match": 0, "clear_correct": 0,
        "tie": 0, "tie_broken_correct": 0, "tie_broken_wrong": 0,
        "tie_unbroken": 0,
    })

    for report_key, report_iocs in report_to_iocs.items():
        report_ioc_set = {v_id for v_id, _ in report_iocs}

        # Find exclusive L1 neighbors
        exclusive_l1 = set()
        for v_id in report_ioc_set:
            for n in adj.get(v_id, set()):
                if node_depth.get(n) != 1:
                    continue
                l0_parents = l1_to_l0.get(n, set())
                if l0_parents and l0_parents.issubset(report_ioc_set):
                    exclusive_l1.add(n)

        removed = report_ioc_set | exclusive_l1

        # Build org TTP profiles EXCLUDING this report's entities
        # (prevent leakage)
        held_out_urls = set()
        for v_id in report_ioc_set:
            for url in node_reports.get(v_id, []):
                held_out_urls.add(url)

        org_profiles = {}
        for org, org_urls in org_reports.items():
            remaining_urls = org_urls - held_out_urls
            if not remaining_urls:
                continue
            docs = [url_to_doc[u] for u in remaining_urls if u in url_to_doc and url_to_doc[u].strip()]
            if not docs:
                continue
            combined = " ".join(docs)
            org_profiles[org] = vectorizer.transform([combined])

        for v_id, v_org in report_iocs:
            n_total += 1
            org_stats[v_org]["total"] += 1

            v_neighbors = adj.get(v_id, set())
            matched = v_neighbors - removed

            if not matched:
                n_no_match += 1
                continue

            n_match += 1
            org_stats[v_org]["match"] += 1

            # Majority vote
            org_votes = Counter()
            for n in matched:
                for org in node_orgs.get(n, set()):
                    org_votes[org] += 1

            top_count = org_votes.most_common(1)[0][1]
            tied = [org for org, cnt in org_votes.items() if cnt == top_count]

            if len(tied) == 1:
                # Clear winner
                n_clear_correct += 1
                org_stats[v_org]["clear_correct"] += 1
            else:
                # Tie → TTP tie-breaking
                n_tie += 1
                org_stats[v_org]["tie"] += 1

                # Get IoC's TTP vector
                ioc_doc = get_ioc_ttp_doc(v_id, node_reports, url_to_doc)
                if not ioc_doc.strip():
                    n_tie_unbroken += 1
                    org_stats[v_org]["tie_unbroken"] += 1
                    continue

                ioc_vec = vectorizer.transform([ioc_doc])

                # Compute similarity to each tied org's profile
                best_org = None
                best_sim = -1
                n_compared = 0
                for org in tied:
                    if org not in org_profiles:
                        continue
                    sim = cosine_similarity(ioc_vec, org_profiles[org])[0][0]
                    n_compared += 1
                    if sim > best_sim:
                        best_sim = sim
                        best_org = org

                if best_org is None or n_compared < 2:
                    # Can't break tie (not enough org profiles)
                    n_tie_unbroken += 1
                    org_stats[v_org]["tie_unbroken"] += 1
                else:
                    n_tie_broken += 1
                    if best_org == v_org:
                        n_tie_broken_correct += 1
                        org_stats[v_org]["tie_broken_correct"] += 1
                    else:
                        org_stats[v_org]["tie_broken_wrong"] += 1

    # ── Results ──
    print(f"\n{'='*70}")
    print("TTP Tie-Breaking Results (Experiment 4)")
    print(f"{'='*70}")

    print(f"\n  Total IoCs:           {n_total:>6,}")
    print(f"  No match:             {n_no_match:>6,} ({n_no_match/n_total*100:.1f}%)")
    print(f"  Matched:              {n_match:>6,} ({n_match/n_total*100:.1f}%)")
    print(f"    Clear winner:       {n_clear_correct:>6,} ({n_clear_correct/n_match*100:.1f}%) → 100% correct")
    print(f"    Tie:                {n_tie:>6,} ({n_tie/n_match*100:.1f}%)")
    print(f"      TTP broken:       {n_tie_broken:>6,} ({n_tie_broken/n_tie*100:.1f}% of ties)")
    tb_acc = n_tie_broken_correct / n_tie_broken * 100 if n_tie_broken else 0
    print(f"        Correct:        {n_tie_broken_correct:>6,} ({tb_acc:.1f}%)")
    print(f"        Wrong:          {n_tie_broken - n_tie_broken_correct:>6,}")
    print(f"      Unbroken:         {n_tie_unbroken:>6,} ({n_tie_unbroken/n_tie*100:.1f}%)")

    # Overall accuracy (deterministic only)
    total_correct = n_clear_correct + n_tie_broken_correct
    total_decided = n_clear_correct + n_tie_broken
    det_acc = total_correct / total_decided * 100 if total_decided else 0
    print(f"\n  Deterministic decisions: {total_decided:>5,}")
    print(f"  Deterministic accuracy: {total_correct}/{total_decided} = {det_acc:.1f}%")
    print(f"  Coverage (decided/total): {total_decided/n_total*100:.1f}%")

    # Comparison: before vs after TTP
    print(f"\n  Before TTP:  {n_clear_correct} decided, {n_clear_correct/n_total*100:.1f}% coverage, 100% acc")
    print(f"  After TTP:   {total_decided} decided, {total_decided/n_total*100:.1f}% coverage, {det_acc:.1f}% acc")
    print(f"  Δ decided:   +{n_tie_broken} ({n_tie_broken/n_total*100:.1f}%)")

    # Per-org detail
    print(f"\n  {'Org':<20} {'Match':>6} {'Clear':>6} {'Tie':>5} {'Broken':>7} {'Correct':>8} {'Acc%':>6}")
    print(f"  {'-'*20} {'-'*6} {'-'*6} {'-'*5} {'-'*7} {'-'*8} {'-'*6}")
    for org in sorted(org_stats.keys()):
        s = org_stats[org]
        broken = s["tie_broken_correct"] + s["tie_broken_wrong"]
        acc = s["tie_broken_correct"] / broken * 100 if broken else 0
        acc_str = f"{acc:.0f}%" if broken else "—"
        print(
            f"  {org:<20} {s['match']:>6} {s['clear_correct']:>6} {s['tie']:>5} "
            f"{broken:>7} {s['tie_broken_correct']:>8} {acc_str:>6}"
        )

    # Save
    output = {
        "summary": {
            "total": n_total,
            "no_match": n_no_match,
            "matched": n_match,
            "clear_correct": n_clear_correct,
            "tie": n_tie,
            "tie_broken": n_tie_broken,
            "tie_broken_correct": n_tie_broken_correct,
            "tie_unbroken": n_tie_unbroken,
            "det_accuracy": round(det_acc / 100, 4),
            "coverage_before": round(n_clear_correct / n_total, 4),
            "coverage_after": round(total_decided / n_total, 4),
        },
        "per_org": {
            org: dict(s) for org, s in org_stats.items()
        },
    }

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT, "w") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    logger.info(f"Saved to {OUTPUT}")


if __name__ == "__main__":
    main()
