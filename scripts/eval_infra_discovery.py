#!/usr/bin/env python3
"""
Phase 7: Infrastructure Discovery Evaluation（Experiment 6）。

對每個正確歸因的 IoC，分析 matched L1 nodes：
- 多少是原報告未提及的（透過 VT relationship 新發現）
- 按 node type 分類
- Precision@K
"""

import json
import sqlite3
import logging
from collections import Counter, defaultdict
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

DB_PATH = Path("knowledge_graphs/master/merged_kg.db")
KG_JSON = Path("knowledge_graphs/master/merged_kg.json")
OUTPUT = Path("scripts/results/eval_infra_discovery.json")


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


def main():
    logger.info("Loading graph...")
    adj, node_depth, node_orgs = load_graph()

    logger.info("Loading reports...")
    node_reports = load_has_ioc_reports()

    # L0 IoCs
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

    # Report grouping
    report_to_iocs = defaultdict(list)
    ioc_to_report = {}
    for v_id, v_org in l0_iocs:
        reports = node_reports.get(v_id, [])
        key = reports[0] if reports else f"__no_report_{v_id}"
        report_to_iocs[key].append((v_id, v_org))
        ioc_to_report[v_id] = key

    # Find which L0 IoCs belong to each report (for "novel discovery" check)
    report_l0_nodes = defaultdict(set)
    for v_id, v_org in l0_iocs:
        rpt = ioc_to_report.get(v_id)
        if rpt:
            report_l0_nodes[rpt].add(v_id)

    logger.info(f"L0 IoCs: {len(l0_iocs)}, Reports: {len(report_to_iocs)}")

    # ── Per-Report LOO ──
    total_correct = 0
    total_matched_infra = 0
    total_novel_infra = 0
    precision_at_k = {5: [], 10: [], 20: []}
    type_counts = Counter()
    novel_type_counts = Counter()

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

        for v_id, v_org in report_iocs:
            v_neighbors = adj.get(v_id, set())
            matched = v_neighbors - removed

            if not matched:
                continue

            # Check if clear winner
            org_votes = Counter()
            for n in matched:
                for org in node_orgs.get(n, set()):
                    org_votes[org] += 1

            top_count = org_votes.most_common(1)[0][1]
            tied = [org for org, cnt in org_votes.items() if cnt == top_count]

            if len(tied) != 1 or tied[0] != v_org:
                continue  # Only analyze correctly attributed (clear winner)

            total_correct += 1

            # Analyze matched L1 nodes as discovered infrastructure
            # Sort by: nodes belonging to fewer orgs first (more specific)
            infra_nodes = []
            for n in matched:
                n_type = n.split("_")[0]
                n_orgs = node_orgs.get(n, set())
                belongs_to_correct = v_org in n_orgs
                # Is this node "novel"? (not in the original report's L0 set)
                is_novel = n not in report_ioc_set  # always True since removed
                is_l1 = node_depth.get(n) == 1
                infra_nodes.append({
                    "id": n,
                    "type": n_type,
                    "n_orgs": len(n_orgs),
                    "correct_org": belongs_to_correct,
                    "depth": node_depth.get(n, -1),
                })

            # Sort by n_orgs (exclusive first) then by type
            infra_nodes.sort(key=lambda x: (x["n_orgs"], x["type"]))

            total_matched_infra += len(infra_nodes)

            # Count novel (depth=1, discovered via VT relationships)
            novel = [n for n in infra_nodes if n["depth"] == 1]
            total_novel_infra += len(novel)

            for n in infra_nodes:
                type_counts[n["type"]] += 1
            for n in novel:
                novel_type_counts[n["type"]] += 1

            # Precision@K: of top-K discovered nodes, how many belong to correct org?
            for k in precision_at_k:
                top_k = infra_nodes[:k]
                if not top_k:
                    continue
                correct_in_k = sum(1 for n in top_k if n["correct_org"])
                precision_at_k[k].append(correct_in_k / len(top_k))

    # ── Results ──
    print(f"\n{'='*70}")
    print("Infrastructure Discovery Evaluation (Experiment 6)")
    print(f"{'='*70}")

    print(f"\n  Correctly attributed IoCs (clear winner): {total_correct:,}")
    print(f"  Total discovered infrastructure nodes:     {total_matched_infra:,}")
    print(f"  Avg per IoC:                               {total_matched_infra/total_correct:.1f}")
    print(f"  Novel (L1, VT-discovered):                 {total_novel_infra:,} ({total_novel_infra/total_matched_infra*100:.1f}%)")

    print(f"\n  Discovered infrastructure by type:")
    for t, cnt in type_counts.most_common():
        novel = novel_type_counts.get(t, 0)
        print(f"    {t:<10} {cnt:>7,} (novel: {novel:>6,})")

    print(f"\n  Precision@K (infrastructure belongs to correct org):")
    for k in sorted(precision_at_k):
        vals = precision_at_k[k]
        if vals:
            avg = sum(vals) / len(vals)
            print(f"    P@{k:<3} = {avg:.3f}  (n={len(vals):,})")

    # Save
    output = {
        "total_correct_attributed": total_correct,
        "total_matched_infra": total_matched_infra,
        "avg_per_ioc": round(total_matched_infra / total_correct, 2) if total_correct else 0,
        "total_novel_infra": total_novel_infra,
        "type_counts": dict(type_counts),
        "novel_type_counts": dict(novel_type_counts),
        "precision_at_k": {
            str(k): round(sum(v) / len(v), 4) if v else 0
            for k, v in precision_at_k.items()
        },
    }

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT, "w") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    logger.info(f"Saved to {OUTPUT}")


if __name__ == "__main__":
    main()
