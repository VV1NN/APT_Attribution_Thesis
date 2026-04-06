#!/usr/bin/env python3
"""
Per-Report Leave-One-Out Overlap 歸因測試。

測試 graph connectivity 的跨 campaign 泛化能力：
  1. 對每份報告，移除該報告的所有 IoC + 獨佔 L1 鄰居
  2. 對被移除的每個 IoC，看它的 VT 鄰居有沒有 match 到剩餘 KG
  3. 用 matched nodes 的 org label 做 majority vote
  4. 和 per-IoC leave-one-out 結果比較

回答：「一個全新 campaign 的 IoC，透過 graph connection 歸因到已知 APT 的成功率」
"""

import json
import sqlite3
import logging
from collections import Counter, defaultdict
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S")
logger = logging.getLogger(__name__)

DB_PATH = Path("knowledge_graphs/master/merged_kg.db")
KG_JSON = Path("knowledge_graphs/master/merged_kg.json")


def load_graph():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    node_depth = {}
    cur = conn.execute("SELECT id, depth FROM nodes")
    for row in cur:
        node_depth[row["id"]] = row["depth"]

    node_orgs = defaultdict(set)
    cur = conn.execute("SELECT node_id, org FROM node_orgs")
    for row in cur:
        node_orgs[row["node_id"]].add(row["org"])

    adj = defaultdict(set)
    cur = conn.execute("SELECT source, target FROM edges WHERE relationship != 'has_ioc'")
    for row in cur:
        adj[row["source"]].add(row["target"])
        adj[row["target"]].add(row["source"])

    conn.close()
    return adj, node_depth, node_orgs


def load_has_ioc_reports():
    logger.info("Loading source_reports...")
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
                existing = set(node_reports[tgt])
                existing.update(reports)
                node_reports[tgt] = sorted(existing)
            else:
                node_reports[tgt] = sorted(reports)
    return node_reports


def precompute_l1_to_l0(adj, node_depth):
    l1_to_l0 = defaultdict(set)
    l0_set = {nid for nid, d in node_depth.items() if d == 0}
    for l1_node, neighbors in adj.items():
        if node_depth.get(l1_node) != 1:
            continue
        for n in neighbors:
            if n in l0_set:
                l1_to_l0[l1_node].add(n)
    return l1_to_l0


def get_l0_iocs_with_orgs(node_depth, node_orgs):
    """取得所有 L0 IoC 及其 org（排除 apt 節點、多 org 共享的 IoC）"""
    iocs = []
    for nid, d in node_depth.items():
        if d != 0:
            continue
        if nid.startswith("apt_"):
            continue
        orgs = node_orgs.get(nid, set())
        if len(orgs) == 1:
            iocs.append((nid, list(orgs)[0]))
    return iocs


def run_per_ioc_loo(l0_iocs, adj, node_depth, node_orgs, l1_to_l0):
    """Per-IoC leave-one-out（移除 1 個 IoC + 獨佔 L1）"""
    results = []
    for v_id, v_org in l0_iocs:
        v_neighbors = adj.get(v_id, set())
        exclusive_l1 = {n for n in v_neighbors
                        if node_depth.get(n) == 1 and l1_to_l0.get(n, set()) == {v_id}}
        removed = {v_id} | exclusive_l1

        matched = v_neighbors - removed
        if not matched:
            results.append({"match": False, "correct": False, "true_org": v_org})
            continue

        org_votes = Counter()
        for n in matched:
            for org in node_orgs.get(n, set()):
                org_votes[org] += 1

        pred = org_votes.most_common(1)[0][0] if org_votes else None
        results.append({"match": True, "correct": pred == v_org, "true_org": v_org, "pred": pred})

    return results


def run_per_report_loo(l0_iocs, adj, node_depth, node_orgs, l1_to_l0, node_reports):
    """Per-Report leave-one-out（移除整份報告的所有 IoC + 獨佔 L1）"""

    # 建立 report → IoC 映射
    report_to_iocs = defaultdict(list)
    ioc_to_report = {}
    for v_id, v_org in l0_iocs:
        reports = node_reports.get(v_id, [])
        key = reports[0] if reports else f"__no_report_{v_id}"
        report_to_iocs[key].append((v_id, v_org))
        ioc_to_report[v_id] = key

    logger.info(f"  {len(report_to_iocs)} unique reports")

    results = []

    for report_key, report_iocs in report_to_iocs.items():
        # 1. 收集該報告的所有 IoC
        report_ioc_set = {v_id for v_id, _ in report_iocs}

        # 2. 找出這些 IoC 的獨佔 L1 鄰居
        #    獨佔 = 該 L1 節點連接的所有 L0 都在這份報告裡
        exclusive_l1 = set()
        for v_id in report_ioc_set:
            for n in adj.get(v_id, set()):
                if node_depth.get(n) != 1:
                    continue
                l0_parents = l1_to_l0.get(n, set())
                if l0_parents and l0_parents.issubset(report_ioc_set):
                    exclusive_l1.add(n)

        removed = report_ioc_set | exclusive_l1

        # 3. 對每個被移除的 IoC，測試 overlap
        for v_id, v_org in report_iocs:
            v_neighbors = adj.get(v_id, set())
            matched = v_neighbors - removed

            if not matched:
                results.append({
                    "match": False, "correct": False, "true_org": v_org,
                    "report": report_key[:80], "n_report_iocs": len(report_iocs),
                    "n_exclusive_l1": len(exclusive_l1),
                })
                continue

            org_votes = Counter()
            for n in matched:
                for org in node_orgs.get(n, set()):
                    org_votes[org] += 1

            pred = org_votes.most_common(1)[0][0] if org_votes else None
            results.append({
                "match": True, "correct": pred == v_org, "true_org": v_org,
                "pred": pred, "report": report_key[:80],
                "n_report_iocs": len(report_iocs),
                "n_exclusive_l1": len(exclusive_l1),
                "n_matched": len(matched),
                "top_votes": org_votes.most_common(3),
            })

    return results


def print_results(label, results):
    total = len(results)
    matched = [r for r in results if r["match"]]
    correct = [r for r in results if r.get("correct")]

    print(f"\n{'='*70}")
    print(f"{label}")
    print(f"{'='*70}")
    print(f"  Total IoCs: {total:,}")
    print(f"  有 match: {len(matched):,}/{total:,} ({len(matched)/total*100:.1f}%)")
    print(f"  歸因正確: {len(correct):,}/{len(matched):,} "
          f"({len(correct)/len(matched)*100:.1f}%)" if matched else "  N/A")
    print(f"  Overall (correct/total): {len(correct):,}/{total:,} "
          f"({len(correct)/total*100:.1f}%)")

    # Per-org
    org_results = defaultdict(lambda: {"total": 0, "matched": 0, "correct": 0})
    for r in results:
        org = r["true_org"]
        org_results[org]["total"] += 1
        if r["match"]:
            org_results[org]["matched"] += 1
        if r.get("correct"):
            org_results[org]["correct"] += 1

    print(f"\n  {'Org':<20} {'IoCs':>5} {'Match%':>8} {'Acc%':>8} {'Overall%':>9}")
    print(f"  {'-'*20} {'-'*5} {'-'*8} {'-'*8} {'-'*9}")
    for org in sorted(org_results.keys()):
        d = org_results[org]
        match_pct = d["matched"] / d["total"] * 100 if d["total"] else 0
        acc_pct = d["correct"] / d["matched"] * 100 if d["matched"] else 0
        overall_pct = d["correct"] / d["total"] * 100 if d["total"] else 0
        print(f"  {org:<20} {d['total']:>5} {match_pct:>7.1f}% {acc_pct:>7.1f}% {overall_pct:>8.1f}%")


def print_comparison(per_ioc, per_report):
    """比較 per-IoC 和 per-report 的差異"""
    print(f"\n{'='*70}")
    print("比較：Per-IoC vs Per-Report Leave-One-Out")
    print(f"{'='*70}")

    for label, results in [("Per-IoC", per_ioc), ("Per-Report", per_report)]:
        total = len(results)
        matched = sum(1 for r in results if r["match"])
        correct = sum(1 for r in results if r.get("correct"))
        acc = correct / matched * 100 if matched else 0
        print(f"  {label:<15} match={matched}/{total} ({matched/total*100:.1f}%)  "
              f"acc={correct}/{matched} ({acc:.1f}%)  "
              f"overall={correct}/{total} ({correct/total*100:.1f}%)")

    # Per-org delta
    org_ioc = defaultdict(lambda: {"matched": 0, "correct": 0, "total": 0})
    org_report = defaultdict(lambda: {"matched": 0, "correct": 0, "total": 0})

    for r in per_ioc:
        org_ioc[r["true_org"]]["total"] += 1
        if r["match"]: org_ioc[r["true_org"]]["matched"] += 1
        if r.get("correct"): org_ioc[r["true_org"]]["correct"] += 1

    for r in per_report:
        org_report[r["true_org"]]["total"] += 1
        if r["match"]: org_report[r["true_org"]]["matched"] += 1
        if r.get("correct"): org_report[r["true_org"]]["correct"] += 1

    print(f"\n  {'Org':<20} {'IoC-Match%':>10} {'Rpt-Match%':>10} {'Δ-Match':>8} │ "
          f"{'IoC-Acc%':>8} {'Rpt-Acc%':>8} {'Δ-Acc':>7}")
    print(f"  {'-'*20} {'-'*10} {'-'*10} {'-'*8} │ {'-'*8} {'-'*8} {'-'*7}")

    all_orgs = sorted(set(list(org_ioc.keys()) + list(org_report.keys())))
    for org in all_orgs:
        di = org_ioc[org]
        dr = org_report[org]
        mi = di["matched"] / di["total"] * 100 if di["total"] else 0
        mr = dr["matched"] / dr["total"] * 100 if dr["total"] else 0
        ai = di["correct"] / di["matched"] * 100 if di["matched"] else 0
        ar = dr["correct"] / dr["matched"] * 100 if dr["matched"] else 0
        print(f"  {org:<20} {mi:>9.1f}% {mr:>9.1f}% {mr-mi:>+7.1f}% │ "
              f"{ai:>7.1f}% {ar:>7.1f}% {ar-ai:>+6.1f}%")


def print_failure_analysis(results):
    """分析 per-report 失敗的案例"""
    print(f"\n{'='*70}")
    print("Per-Report 失敗分析")
    print(f"{'='*70}")

    # 無 match 的報告
    no_match_reports = defaultdict(list)
    for r in results:
        if not r["match"]:
            no_match_reports[r["report"]].append(r)

    if no_match_reports:
        print(f"\n  完全無 match 的報告（所有 IoC 都沒有跨 campaign 連結）:")
        for report, iocs in sorted(no_match_reports.items(), key=lambda x: -len(x[1]))[:15]:
            orgs = set(r["true_org"] for r in iocs)
            excl = iocs[0].get("n_exclusive_l1", "?")
            print(f"    {report[:70]}...")
            print(f"      {len(iocs)} IoCs, org={orgs}, exclusive_L1_removed={excl}")

    # 有 match 但歸錯的
    wrong = [r for r in results if r["match"] and not r.get("correct")]
    if wrong:
        print(f"\n  有 match 但歸因錯誤 ({len(wrong)} 個)，前 10 個:")
        for r in wrong[:10]:
            print(f"    true={r['true_org']}, pred={r.get('pred')}, "
                  f"matched={r.get('n_matched', '?')}, votes={r.get('top_votes', [])}")


def main():
    logger.info("Loading graph...")
    adj, node_depth, node_orgs = load_graph()
    logger.info("Loading reports...")
    node_reports = load_has_ioc_reports()

    logger.info("Precomputing L1→L0 mapping...")
    l1_to_l0 = precompute_l1_to_l0(adj, node_depth)

    l0_iocs = get_l0_iocs_with_orgs(node_depth, node_orgs)
    logger.info(f"L0 IoCs: {len(l0_iocs)}")

    logger.info("\n=== Per-IoC Leave-One-Out ===")
    per_ioc = run_per_ioc_loo(l0_iocs, adj, node_depth, node_orgs, l1_to_l0)
    print_results("Per-IoC Leave-One-Out (baseline)", per_ioc)

    logger.info("\n=== Per-Report Leave-One-Out ===")
    per_report = run_per_report_loo(l0_iocs, adj, node_depth, node_orgs, l1_to_l0, node_reports)
    print_results("Per-Report Leave-One-Out (cross-campaign)", per_report)

    print_comparison(per_ioc, per_report)
    print_failure_analysis(per_report)

    # Save
    output = {
        "per_ioc": {
            "total": len(per_ioc),
            "matched": sum(1 for r in per_ioc if r["match"]),
            "correct": sum(1 for r in per_ioc if r.get("correct")),
        },
        "per_report": {
            "total": len(per_report),
            "matched": sum(1 for r in per_report if r["match"]),
            "correct": sum(1 for r in per_report if r.get("correct")),
        },
    }
    out_path = Path("scripts/results/eval_overlap_by_report.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2)
    logger.info(f"\nSaved to {out_path}")


if __name__ == "__main__":
    main()
