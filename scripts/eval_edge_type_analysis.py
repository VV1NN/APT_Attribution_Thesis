#!/usr/bin/env python3
"""
Edge-Type-Aware Weighted Voting + Coverage Gap 分析。

Step 1: 統計每種 edge type 在 per-report leave-one-out 下的歸因精度（precision），
        用 precision 作為 voting weight 重跑歸因。
Step 2: 分析 no-match IoC 的原因（無鄰居 / 鄰居不在 KG / 鄰居被 LOO 移除）。

基於 eval_overlap_by_report.py 的 per-report LOO 框架。
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

# ── VT relationship cache paths ──
VT_REL_CACHE = Path("vt_relationships/.cache")


def load_graph_with_edge_types():
    """載入圖，adj 紀錄邊的 relationship type。"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    node_depth = {}
    for row in conn.execute("SELECT id, depth FROM nodes"):
        node_depth[row["id"]] = row["depth"]

    node_orgs = defaultdict(set)
    for row in conn.execute("SELECT node_id, org FROM node_orgs"):
        node_orgs[row["node_id"]].add(row["org"])

    # adj[node] = set of neighbor ids (for compatibility)
    adj = defaultdict(set)
    # edge_types[(src, tgt)] = set of relationship types
    edge_types = defaultdict(set)

    for row in conn.execute(
        "SELECT source, target, relationship FROM edges WHERE relationship <> 'has_ioc'"
    ):
        s, t, r = row["source"], row["target"], row["relationship"]
        adj[s].add(t)
        adj[t].add(s)
        edge_types[(s, t)].add(r)
        edge_types[(t, s)].add(r)

    conn.close()
    return adj, node_depth, node_orgs, edge_types


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
                existing = set(node_reports[tgt])
                existing.update(reports)
                node_reports[tgt] = sorted(existing)
            else:
                node_reports[tgt] = sorted(reports)
    return node_reports


def load_vt_neighbor_cache():
    """載入 VT relationship cache，取得每個 IoC 的 VT 鄰居清單。
    用於 coverage 分析：判斷「無 match」是 VT 沒有鄰居還是鄰居不在 KG。
    """
    vt_neighbors = defaultdict(set)

    if not VT_REL_CACHE.exists():
        logger.warning(f"VT cache not found: {VT_REL_CACHE}")
        return vt_neighbors

    for cache_file in VT_REL_CACHE.glob("*.json"):
        try:
            with open(cache_file) as f:
                data = json.load(f)
        except (json.JSONDecodeError, IOError):
            continue

        vt_id = data.get("id", "")
        vt_type = data.get("type", "")

        # 從 cache 取出 IoC 的 VT ID → 轉成我們的 node ID
        if vt_type == "file":
            node_id = f"file_{vt_id}"
        elif vt_type == "domain":
            node_id = f"domain_{vt_id}"
        elif vt_type == "ip_address":
            node_id = f"ip_{vt_id}"
        else:
            continue

        # 收集 VT 回傳的所有鄰居
        for rel_type, items in data.get("relationships", {}).items():
            for item in items:
                item_id = item.get("id", "")
                item_type = item.get("type", "")
                if item_type == "file":
                    vt_neighbors[node_id].add(f"file_{item_id}")
                elif item_type == "domain":
                    vt_neighbors[node_id].add(f"domain_{item_id}")
                elif item_type == "ip_address":
                    vt_neighbors[node_id].add(f"ip_{item_id}")
                elif item_type == "resolution":
                    # resolution 物件含 ip_address_last_analysis_date 等
                    # 但實際的 IP 在 item 的 attributes 中
                    pass

    return vt_neighbors


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
    iocs = []
    for nid, d in node_depth.items():
        if d != 0 or nid.startswith("apt_"):
            continue
        orgs = node_orgs.get(nid, set())
        if len(orgs) == 1:
            iocs.append((nid, list(orgs)[0]))
    return iocs


def run_per_report_loo_with_edge_analysis(
    l0_iocs, adj, node_depth, node_orgs, l1_to_l0, node_reports, edge_types
):
    """Per-Report LOO，同時記錄每個 match 的 edge type。"""

    # report → IoC 映射
    report_to_iocs = defaultdict(list)
    for v_id, v_org in l0_iocs:
        reports = node_reports.get(v_id, [])
        key = reports[0] if reports else f"__no_report_{v_id}"
        report_to_iocs[key].append((v_id, v_org))

    logger.info(f"  {len(report_to_iocs)} unique reports, {len(l0_iocs)} IoCs")

    # ── Step 1: Edge type 歸因力 ──
    # 統計每種 edge type 產生的 org vote 中，投給正確 org 的比例
    # correct_vote = matched neighbor 透過 edge_type 投給 true_org 的票數
    # wrong_vote = matched neighbor 透過 edge_type 投給其他 org 的票數
    edge_type_stats = defaultdict(lambda: {"correct_votes": 0, "wrong_votes": 0, "total_votes": 0})

    # ── Step 2: No-match 原因 ──
    no_match_reasons = Counter()
    # "no_vt_neighbors": VT 沒回傳鄰居
    # "neighbors_not_in_kg": 有 VT 鄰居但都不在 KG
    # "all_removed_by_loo": 鄰居在 KG 但被 LOO 移除

    all_kg_nodes = set(node_depth.keys())

    results_uniform = []  # uniform voting (baseline)
    results_weighted = []  # edge-type weighted voting
    results_idf = []  # IDF weighted voting
    results_eidf = []  # edge × IDF weighted voting

    for report_key, report_iocs in report_to_iocs.items():
        report_ioc_set = {v_id for v_id, _ in report_iocs}

        # 找獨佔 L1 鄰居
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
                # ── Step 2: 診斷 no-match 原因 ──
                if not v_neighbors:
                    no_match_reasons["no_kg_neighbors"] += 1
                else:
                    # 有 KG 鄰居但全被移除
                    # 檢查是否所有鄰居都在 removed set 裡
                    in_removed = v_neighbors & removed
                    if in_removed == v_neighbors:
                        no_match_reasons["all_removed_by_loo"] += 1
                    else:
                        # 不該發生（matched = v_neighbors - removed 已排除）
                        no_match_reasons["other"] += 1

                r = {
                    "match": False,
                    "correct": False,
                    "true_org": v_org,
                    "report": report_key[:80],
                    "n_neighbors": len(v_neighbors),
                    "n_removed": len(v_neighbors & removed),
                }
                results_uniform.append(r)
                results_weighted.append(r.copy())
                results_idf.append(r.copy())
                results_eidf.append(r.copy())
                continue

            # ── Step 1: 收集 edge type 資訊 ──
            # 對每個 matched neighbor，記錄連接的 edge types
            edge_type_votes = defaultdict(lambda: Counter())  # edge_type → org Counter
            org_votes_uniform = Counter()

            for n in matched:
                n_orgs = node_orgs.get(n, set())
                etypes = edge_types.get((v_id, n), set())

                for org in n_orgs:
                    org_votes_uniform[org] += 1

                for etype in etypes:
                    for org in n_orgs:
                        edge_type_votes[etype][org] += 1

                    # 統計每種 edge type 產生的 org vote 品質
                    # 一個 neighbor 可能屬於多個 org → 產生多票
                    for org in n_orgs:
                        edge_type_stats[etype]["total_votes"] += 1
                        if org == v_org:
                            edge_type_stats[etype]["correct_votes"] += 1
                        else:
                            edge_type_stats[etype]["wrong_votes"] += 1

            # Uniform vote
            pred_uniform = org_votes_uniform.most_common(1)[0][0]
            results_uniform.append({
                "match": True,
                "correct": pred_uniform == v_org,
                "true_org": v_org,
                "pred": pred_uniform,
                "report": report_key[:80],
                "n_matched": len(matched),
                "top_votes": org_votes_uniform.most_common(3),
            })

            # Weighted vote（先用 placeholder，第二遍填入）
            results_weighted.append({
                "match": True,
                "true_org": v_org,
                "report": report_key[:80],
                "n_matched": len(matched),
                "_edge_type_votes": dict(edge_type_votes),
            })

            # IDF vote — neighbor data for 1/|orgs| weighting
            neighbor_data = [
                (n, node_orgs.get(n, set())) for n in matched
            ]
            results_idf.append({
                "match": True,
                "true_org": v_org,
                "report": report_key[:80],
                "n_matched": len(matched),
                "_neighbor_data": neighbor_data,
                "_neighbor_data_copy": list(neighbor_data),  # for filter sweep
            })

            # Edge × IDF vote
            neighbor_edge_data = [
                (n, node_orgs.get(n, set()), edge_types.get((v_id, n), set()))
                for n in matched
            ]
            results_eidf.append({
                "match": True,
                "true_org": v_org,
                "report": report_key[:80],
                "n_matched": len(matched),
                "_neighbor_edge_data": neighbor_edge_data,
            })

    return (
        results_uniform,
        results_weighted,
        results_idf,
        results_eidf,
        edge_type_stats,
        no_match_reasons,
    )


def apply_weighted_voting(results_weighted, edge_type_precision):
    """用 edge type precision 作為 weight 重新投票。"""
    for r in results_weighted:
        if not r.get("match"):
            r["correct"] = False
            continue

        etv = r.pop("_edge_type_votes", {})
        org_scores = Counter()
        for etype, org_counter in etv.items():
            weight = edge_type_precision.get(etype, 0.5)
            for org, count in org_counter.items():
                org_scores[org] += count * weight

        if org_scores:
            pred = org_scores.most_common(1)[0][0]
            r["pred"] = pred
            r["correct"] = pred == r["true_org"]
            r["top_scores"] = org_scores.most_common(3)
        else:
            r["correct"] = False


def apply_idf_weighted_voting(results_idf, node_orgs):
    """用 1/|orgs(neighbor)| 作為 IDF-like weight：
    只屬於 1 個 org 的 neighbor 權重=1，屬於 5 個 org 的權重=0.2。
    """
    for r in results_idf:
        if not r.get("match"):
            r["correct"] = False
            continue

        neighbor_data = r.pop("_neighbor_data", [])
        org_scores = Counter()
        for n_id, n_orgs_set in neighbor_data:
            weight = 1.0 / len(n_orgs_set) if n_orgs_set else 0
            for org in n_orgs_set:
                org_scores[org] += weight

        if org_scores:
            pred = org_scores.most_common(1)[0][0]
            r["pred"] = pred
            r["correct"] = pred == r["true_org"]
            r["top_scores"] = org_scores.most_common(3)
        else:
            r["correct"] = False


def apply_edge_idf_weighted_voting(results_eidf, node_orgs, edge_type_precision):
    """Edge type precision × IDF weight 結合。"""
    for r in results_eidf:
        if not r.get("match"):
            r["correct"] = False
            continue

        neighbor_edge_data = r.pop("_neighbor_edge_data", [])
        org_scores = Counter()
        for n_id, n_orgs_set, etypes in neighbor_edge_data:
            idf = 1.0 / len(n_orgs_set) if n_orgs_set else 0
            # 取該 neighbor 的最佳 edge type precision
            best_etp = max(
                (edge_type_precision.get(e, 0.1) for e in etypes), default=0.1
            )
            weight = idf * best_etp
            for org in n_orgs_set:
                org_scores[org] += weight

        if org_scores:
            pred = org_scores.most_common(1)[0][0]
            r["pred"] = pred
            r["correct"] = pred == r["true_org"]
            r["top_scores"] = org_scores.most_common(3)
        else:
            r["correct"] = False


def analyze_no_match_deeper(l0_iocs, adj, node_depth, node_reports):
    """更深入分析 no-match IoC：有沒有 VT 鄰居、鄰居在不在 KG。"""
    report_to_iocs = defaultdict(list)
    for v_id, v_org in l0_iocs:
        reports = node_reports.get(v_id, [])
        key = reports[0] if reports else f"__no_report_{v_id}"
        report_to_iocs[key].append((v_id, v_org))

    all_kg_nodes = set(node_depth.keys())
    l1_to_l0 = defaultdict(set)
    l0_set = {nid for nid, d in node_depth.items() if d == 0}
    for n, neighbors in adj.items():
        if node_depth.get(n) != 1:
            continue
        for nb in neighbors:
            if nb in l0_set:
                l1_to_l0[n].add(nb)

    # 統計各類型 IoC 的 no-match 細分
    type_stats = defaultdict(lambda: {
        "total": 0,
        "no_kg_neighbors": 0,
        "all_exclusive_removed": 0,
        "has_match": 0,
    })

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
            ioc_type = v_id.split("_")[0]  # file, domain, ip
            type_stats[ioc_type]["total"] += 1

            v_neighbors = adj.get(v_id, set())
            matched = v_neighbors - removed

            if matched:
                type_stats[ioc_type]["has_match"] += 1
            elif not v_neighbors:
                type_stats[ioc_type]["no_kg_neighbors"] += 1
            else:
                type_stats[ioc_type]["all_exclusive_removed"] += 1

    return type_stats


def print_edge_type_table(edge_type_stats):
    print(f"\n{'='*70}")
    print("Step 1: Edge Type 歸因力（per-vote signal-to-noise ratio）")
    print(f"{'='*70}")
    print(
        f"  {'Edge Type':<22} {'Votes':>7} {'Correct':>8} {'Wrong':>7} "
        f"{'Precision':>10} {'SNR':>7}"
    )
    print(f"  {'-'*22} {'-'*7} {'-'*8} {'-'*7} {'-'*10} {'-'*7}")

    precision = {}
    for etype in sorted(
        edge_type_stats.keys(),
        key=lambda e: -edge_type_stats[e]["total_votes"],
    ):
        s = edge_type_stats[etype]
        p = s["correct_votes"] / s["total_votes"] if s["total_votes"] else 0
        snr = (
            s["correct_votes"] / s["wrong_votes"]
            if s["wrong_votes"]
            else float("inf")
        )
        precision[etype] = p
        snr_str = f"{snr:>6.1f}x" if snr != float("inf") else "    ∞"
        print(
            f"  {etype:<22} {s['total_votes']:>7,} {s['correct_votes']:>8,} "
            f"{s['wrong_votes']:>7,} {p:>9.1%} {snr_str}"
        )

    return precision


def print_coverage_analysis(no_match_reasons, total_iocs, type_stats):
    print(f"\n{'='*70}")
    print("Step 2: Coverage Gap 分析（為什麼 IoC 沒有 match）")
    print(f"{'='*70}")

    no_match_total = sum(no_match_reasons.values())
    print(f"\n  總 IoCs: {total_iocs:,}")
    print(f"  有 match: {total_iocs - no_match_total:,} ({(total_iocs - no_match_total)/total_iocs*100:.1f}%)")
    print(f"  無 match: {no_match_total:,} ({no_match_total/total_iocs*100:.1f}%)")
    print()
    print(f"  無 match 原因分佈:")
    for reason, count in no_match_reasons.most_common():
        pct = count / no_match_total * 100 if no_match_total else 0
        label = {
            "no_kg_neighbors": "KG 中完全沒有鄰居（VT 無回傳 / IoC 孤立）",
            "all_removed_by_loo": "有鄰居但全被 LOO 移除（所有鄰居都是同報告獨佔）",
            "other": "其他",
        }.get(reason, reason)
        print(f"    {label}: {count:,} ({pct:.1f}%)")

    print(f"\n  各 IoC 類型的 coverage 細分:")
    print(
        f"  {'Type':<10} {'Total':>7} {'Match':>7} {'No-Nbr':>8} {'LOO-Rm':>8} {'Match%':>8}"
    )
    print(f"  {'-'*10} {'-'*7} {'-'*7} {'-'*8} {'-'*8} {'-'*8}")
    for t in sorted(type_stats.keys()):
        s = type_stats[t]
        match_pct = s["has_match"] / s["total"] * 100 if s["total"] else 0
        print(
            f"  {t:<10} {s['total']:>7,} {s['has_match']:>7,} "
            f"{s['no_kg_neighbors']:>8,} {s['all_exclusive_removed']:>8,} {match_pct:>7.1f}%"
        )


def print_voting_comparison(strategies):
    """strategies: list of (label, results)"""
    print(f"\n{'='*70}")
    print("Voting 策略比較")
    print(f"{'='*70}")

    for label, results in strategies:
        total = len(results)
        matched = [r for r in results if r["match"]]
        correct = [r for r in results if r.get("correct")]
        acc = len(correct) / len(matched) * 100 if matched else 0
        overall = len(correct) / total * 100 if total else 0
        print(
            f"  {label:<22} match={len(matched):,}/{total:,} ({len(matched)/total*100:.1f}%)  "
            f"acc={len(correct):,}/{len(matched):,} ({acc:.1f}%)  "
            f"overall={len(correct):,}/{total:,} ({overall:.1f}%)"
        )

    # Per-org comparison table
    org_data = {}  # org → {strategy_label: acc%}
    org_totals = {}
    for label, results in strategies:
        per_org = defaultdict(lambda: {"total": 0, "matched": 0, "correct": 0})
        for r in results:
            o = r["true_org"]
            per_org[o]["total"] += 1
            if r["match"]:
                per_org[o]["matched"] += 1
            if r.get("correct"):
                per_org[o]["correct"] += 1
        for o, d in per_org.items():
            if o not in org_data:
                org_data[o] = {}
                org_totals[o] = d["total"]
            org_data[o][label] = (
                d["correct"] / d["matched"] * 100 if d["matched"] else 0
            )

    labels = [l for l, _ in strategies]
    header = f"  {'Org':<20} {'IoCs':>5} │ " + " ".join(f"{l[:8]:>8}" for l in labels) + f" {'Best Δ':>8}"
    print(f"\n{header}")
    print(f"  {'-'*20} {'-'*5} │ " + " ".join([f"{'-'*8}"] * len(labels)) + f" {'-'*8}")

    for org in sorted(org_data.keys()):
        vals = [org_data[org].get(l, 0) for l in labels]
        base = vals[0]  # uniform as baseline
        best_delta = max(v - base for v in vals[1:]) if len(vals) > 1 else 0
        marker = " ✦" if best_delta > 3 else ""
        vals_str = " ".join(f"{v:>7.1f}%" for v in vals)
        print(
            f"  {org:<20} {org_totals[org]:>5} │ {vals_str} {best_delta:>+7.1f}%{marker}"
        )


def main():
    logger.info("Loading graph with edge types...")
    adj, node_depth, node_orgs, edge_types = load_graph_with_edge_types()

    logger.info("Loading reports...")
    node_reports = load_has_ioc_reports()

    logger.info("Precomputing L1→L0 mapping...")
    l1_to_l0 = precompute_l1_to_l0(adj, node_depth)

    l0_iocs = get_l0_iocs_with_orgs(node_depth, node_orgs)
    logger.info(f"L0 IoCs: {len(l0_iocs)}")

    # ── 主分析 ──
    logger.info("Running per-report LOO with edge type analysis...")
    uniform, weighted, idf, eidf, edge_type_stats, no_match_reasons = (
        run_per_report_loo_with_edge_analysis(
            l0_iocs, adj, node_depth, node_orgs, l1_to_l0, node_reports, edge_types
        )
    )

    # Step 1: Edge type precision table
    precision = print_edge_type_table(edge_type_stats)

    # Apply voting strategies
    apply_weighted_voting(weighted, precision)
    apply_idf_weighted_voting(idf, node_orgs)
    apply_edge_idf_weighted_voting(eidf, node_orgs, precision)

    # 比較基本策略
    print_voting_comparison([
        ("Uniform", uniform),
        ("EdgeType", weighted),
        ("IDF", idf),
        ("Edge×IDF", eidf),
    ])

    # ── Step 1b: Max-org filter sweep ──
    # 只接受屬於 ≤ k 個 org 的 neighbor 的投票
    print(f"\n{'='*70}")
    print("Step 1b: Max-Org Filter Sweep（只接受 ≤ k 個 org 的 neighbor 投票）")
    print(f"{'='*70}")
    print(f"  {'max_orgs':>9} {'match':>7} {'correct':>8} {'acc%':>7} {'overall%':>9}")
    print(f"  {'-'*9} {'-'*7} {'-'*8} {'-'*7} {'-'*9}")

    filter_results = {}
    for max_k in [1, 2, 3, 4, 5, 10, 999]:
        n_match = 0
        n_correct = 0
        for r in idf:
            if not r.get("match"):
                continue
            # re-vote with only neighbors having ≤ k orgs
            nbr_data = r.get("_neighbor_data_copy", [])
            org_votes = Counter()
            for n_id, n_orgs_set in nbr_data:
                if len(n_orgs_set) <= max_k:
                    for org in n_orgs_set:
                        org_votes[org] += 1
            if org_votes:
                n_match += 1
                pred = org_votes.most_common(1)[0][0]
                if pred == r["true_org"]:
                    n_correct += 1

        total = len(l0_iocs)
        acc = n_correct / n_match * 100 if n_match else 0
        overall = n_correct / total * 100
        label = f"≤{max_k}" if max_k < 999 else "all"
        print(f"  {label:>9} {n_match:>7,} {n_correct:>8,} {acc:>6.1f}% {overall:>8.1f}%")
        filter_results[max_k] = {"match": n_match, "correct": n_correct}

    # Step 2: Coverage gap
    type_stats = analyze_no_match_deeper(l0_iocs, adj, node_depth, node_reports)
    print_coverage_analysis(no_match_reasons, len(l0_iocs), type_stats)

    # ── Save results ──
    output = {
        "edge_type_precision": {
            etype: {
                "total_votes": s["total_votes"],
                "correct_votes": s["correct_votes"],
                "wrong_votes": s["wrong_votes"],
                "precision": round(s["correct_votes"] / s["total_votes"], 4)
                if s["total_votes"]
                else 0,
            }
            for etype, s in edge_type_stats.items()
        },
        "no_match_reasons": dict(no_match_reasons),
        "coverage_by_type": {
            t: dict(s) for t, s in type_stats.items()
        },
        "strategies": {
            label: {
                "total": len(results),
                "matched": sum(1 for r in results if r["match"]),
                "correct": sum(1 for r in results if r.get("correct")),
            }
            for label, results in [
                ("uniform", uniform),
                ("edge_type", weighted),
                ("idf", idf),
                ("edge_idf", eidf),
            ]
        },
    }

    out_path = Path("scripts/results/eval_edge_type_analysis.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    logger.info(f"Saved to {out_path}")


if __name__ == "__main__":
    main()
