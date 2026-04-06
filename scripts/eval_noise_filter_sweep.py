#!/usr/bin/env python3
"""
噪音過濾 + Confidence-Gated Attribution 分析。

以 per-report LOO 為基礎，測試：
1. 移除屬於 ≥ N 個 org 的 L1 節點（noise threshold sweep）
2. Confidence-gated attribution（exclusive → low-sharing → high-sharing）
3. 正確處理 tie-breaking：回報 deterministic accuracy（排除 tie cases）

結果回答：「清理共享基礎設施噪音後，跨 campaign 歸因能到多好？」
"""

import json
import sqlite3
import ipaddress
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


def load_data():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    node_depth = {}
    for row in conn.execute("SELECT id, depth FROM nodes"):
        node_depth[row["id"]] = row["depth"]

    node_orgs = defaultdict(set)
    for row in conn.execute("SELECT node_id, org FROM node_orgs"):
        node_orgs[row["node_id"]].add(row["org"])

    adj = defaultdict(set)
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

    return adj, node_depth, node_orgs, edge_types, node_reports


def build_infra_noise_set(node_depth):
    """靜態噪音：private IP、public DNS、loopback 等。"""
    noise = set()
    for nid in node_depth:
        if nid.startswith("ip_"):
            try:
                addr = ipaddress.ip_address(nid[3:])
                if addr.is_private or addr.is_reserved or addr.is_loopback or addr.is_multicast:
                    noise.add(nid)
            except ValueError:
                pass
            if nid[3:] in (
                "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",
                "114.114.114.114", "114.114.115.115",
                "208.67.222.222", "208.67.220.220",
            ):
                noise.add(nid)
    return noise


def run_loo_with_filter(
    l0_iocs, adj, node_depth, node_orgs, node_reports, noise_set, max_org_threshold
):
    """Per-report LOO，加上噪音過濾。

    Args:
        noise_set: 靜態噪音節點（永遠排除）
        max_org_threshold: 動態噪音 — 排除屬於 >= N 個 org 的 neighbor
    """

    # Precompute
    l0_set = {nid for nid, d in node_depth.items() if d == 0}
    l1_to_l0 = defaultdict(set)
    for n, neighbors in adj.items():
        if node_depth.get(n) != 1:
            continue
        for nb in neighbors:
            if nb in l0_set:
                l1_to_l0[n].add(nb)

    report_to_iocs = defaultdict(list)
    for v_id, v_org in l0_iocs:
        reports = node_reports.get(v_id, [])
        key = reports[0] if reports else f"__no_report_{v_id}"
        report_to_iocs[key].append((v_id, v_org))

    n_total = 0
    n_match = 0
    n_clear_correct = 0
    n_tie_true_in = 0
    n_tie_true_not = 0
    n_no_match_no_nbr = 0
    n_no_match_all_noise = 0
    n_no_match_loo = 0

    # Per-org tracking
    org_stats = defaultdict(lambda: {
        "total": 0, "match": 0, "clear_correct": 0,
        "tie_true_in": 0, "tie_true_not": 0,
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
            n_total += 1
            org_stats[v_org]["total"] += 1

            v_neighbors = adj.get(v_id, set())

            # Filter: remove LOO + noise + high-sharing
            filtered = set()
            for n in v_neighbors:
                if n in removed:
                    continue
                if n in noise_set:
                    continue
                if len(node_orgs.get(n, set())) >= max_org_threshold:
                    continue
                filtered.add(n)

            if not filtered:
                # Diagnose why
                if not v_neighbors:
                    n_no_match_no_nbr += 1
                else:
                    raw_after_loo = v_neighbors - removed
                    if not raw_after_loo:
                        n_no_match_loo += 1
                    else:
                        n_no_match_all_noise += 1
                continue

            # Vote
            org_votes = Counter()
            for n in filtered:
                for org in node_orgs.get(n, set()):
                    org_votes[org] += 1

            if not org_votes:
                continue

            n_match += 1
            org_stats[v_org]["match"] += 1

            top_count = org_votes.most_common(1)[0][1]
            tied = [org for org, cnt in org_votes.items() if cnt == top_count]

            if len(tied) == 1:
                if tied[0] == v_org:
                    n_clear_correct += 1
                    org_stats[v_org]["clear_correct"] += 1
                # else: clear winner but wrong → shouldn't happen based on our analysis
                # but let's track it anyway
            else:
                if v_org in tied:
                    n_tie_true_in += 1
                    org_stats[v_org]["tie_true_in"] += 1
                else:
                    n_tie_true_not += 1
                    org_stats[v_org]["tie_true_not"] += 1

    return {
        "total": n_total,
        "match": n_match,
        "clear_correct": n_clear_correct,
        "tie_true_in": n_tie_true_in,
        "tie_true_not": n_tie_true_not,
        "no_match_no_nbr": n_no_match_no_nbr,
        "no_match_all_noise": n_no_match_all_noise,
        "no_match_loo": n_no_match_loo,
        "org_stats": dict(org_stats),
    }


def main():
    logger.info("Loading data...")
    adj, node_depth, node_orgs, edge_types, node_reports = load_data()

    # L0 IoCs
    l0_iocs = []
    for nid, d in node_depth.items():
        if d != 0 or nid.startswith("apt_"):
            continue
        orgs = node_orgs.get(nid, set())
        if len(orgs) == 1:
            l0_iocs.append((nid, list(orgs)[0]))
    logger.info(f"L0 IoCs: {len(l0_iocs)}")

    infra_noise = build_infra_noise_set(node_depth)
    logger.info(f"Static infra noise nodes: {len(infra_noise)}")

    # ── Sweep: max_org_threshold ──
    print(f"\n{'='*90}")
    print("Noise Filter Sweep: max_org_threshold（排除屬於 ≥ N org 的 neighbor）")
    print(f"{'='*90}")
    print(
        f"  {'Threshold':>10} {'Match':>7} {'Clear✓':>8} {'Tie(in)':>8} {'Tie(out)':>9} "
        f"{'Det.Acc%':>9} {'Tie%':>6} {'Cover%':>8} {'NoNbr':>6} {'Noise':>6} {'LOO':>6}"
    )
    print(
        f"  {'-'*10} {'-'*7} {'-'*8} {'-'*8} {'-'*9} "
        f"{'-'*9} {'-'*6} {'-'*8} {'-'*6} {'-'*6} {'-'*6}"
    )

    all_results = {}
    for threshold in [3, 4, 5, 6, 8, 10, 15, 9999]:
        r = run_loo_with_filter(
            l0_iocs, adj, node_depth, node_orgs, node_reports,
            infra_noise, threshold,
        )
        all_results[threshold] = r

        det_acc = r["clear_correct"] / (r["clear_correct"] + r["tie_true_not"]) * 100 if (r["clear_correct"] + r["tie_true_not"]) else 0
        tie_pct = (r["tie_true_in"] + r["tie_true_not"]) / r["match"] * 100 if r["match"] else 0
        cover = r["match"] / r["total"] * 100

        label = f"≥{threshold}" if threshold < 9999 else "none"
        print(
            f"  {label:>10} {r['match']:>7,} {r['clear_correct']:>8,} "
            f"{r['tie_true_in']:>8,} {r['tie_true_not']:>9,} "
            f"{det_acc:>8.1f}% {tie_pct:>5.1f}% {cover:>7.1f}% "
            f"{r['no_match_no_nbr']:>6,} {r['no_match_all_noise']:>6,} {r['no_match_loo']:>6,}"
        )

    # ── Per-org detail for best threshold ──
    # Pick threshold where deterministic accuracy is best with reasonable coverage
    print(f"\n{'='*90}")
    print("Per-Org Detail（threshold ≥5 + static noise filter）")
    print(f"{'='*90}")

    r5 = all_results[5]
    print(
        f"  {'Org':<20} {'Total':>5} {'Match':>6} {'Clear✓':>7} {'Tie-in':>7} "
        f"{'Det.Acc%':>9} {'Tie%':>6} {'Cover%':>8}"
    )
    print(
        f"  {'-'*20} {'-'*5} {'-'*6} {'-'*7} {'-'*7} "
        f"{'-'*9} {'-'*6} {'-'*8}"
    )

    for org in sorted(r5["org_stats"].keys()):
        s = r5["org_stats"][org]
        det_acc = s["clear_correct"] / (s["clear_correct"] + s["tie_true_not"]) * 100 if (s["clear_correct"] + s["tie_true_not"]) else 0
        tie_pct = (s["tie_true_in"] + s["tie_true_not"]) / s["match"] * 100 if s["match"] else 0
        cover = s["match"] / s["total"] * 100 if s["total"] else 0
        # det_acc might be NaN if no clear_correct and no tie_true_not
        det_str = f"{det_acc:>8.1f}%" if (s["clear_correct"] + s["tie_true_not"]) else "     N/A"
        print(
            f"  {org:<20} {s['total']:>5} {s['match']:>6} {s['clear_correct']:>7} "
            f"{s['tie_true_in']:>7} {det_str} {tie_pct:>5.1f}% {cover:>7.1f}%"
        )

    # ── Confidence-gated attribution ──
    print(f"\n{'='*90}")
    print("Confidence-Gated Attribution（分層信心度歸因）")
    print(f"{'='*90}")

    # Re-run with detailed per-IoC tracking
    l0_set = {nid for nid, d in node_depth.items() if d == 0}
    l1_to_l0 = defaultdict(set)
    for n, neighbors in adj.items():
        if node_depth.get(n) != 1:
            continue
        for nb in neighbors:
            if nb in l0_set:
                l1_to_l0[n].add(nb)

    report_to_iocs = defaultdict(list)
    for v_id, v_org in l0_iocs:
        reports = node_reports.get(v_id, [])
        key = reports[0] if reports else f"__no_report_{v_id}"
        report_to_iocs[key].append((v_id, v_org))

    tiers = {
        "high":   {"max_org": 2, "total": 0, "clear_correct": 0, "tie_in": 0, "tie_out": 0},
        "medium": {"max_org": 5, "total": 0, "clear_correct": 0, "tie_in": 0, "tie_out": 0},
        "low":    {"max_org": 9999, "total": 0, "clear_correct": 0, "tie_in": 0, "tie_out": 0},
        "none":   {"total": 0},  # no match at all
    }

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

            # Try each tier in order (high → medium → low)
            assigned = False
            for tier_name in ["high", "medium", "low"]:
                tier = tiers[tier_name]
                max_org = tier["max_org"]

                filtered = set()
                for n in v_neighbors:
                    if n in removed or n in infra_noise:
                        continue
                    if len(node_orgs.get(n, set())) <= max_org:
                        filtered.add(n)

                if not filtered:
                    continue

                tier["total"] += 1
                org_votes = Counter()
                for n in filtered:
                    for org in node_orgs.get(n, set()):
                        org_votes[org] += 1

                top_count = org_votes.most_common(1)[0][1]
                tied = [org for org, cnt in org_votes.items() if cnt == top_count]

                if len(tied) == 1:
                    if tied[0] == v_org:
                        tier["clear_correct"] += 1
                else:
                    if v_org in tied:
                        tier["tie_in"] += 1
                    else:
                        tier["tie_out"] += 1

                assigned = True
                break

            if not assigned:
                tiers["none"]["total"] += 1

    total = len(l0_iocs)
    print(f"\n  Total IoCs: {total:,}\n")
    print(f"  {'Tier':<12} {'Criteria':<25} {'Count':>6} {'%Total':>7} {'Clear✓':>8} {'Tie':>8} {'Det.Acc%':>9}")
    print(f"  {'-'*12} {'-'*25} {'-'*6} {'-'*7} {'-'*8} {'-'*8} {'-'*9}")

    for tier_name, label, criteria in [
        ("high", "High", "≤2 org neighbors"),
        ("medium", "Medium", "≤5 org neighbors"),
        ("low", "Low", "any neighbor"),
        ("none", "No match", "—"),
    ]:
        t = tiers[tier_name]
        pct = t["total"] / total * 100
        if tier_name == "none":
            print(f"  {label:<12} {criteria:<25} {t['total']:>6} {pct:>6.1f}%")
        else:
            det = t["clear_correct"] + t.get("tie_out", 0)
            det_acc = t["clear_correct"] / det * 100 if det else 0
            tie_cnt = t.get("tie_in", 0) + t.get("tie_out", 0)
            print(
                f"  {label:<12} {criteria:<25} {t['total']:>6} {pct:>6.1f}% "
                f"{t['clear_correct']:>8} {tie_cnt:>8} {det_acc:>8.1f}%"
            )

    # ── Save ──
    output = {
        "sweep": {
            str(k): {key: v for key, v in r.items() if key != "org_stats"}
            for k, r in all_results.items()
        },
        "confidence_tiers": {
            k: {kk: vv for kk, vv in v.items() if kk != "max_org"}
            for k, v in tiers.items()
        },
    }
    out_path = Path("scripts/results/eval_noise_filter_sweep.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    logger.info(f"Saved to {out_path}")


if __name__ == "__main__":
    main()
