"""
Multi-hop 歸因 Leave-One-Out 模擬：
對每個 L0 IoC，假裝它是未知的 → 移除它和其獨佔 L1 鄰居 →
看 1-hop / 2-hop 鄰居在剩餘 KG 中能 match 多少 → 能否正確歸因
"""

import sqlite3
from collections import Counter, defaultdict
from pathlib import Path

DB_PATH = Path("knowledge_graphs/master/merged_kg.db")


def load_graph():
    """從 SQLite 載入所有需要的資料"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    # Node info
    node_depth = {}
    node_type = {}
    cur = conn.execute("SELECT id, depth, type FROM nodes")
    for row in cur:
        node_depth[row["id"]] = row["depth"]
        node_type[row["id"]] = row["type"]

    # Node-org mapping
    node_orgs = defaultdict(set)
    cur = conn.execute("SELECT node_id, org FROM node_orgs")
    for row in cur:
        node_orgs[row["node_id"]].add(row["org"])

    # Adjacency (exclude has_ioc)
    adj = defaultdict(set)
    cur = conn.execute(
        "SELECT source, target FROM edges WHERE relationship != 'has_ioc'"
    )
    for row in cur:
        adj[row["source"]].add(row["target"])
        adj[row["target"]].add(row["source"])

    # L0 IoCs with their orgs
    cur = conn.execute(
        "SELECT n.id, n.type, no2.org FROM nodes n "
        "JOIN node_orgs no2 ON n.id = no2.node_id "
        "WHERE n.depth = 0 AND n.type != 'apt'"
    )
    l0_iocs = []
    for row in cur:
        l0_iocs.append((row["id"], row["type"], row["org"]))

    conn.close()
    return adj, node_depth, node_type, node_orgs, l0_iocs


def precompute_l1_to_l0(adj, node_depth):
    """對每個 L1 節點，找出它連接了哪些 L0 節點"""
    l1_to_l0 = defaultdict(set)
    l0_set = {nid for nid, d in node_depth.items() if d == 0}

    for l1_node, neighbors in adj.items():
        if node_depth.get(l1_node) != 1:
            continue
        for n in neighbors:
            if n in l0_set:
                l1_to_l0[l1_node].add(n)

    return l1_to_l0


def leave_one_out_simulation(adj, node_depth, node_type, node_orgs, l0_iocs, l1_to_l0):
    """
    對每個 L0 IoC v：
    1. 移除 v 和 v 的獨佔 L1 鄰居（只連到 v 的 L1 節點）
    2. 模擬 VT 查詢：v 的 1-hop 鄰居 = adj[v]
    3. 1-hop match：adj[v] 中仍在剩餘 KG 的節點
    4. 2-hop match：adj[v] 的鄰居中仍在剩餘 KG 的節點
    5. 從 matched 節點的 org label 做 majority vote 歸因
    """
    all_nodes = set(node_depth.keys())

    # --- per-IoC results ---
    results = []

    for i, (v_id, v_type, v_true_org) in enumerate(l0_iocs):
        if i % 1000 == 0 and i > 0:
            print(f"  進度: {i}/{len(l0_iocs)}...")

        # Step 1: 找出 v 的獨佔 L1 鄰居
        v_neighbors = adj.get(v_id, set())
        exclusive_l1 = set()
        for n in v_neighbors:
            if node_depth.get(n) == 1:
                # 這個 L1 節點只連到 v 一個 L0 節點 → 獨佔
                if l1_to_l0.get(n, set()) == {v_id}:
                    exclusive_l1.add(n)

        removed = {v_id} | exclusive_l1

        # Step 2: 1-hop match（VT 回傳 v 的鄰居，看哪些還在 KG 中）
        matched_1hop = v_neighbors - removed

        # Step 3: 2-hop match（對 v 的每個鄰居再展開一層）
        # 注意：即使是被移除的獨佔 L1 節點，VT 仍會回傳它的 relationships
        # 所以我們從 v 的所有原始鄰居展開，但只看 match 到剩餘 KG 的節點
        neighbors_2hop = set()
        for n in v_neighbors:
            neighbors_2hop.update(adj.get(n, set()))
        neighbors_2hop -= v_neighbors  # 去掉 1-hop 本身
        neighbors_2hop.discard(v_id)    # 去掉自己
        matched_2hop_new = neighbors_2hop - removed  # 在剩餘 KG 中的 2-hop 節點

        # Step 4: 歸因 — 從 matched 節點的 org labels 做 majority vote
        def attribute(matched_nodes):
            """從 matched 節點收集 org labels，majority vote"""
            org_votes = Counter()
            for n in matched_nodes:
                for org in node_orgs.get(n, set()):
                    org_votes[org] += 1
            if not org_votes:
                return None, {}
            return org_votes.most_common(1)[0][0], dict(org_votes)

        # 1-hop only attribution
        pred_1hop, votes_1hop = attribute(matched_1hop)

        # 1+2 hop attribution
        all_matched = matched_1hop | matched_2hop_new
        pred_2hop, votes_2hop = attribute(all_matched)

        # API cost for 2-hop
        api_cost = len(v_neighbors)  # 每個 1-hop 鄰居都要查 VT

        results.append({
            "id": v_id,
            "type": v_type,
            "true_org": v_true_org,
            "n_neighbors": len(v_neighbors),
            "n_exclusive_l1": len(exclusive_l1),
            "n_matched_1hop": len(matched_1hop),
            "n_matched_2hop_new": len(matched_2hop_new),
            "n_all_matched": len(all_matched),
            "pred_1hop": pred_1hop,
            "correct_1hop": pred_1hop == v_true_org,
            "pred_2hop": pred_2hop,
            "correct_2hop": pred_2hop == v_true_org,
            "api_cost_2hop": api_cost,
            "votes_1hop": votes_1hop,
            "votes_2hop": votes_2hop,
        })

    return results


def print_overall_results(results):
    """整體結果"""
    print("=" * 70)
    print("Leave-One-Out Multi-hop 歸因模擬結果")
    print("=" * 70)

    total = len(results)

    # --- Match 率 ---
    has_1hop_match = sum(1 for r in results if r["n_matched_1hop"] > 0)
    has_2hop_new_match = sum(1 for r in results
                            if r["n_matched_1hop"] == 0 and r["n_matched_2hop_new"] > 0)
    has_any_match = sum(1 for r in results if r["n_all_matched"] > 0)

    print(f"\n  Match 率（鄰居能在剩餘 KG 找到匹配）:")
    print(f"    1-hop 有 match: {has_1hop_match:,}/{total:,} ({has_1hop_match/total*100:.1f}%)")
    print(f"    2-hop 新增 match: +{has_2hop_new_match:,} (原本 1-hop 沒有，2-hop 才找到)")
    print(f"    合計有 match: {has_any_match:,}/{total:,} ({has_any_match/total*100:.1f}%)")
    print(f"    2-hop 提升: {has_1hop_match/total*100:.1f}% → {has_any_match/total*100:.1f}% "
          f"(+{(has_any_match-has_1hop_match)/total*100:.1f}%)")

    # --- Match 數量分布 ---
    m1_list = sorted(r["n_matched_1hop"] for r in results)
    m2_list = sorted(r["n_all_matched"] for r in results)
    print(f"\n  Match 數量分布:")
    print(f"  {'':15s} {'1-hop':>10s} {'1+2 hop':>10s}")
    print(f"  {'平均':15s} {sum(m1_list)/total:>10.1f} {sum(m2_list)/total:>10.1f}")
    for label, pct in [("中位數", 0.5), ("P75", 0.75), ("P90", 0.90)]:
        idx = int(total * pct)
        print(f"  {label:15s} {m1_list[idx]:>10,} {m2_list[idx]:>10,}")

    # --- 獨佔 L1 統計 ---
    excl_list = sorted(r["n_exclusive_l1"] for r in results)
    print(f"\n  獨佔 L1 鄰居（被移除的節點）:")
    print(f"    平均: {sum(excl_list)/total:.1f}")
    print(f"    中位數: {excl_list[total//2]}")
    print(f"    P90: {excl_list[int(total*0.90)]}")
    n_all_exclusive = sum(1 for r in results
                         if r["n_exclusive_l1"] == r["n_neighbors"] and r["n_neighbors"] > 0)
    print(f"    所有鄰居都是獨佔（1-hop 全被移除）: {n_all_exclusive:,}")

    # --- 歸因準確率 ---
    # 1-hop
    has_pred_1 = [r for r in results if r["pred_1hop"] is not None]
    correct_1 = sum(1 for r in has_pred_1 if r["correct_1hop"])
    # 2-hop
    has_pred_2 = [r for r in results if r["pred_2hop"] is not None]
    correct_2 = sum(1 for r in has_pred_2 if r["correct_2hop"])
    # 2-hop only: cases where 1-hop had no match but 2-hop does
    hop2_only = [r for r in results if r["pred_1hop"] is None and r["pred_2hop"] is not None]
    correct_2only = sum(1 for r in hop2_only if r["correct_2hop"])

    print(f"\n  歸因準確率（Majority Vote）:")
    print(f"  {'':25s} {'能歸因':>8s} {'正確':>8s} {'準確率':>8s}")
    print(f"  {'1-hop only':25s} {len(has_pred_1):>8,} {correct_1:>8,} "
          f"{correct_1/len(has_pred_1)*100 if has_pred_1 else 0:>7.1f}%")
    print(f"  {'1+2 hop':25s} {len(has_pred_2):>8,} {correct_2:>8,} "
          f"{correct_2/len(has_pred_2)*100 if has_pred_2 else 0:>7.1f}%")
    print(f"  {'2-hop 獨有貢獻':25s} {len(hop2_only):>8,} {correct_2only:>8,} "
          f"{correct_2only/len(hop2_only)*100 if hop2_only else 0:>7.1f}%")
    print(f"  {'無法歸因':25s} {total - len(has_pred_2):>8,}")

    # --- API 成本 ---
    api_costs = sorted(r["api_cost_2hop"] for r in results)
    print(f"\n  2-hop API 成本（每個 IoC 需查詢的 VT relationship 數）:")
    print(f"    平均: {sum(api_costs)/total:.1f}")
    print(f"    中位數: {api_costs[total//2]}")
    print(f"    P90: {api_costs[int(total*0.90)]}")
    print(f"    總計: {sum(api_costs):,}")


def print_per_org_results(results):
    """Per-org 結果"""
    print(f"\n{'=' * 70}")
    print("Per-Org 歸因結果")
    print("=" * 70)

    org_results = defaultdict(list)
    for r in results:
        org_results[r["true_org"]].append(r)

    print(f"  {'Org':20s} {'IoCs':>5s} │ {'1hop匹配':>8s} {'1hop正確':>8s} {'1hop%':>7s} │ "
          f"{'2hop匹配':>8s} {'2hop正確':>8s} {'2hop%':>7s} │ {'增益':>5s}")
    print(f"  {'-'*20} {'-'*5} │ {'-'*8} {'-'*8} {'-'*7} │ {'-'*8} {'-'*8} {'-'*7} │ {'-'*5}")

    total_1hop_match = 0
    total_1hop_correct = 0
    total_2hop_match = 0
    total_2hop_correct = 0

    for org in sorted(org_results.keys()):
        rs = org_results[org]
        n = len(rs)

        # 1-hop
        m1 = sum(1 for r in rs if r["pred_1hop"] is not None)
        c1 = sum(1 for r in rs if r["correct_1hop"])
        acc1 = c1 / m1 * 100 if m1 else 0

        # 2-hop
        m2 = sum(1 for r in rs if r["pred_2hop"] is not None)
        c2 = sum(1 for r in rs if r["correct_2hop"])
        acc2 = c2 / m2 * 100 if m2 else 0

        gain = c2 - c1

        total_1hop_match += m1
        total_1hop_correct += c1
        total_2hop_match += m2
        total_2hop_correct += c2

        print(f"  {org:20s} {n:>5,} │ {m1:>8,} {c1:>8,} {acc1:>6.1f}% │ "
              f"{m2:>8,} {c2:>8,} {acc2:>6.1f}% │ {gain:>+5}")

    print(f"  {'-'*20} {'-'*5} │ {'-'*8} {'-'*8} {'-'*7} │ {'-'*8} {'-'*8} {'-'*7} │ {'-'*5}")
    n_total = len(results)
    acc1_total = total_1hop_correct / total_1hop_match * 100 if total_1hop_match else 0
    acc2_total = total_2hop_correct / total_2hop_match * 100 if total_2hop_match else 0
    gain_total = total_2hop_correct - total_1hop_correct
    print(f"  {'TOTAL':20s} {n_total:>5,} │ {total_1hop_match:>8,} {total_1hop_correct:>8,} "
          f"{acc1_total:>6.1f}% │ {total_2hop_match:>8,} {total_2hop_correct:>8,} "
          f"{acc2_total:>6.1f}% │ {gain_total:>+5}")


def print_type_breakdown(results):
    """按 IoC 類型分析"""
    print(f"\n{'=' * 70}")
    print("按 IoC 類型分析")
    print("=" * 70)

    type_results = defaultdict(list)
    for r in results:
        type_results[r["type"]].append(r)

    print(f"  {'Type':10s} {'IoCs':>5s} │ {'1hop匹配%':>8s} {'1hop正確%':>8s} │ "
          f"{'2hop匹配%':>8s} {'2hop正確%':>8s} │ {'新增match':>8s}")
    print(f"  {'-'*10} {'-'*5} │ {'-'*8} {'-'*8} │ {'-'*8} {'-'*8} │ {'-'*8}")

    for t in sorted(type_results.keys()):
        rs = type_results[t]
        n = len(rs)

        m1 = sum(1 for r in rs if r["pred_1hop"] is not None)
        c1 = sum(1 for r in rs if r["correct_1hop"])
        m2 = sum(1 for r in rs if r["pred_2hop"] is not None)
        c2 = sum(1 for r in rs if r["correct_2hop"])
        new_match = sum(1 for r in rs if r["pred_1hop"] is None and r["pred_2hop"] is not None)

        print(f"  {t:10s} {n:>5,} │ {m1/n*100:>7.1f}% {c1/m1*100 if m1 else 0:>7.1f}% │ "
              f"{m2/n*100:>7.1f}% {c2/m2*100 if m2 else 0:>7.1f}% │ {new_match:>8,}")


def print_examples(results):
    """印出幾個 2-hop 新增 match 的案例"""
    print(f"\n{'=' * 70}")
    print("2-hop 新增歸因的案例（原本 1-hop 沒有 match）")
    print("=" * 70)

    hop2_only = [r for r in results if r["pred_1hop"] is None and r["pred_2hop"] is not None]

    if not hop2_only:
        print("  （無案例 — 所有能歸因的 IoC 在 1-hop 就有 match）")
        return

    for r in hop2_only[:10]:
        status = "✅" if r["correct_2hop"] else "❌"
        print(f"  {status} {r['id'][:60]}...")
        print(f"     type={r['type']}, true_org={r['true_org']}")
        print(f"     1-hop neighbors: {r['n_neighbors']}, exclusive: {r['n_exclusive_l1']}, "
              f"matched: {r['n_matched_1hop']}")
        print(f"     2-hop new matched: {r['n_matched_2hop_new']}, pred={r['pred_2hop']}")
        top3 = Counter(r["votes_2hop"]).most_common(3)
        print(f"     votes: {top3}")
        print()


def main():
    print("載入 Master KG...")
    adj, node_depth, node_type, node_orgs, l0_iocs = load_graph()
    print(f"  節點: {len(node_depth):,}, L0 IoC: {len(l0_iocs):,}")

    print("\n預計算 L1→L0 映射...")
    l1_to_l0 = precompute_l1_to_l0(adj, node_depth)
    print(f"  L1 節點: {len(l1_to_l0):,}")

    print("\n開始 Leave-One-Out 模擬...")
    results = leave_one_out_simulation(adj, node_depth, node_type, node_orgs, l0_iocs, l1_to_l0)

    print_overall_results(results)
    print_per_org_results(results)
    print_type_breakdown(results)
    print_examples(results)


if __name__ == "__main__":
    main()
