#!/usr/bin/env python3
"""
merge_knowledge_graphs.py — 合併多個 APT Knowledge Graph 為統一資料庫。

策略：
  - 相同 node ID → 合併（數值取最新、清單累加去重）
  - 邊全部保留（不同 APT 指向同一節點的邊各自獨立）
  - 輸出：JSON + SQLite

輸出位置：
  knowledge_graphs/master/merged_kg.json
  knowledge_graphs/master/merged_kg.db

用法：
  uv run python scripts/merge_knowledge_graphs.py
  uv run python scripts/merge_knowledge_graphs.py --orgs APT18,APT19
  uv run python scripts/merge_knowledge_graphs.py --visualize
"""

from __future__ import annotations

import argparse
import json
import logging
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

BASE_DIR = Path(__file__).parent.parent
KG_DIR = BASE_DIR / "knowledge_graphs"
MASTER_DIR = KG_DIR / "master"

# 數值型欄位（取最新）
NUMERIC_FIELDS = {
    "malicious", "suspicious", "harmless", "undetected",
    "total_engines", "detection_ratio", "reputation",
    "size", "times_submitted", "unique_sources",
}

# 清單型欄位（累加去重）
LIST_FIELDS = {
    "names", "tags", "type_tags", "trid", "detectiteasy",
    "crowdsourced_context",
    "ioc_original_types", "ioc_original_values", "source_reports",
}


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def setup_logging() -> logging.Logger:
    logger = logging.getLogger("kg_merger")
    if not logger.handlers:
        logger.setLevel(logging.DEBUG)
        ch = logging.StreamHandler(sys.stdout)
        ch.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%H:%M:%S"))
        ch.setLevel(logging.INFO)
        logger.addHandler(ch)
    return logger


# ---------------------------------------------------------------------------
# Metadata 合併
# ---------------------------------------------------------------------------

def _merge_attributes(old: dict, new: dict) -> dict:
    """
    合併兩個 attributes dict。
    - 數值型：取 new（較新的資料）
    - 清單型：累加去重
    - 其他：new 有值就覆蓋
    """
    merged = dict(old)

    for key, val in new.items():
        if key in LIST_FIELDS:
            old_list = merged.get(key) or []
            new_list = val or []
            if not isinstance(old_list, list):
                old_list = [old_list]
            if not isinstance(new_list, list):
                new_list = [new_list]
            # 去重：dict 用 json 序列化比較
            seen = set()
            combined = []
            for item in old_list + new_list:
                key_repr = json.dumps(item, sort_keys=True) if isinstance(item, dict) else str(item)
                if key_repr not in seen:
                    seen.add(key_repr)
                    combined.append(item)
            merged[key] = combined
        elif val is not None:
            merged[key] = val

    return merged


def _get_query_time(node: dict, kg: dict) -> str | None:
    """嘗試從節點或 KG 取得查詢時間。"""
    attrs = node.get("attributes") or {}
    # 嘗試多個時間欄位
    for field in ("last_analysis", "last_submission", "query_time"):
        if attrs.get(field):
            return attrs[field]
    return kg.get("created_at")


# ---------------------------------------------------------------------------
# 合併邏輯
# ---------------------------------------------------------------------------

def merge_graphs(kg_list: list[dict], logger: logging.Logger) -> dict:
    """
    合併多個 KG dict 為一個統一圖譜。

    回傳 merged dict:
    {
        "orgs": ["APT18", "APT19"],
        "created_at": "...",
        "node_count": N,
        "edge_count": M,
        "nodes": [...],
        "edges": [...],
        "merge_stats": { ... }
    }
    """
    nodes_map: dict[str, dict] = {}   # node_id → merged node
    node_orgs: dict[str, set] = {}    # node_id → {org1, org2, ...}
    node_times: dict[str, str] = {}   # node_id → latest query_time
    edges: list[dict] = []
    orgs: list[str] = []

    for kg in kg_list:
        org = kg["organization"]
        orgs.append(org)
        kg_time = kg.get("created_at", "")
        logger.info(f"載入 {org}：{kg['node_count']} nodes, {kg['edge_count']} edges")

        # ── 合併節點 ──
        for node in kg["nodes"]:
            nid = node["id"]
            query_time = _get_query_time(node, kg) or kg_time

            if nid not in nodes_map:
                # 新節點
                nodes_map[nid] = {
                    "id":        nid,
                    "type":      node["type"],
                    "vt_found":  node.get("vt_found", False),
                    "depth":     node.get("depth"),
                    "attributes": dict(node.get("attributes") or {}),
                }
                node_orgs[nid] = {org}
                node_times[nid] = query_time or ""
            else:
                # 合併：metadata merge
                existing = nodes_map[nid]
                # vt_found: 任一為 True 就是 True
                if node.get("vt_found"):
                    existing["vt_found"] = True
                # depth: 取最小值（0 = Layer 1 優先）
                old_depth = existing.get("depth")
                new_depth = node.get("depth")
                if old_depth is not None and new_depth is not None:
                    existing["depth"] = min(old_depth, new_depth)
                elif new_depth is not None:
                    existing["depth"] = new_depth

                # attributes merge
                old_time = node_times.get(nid, "")
                if query_time and query_time >= old_time:
                    # new 較新 → new 的數值覆蓋 old
                    existing["attributes"] = _merge_attributes(
                        existing["attributes"], node.get("attributes") or {}
                    )
                    node_times[nid] = query_time
                else:
                    # old 較新 → old 的數值保留，new 的清單累加
                    existing["attributes"] = _merge_attributes(
                        node.get("attributes") or {}, existing["attributes"]
                    )

                node_orgs[nid].add(org)

        # ── 邊全部保留，標記來源 org ──
        for edge in kg["edges"]:
            edges.append({
                "source":       edge["source"],
                "target":       edge["target"],
                "relationship": edge["relationship"],
                "attributes":   edge.get("attributes") or {},
                "org":          org,
            })

    # ── 統計 ──
    shared_nodes = {nid for nid, o in node_orgs.items() if len(o) > 1}
    unique_nodes = {nid for nid, o in node_orgs.items() if len(o) == 1}

    # 在節點上標記所屬 org
    nodes_out = []
    for nid, node in nodes_map.items():
        node["orgs"] = sorted(node_orgs[nid])
        nodes_out.append(node)

    stats = {
        "total_orgs":    len(orgs),
        "total_nodes":   len(nodes_out),
        "total_edges":   len(edges),
        "shared_nodes":  len(shared_nodes),
        "unique_nodes":  len(unique_nodes),
        "shared_node_ids": sorted(shared_nodes),
    }

    logger.info(f"合併完成：{stats['total_nodes']} nodes, {stats['total_edges']} edges")
    logger.info(f"  共享節點（跨組織）：{stats['shared_nodes']}")
    logger.info(f"  獨有節點：{stats['unique_nodes']}")

    return {
        "version":     "1.0",
        "orgs":        orgs,
        "created_at":  datetime.now(timezone.utc).isoformat(),
        "node_count":  len(nodes_out),
        "edge_count":  len(edges),
        "nodes":       nodes_out,
        "edges":       edges,
        "merge_stats": stats,
    }


# ---------------------------------------------------------------------------
# SQLite 輸出
# ---------------------------------------------------------------------------

def export_sqlite(merged: dict, db_path: Path, logger: logging.Logger) -> None:
    """將合併圖譜寫入 SQLite 資料庫。"""

    if db_path.exists():
        db_path.unlink()

    conn = sqlite3.connect(str(db_path))
    cur = conn.cursor()

    # ── 建表 ──
    cur.executescript("""
        CREATE TABLE nodes (
            id          TEXT PRIMARY KEY,
            type        TEXT NOT NULL,
            vt_found    INTEGER DEFAULT 0,
            depth       INTEGER,
            attributes  TEXT,    -- JSON blob
            orgs        TEXT     -- JSON array of org names
        );

        CREATE TABLE edges (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            source       TEXT NOT NULL,
            target       TEXT NOT NULL,
            relationship TEXT NOT NULL,
            attributes   TEXT,   -- JSON blob
            org          TEXT NOT NULL,
            FOREIGN KEY (source) REFERENCES nodes(id),
            FOREIGN KEY (target) REFERENCES nodes(id)
        );

        -- 多對多：節點 ↔ 組織
        CREATE TABLE node_orgs (
            node_id TEXT NOT NULL,
            org     TEXT NOT NULL,
            PRIMARY KEY (node_id, org),
            FOREIGN KEY (node_id) REFERENCES nodes(id)
        );

        -- 索引
        CREATE INDEX idx_edges_source ON edges(source);
        CREATE INDEX idx_edges_target ON edges(target);
        CREATE INDEX idx_edges_org ON edges(org);
        CREATE INDEX idx_edges_relationship ON edges(relationship);
        CREATE INDEX idx_nodes_type ON nodes(type);
        CREATE INDEX idx_node_orgs_org ON node_orgs(org);
    """)

    # ── 寫入 nodes ──
    for node in merged["nodes"]:
        cur.execute(
            "INSERT INTO nodes (id, type, vt_found, depth, attributes, orgs) VALUES (?, ?, ?, ?, ?, ?)",
            (
                node["id"],
                node["type"],
                1 if node.get("vt_found") else 0,
                node.get("depth"),
                json.dumps(node.get("attributes") or {}, ensure_ascii=False),
                json.dumps(node.get("orgs") or [], ensure_ascii=False),
            ),
        )

    # ── 寫入 node_orgs ──
    for node in merged["nodes"]:
        for org in node.get("orgs", []):
            cur.execute(
                "INSERT INTO node_orgs (node_id, org) VALUES (?, ?)",
                (node["id"], org),
            )

    # ── 寫入 edges ──
    for edge in merged["edges"]:
        cur.execute(
            "INSERT INTO edges (source, target, relationship, attributes, org) VALUES (?, ?, ?, ?, ?)",
            (
                edge["source"],
                edge["target"],
                edge["relationship"],
                json.dumps(edge.get("attributes") or {}, ensure_ascii=False),
                edge.get("org", ""),
            ),
        )

    conn.commit()

    # ── 驗證 ──
    node_count = cur.execute("SELECT COUNT(*) FROM nodes").fetchone()[0]
    edge_count = cur.execute("SELECT COUNT(*) FROM edges").fetchone()[0]
    shared = cur.execute(
        "SELECT COUNT(*) FROM (SELECT node_id FROM node_orgs GROUP BY node_id HAVING COUNT(DISTINCT org) > 1)"
    ).fetchone()[0]

    conn.close()

    logger.info(f"SQLite 已儲存：{db_path}")
    logger.info(f"  nodes: {node_count}, edges: {edge_count}, shared: {shared}")


# ---------------------------------------------------------------------------
# 視覺化
# ---------------------------------------------------------------------------

def visualize(merged: dict, out_path: Path, logger: logging.Logger) -> None:
    """產出合併 Knowledge Graph 視覺化 PNG。"""
    try:
        import networkx as nx
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import matplotlib.patches as mpatches
    except ImportError as e:
        logger.warning(f"視覺化套件未安裝，跳過：{e}")
        return

    G = nx.DiGraph()
    COLOR = {
        "apt":    "#E74C3C",
        "file":   "#3498DB",
        "domain": "#2ECC71",
        "ip":     "#F39C12",
        "email":  "#9B59B6",
    }

    for n in merged["nodes"]:
        ntype = n["type"]
        orgs = n.get("orgs", [])
        nid = n["id"]

        # 標籤
        if ntype == "apt":
            label = n["attributes"].get("name", nid)
        elif ntype == "file":
            label = nid[5:17] + "..." if len(nid) > 17 else nid
        elif ntype == "domain":
            label = nid.removeprefix("domain_")
        elif ntype == "ip":
            label = nid.removeprefix("ip_")
        elif ntype == "email":
            label = nid.removeprefix("email_")
        else:
            label = nid

        G.add_node(
            nid,
            label=label,
            ntype=ntype,
            color=COLOR.get(ntype, "#95A5A6"),
            shared=len(orgs) > 1,
        )

    for e in merged["edges"]:
        G.add_edge(e["source"], e["target"], rel=e["relationship"], org=e.get("org", ""))

    fig, ax = plt.subplots(figsize=(18, 14))
    ax.set_facecolor("#1A1A2E")
    fig.patch.set_facecolor("#1A1A2E")

    pos = nx.spring_layout(G, k=2.0, seed=42, iterations=80)

    # 共享節點用星形標記
    shared_nodes = [n for n in G.nodes if G.nodes[n].get("shared")]
    normal_nodes = [n for n in G.nodes if not G.nodes[n].get("shared")]

    # Normal nodes
    if normal_nodes:
        colors_n = [G.nodes[n]["color"] for n in normal_nodes]
        sizes_n = [2000 if G.nodes[n]["ntype"] == "apt" else 700 for n in normal_nodes]
        nx.draw_networkx_nodes(G, pos, nodelist=normal_nodes, node_color=colors_n,
                               node_size=sizes_n, alpha=0.85, ax=ax)

    # Shared nodes（較大 + 白色邊框）
    if shared_nodes:
        colors_s = [G.nodes[n]["color"] for n in shared_nodes]
        sizes_s = [1200 for _ in shared_nodes]
        nx.draw_networkx_nodes(G, pos, nodelist=shared_nodes, node_color=colors_s,
                               node_size=sizes_s, alpha=1.0, ax=ax,
                               edgecolors="white", linewidths=2.5)

    labels = {n: G.nodes[n]["label"] for n in G.nodes}
    nx.draw_networkx_labels(G, pos, labels=labels,
                            font_size=6, font_color="white", ax=ax)
    nx.draw_networkx_edges(G, pos, edge_color="#AAAAAA", arrows=True,
                           arrowsize=12, width=0.8,
                           connectionstyle="arc3,rad=0.05", ax=ax)

    # 圖例
    legend_patches = [
        mpatches.Patch(color=c, label=t.upper()) for t, c in COLOR.items()
    ]
    legend_patches.append(
        mpatches.Patch(facecolor="#555555", edgecolor="white", linewidth=2,
                       label=f"SHARED ({len(shared_nodes)})")
    )
    ax.legend(handles=legend_patches, loc="lower left",
              facecolor="#2C2C54", labelcolor="white", fontsize=9)

    orgs_str = " + ".join(merged["orgs"])
    stats = merged["merge_stats"]
    ax.set_title(
        f"Merged Knowledge Graph: {orgs_str}\n"
        f"({stats['total_nodes']} nodes, {stats['total_edges']} edges, "
        f"{stats['shared_nodes']} shared)",
        color="white", fontsize=13, pad=12,
    )
    ax.axis("off")
    plt.tight_layout()
    plt.savefig(out_path, dpi=300, bbox_inches="tight",
                facecolor=fig.get_facecolor())
    plt.close()
    logger.info(f"視覺化已儲存：{out_path}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="合併多個 APT Knowledge Graph 為統一資料庫"
    )
    parser.add_argument(
        "--orgs",
        help="指定組織（逗號分隔），預設自動偵測所有已完成的 KG",
    )
    parser.add_argument(
        "--visualize", action="store_true",
        help="產出合併視覺化 PNG",
    )
    args = parser.parse_args()

    logger = setup_logging()

    # ── 找出要合併的 KG ──
    if args.orgs:
        org_list = [o.strip() for o in args.orgs.split(",")]
    else:
        # 自動偵測：knowledge_graphs/{org}/{org}.json 存在的組織
        org_list = []
        for d in sorted(KG_DIR.iterdir()):
            if d.is_dir() and d.name != "master":
                kg_file = d / f"{d.name}.json"
                if kg_file.exists():
                    org_list.append(d.name)

    if len(org_list) < 2:
        logger.error(f"至少需要 2 個 KG 才能合併，找到：{org_list}")
        sys.exit(1)

    logger.info(f"準備合併 {len(org_list)} 個組織：{org_list}")

    # ── 載入 KG ──
    kg_list = []
    for org in org_list:
        kg_file = KG_DIR / org / f"{org}.json"
        if not kg_file.exists():
            logger.error(f"KG 不存在：{kg_file}")
            sys.exit(1)
        kg = json.loads(kg_file.read_text(encoding="utf-8"))
        kg_list.append(kg)

    # ── 合併 ──
    merged = merge_graphs(kg_list, logger)

    # ── 輸出 ──
    MASTER_DIR.mkdir(parents=True, exist_ok=True)

    # JSON
    json_path = MASTER_DIR / "merged_kg.json"
    json_path.write_text(
        json.dumps(merged, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    logger.info(f"JSON 已儲存：{json_path}")

    # SQLite
    db_path = MASTER_DIR / "merged_kg.db"
    export_sqlite(merged, db_path, logger)

    # 視覺化
    if args.visualize:
        png_path = MASTER_DIR / "merged_kg.png"
        visualize(merged, png_path, logger)

    # ── 印出摘要 ──
    stats = merged["merge_stats"]
    logger.info("=" * 50)
    logger.info(f"合併摘要")
    logger.info(f"  組織：{', '.join(merged['orgs'])}")
    logger.info(f"  節點：{stats['total_nodes']}（共享 {stats['shared_nodes']}）")
    logger.info(f"  邊：  {stats['total_edges']}")
    if stats["shared_node_ids"]:
        logger.info(f"  共享節點清單：")
        for nid in stats["shared_node_ids"]:
            logger.info(f"    {nid}")
    logger.info("=" * 50)

    # 示範 SQL 查詢
    logger.info("")
    logger.info("SQLite 查詢範例：")
    logger.info(f"  sqlite3 {db_path}")
    logger.info("  -- 找出跨組織共用的 IoC")
    logger.info("  SELECT node_id, GROUP_CONCAT(org) FROM node_orgs GROUP BY node_id HAVING COUNT(DISTINCT org) > 1;")
    logger.info("  -- 統計每個組織的節點數")
    logger.info("  SELECT org, COUNT(*) FROM node_orgs GROUP BY org;")
    logger.info("  -- 查看特定 IP 被哪些組織使用")
    logger.info("  SELECT * FROM node_orgs WHERE node_id LIKE 'ip_%' AND node_id IN (SELECT node_id FROM node_orgs GROUP BY node_id HAVING COUNT(DISTINCT org) > 1);")


if __name__ == "__main__":
    main()
