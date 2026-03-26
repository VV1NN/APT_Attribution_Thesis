#!/usr/bin/env python3
"""批次為所有已建立的 Knowledge Graph JSON 產出視覺化 PNG。

Usage:
    uv run python scripts/batch_visualize.py              # 只產出缺少 PNG 的
    uv run python scripts/batch_visualize.py --force       # 全部重新產出
    uv run python scripts/batch_visualize.py --orgs APT28,APT29  # 指定 org
"""

import argparse
import json
import logging
import sys
from pathlib import Path

import networkx as nx
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

KG_DIR = Path(__file__).resolve().parent.parent / "knowledge_graphs"

COLOR = {
    "apt":    "#E74C3C",
    "file":   "#3498DB",
    "domain": "#2ECC71",
    "ip":     "#F39C12",
    "email":  "#9B59B6",
}


def visualize(graph: dict, out_path: Path, logger: logging.Logger) -> None:
    """產出 Knowledge Graph 視覺化 PNG（複用 build_knowledge_graph.py 的邏輯）。"""
    G = nx.DiGraph()

    for n in graph["nodes"]:
        ntype = n["type"]
        label = n["attributes"].get("name", n["id"])
        if ntype == "file" and len(label) > 20:
            label = n["id"][:17] + "..."
        elif ntype == "domain":
            label = n["id"].removeprefix("domain_")
        elif ntype == "ip":
            label = n["id"].removeprefix("ip_")
        elif ntype == "email":
            label = n["id"].removeprefix("email_")

        G.add_node(
            n["id"],
            label=label,
            ntype=ntype,
            color=COLOR.get(ntype, "#95A5A6"),
        )

    for e in graph["edges"]:
        G.add_edge(e["source"], e["target"], rel=e["relationship"])

    fig, ax = plt.subplots(figsize=(14, 10))
    ax.set_facecolor("#1A1A2E")
    fig.patch.set_facecolor("#1A1A2E")

    pos = nx.spring_layout(G, k=2.5, seed=42)
    colors = [G.nodes[n]["color"] for n in G.nodes]
    labels = {n: G.nodes[n]["label"] for n in G.nodes}
    sizes = [2000 if G.nodes[n]["ntype"] == "apt" else 900 for n in G.nodes]

    nx.draw_networkx_nodes(G, pos, node_color=colors, node_size=sizes,
                           alpha=0.92, ax=ax)
    nx.draw_networkx_labels(G, pos, labels=labels,
                            font_size=7, font_color="white", ax=ax)
    nx.draw_networkx_edges(G, pos, edge_color="#AAAAAA", arrows=True,
                           arrowsize=15, width=1.2,
                           connectionstyle="arc3,rad=0.05", ax=ax)

    edge_labels = {(e[0], e[1]): e[2]["rel"] for e in G.edges(data=True)}
    nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels,
                                  font_size=5, font_color="#CCCCCC",
                                  label_pos=0.5, ax=ax)

    legend_patches = [
        mpatches.Patch(color=c, label=t.upper()) for t, c in COLOR.items()
    ]
    ax.legend(handles=legend_patches, loc="lower left",
              facecolor="#2C2C54", labelcolor="white", fontsize=9)

    org = graph["organization"]
    ax.set_title(
        f"{org} Knowledge Graph  "
        f"({graph['node_count']} nodes, {graph['edge_count']} edges)",
        color="white", fontsize=13, pad=12,
    )
    ax.axis("off")
    plt.tight_layout()
    plt.savefig(out_path, dpi=300, bbox_inches="tight",
                facecolor=fig.get_facecolor())
    plt.close()
    logger.info(f"✓ {org}: {out_path.name} ({graph['node_count']} nodes, {graph['edge_count']} edges)")


def main():
    parser = argparse.ArgumentParser(description="批次產出 KG 視覺化 PNG")
    parser.add_argument("--force", action="store_true", help="重新產出所有 PNG（包括已存在的）")
    parser.add_argument("--orgs", type=str, default="", help="指定 org（逗號分隔），預設全部")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(message)s")
    logger = logging.getLogger("batch_viz")

    # 找出所有 org KG JSON
    org_dirs = sorted(
        d for d in KG_DIR.iterdir()
        if d.is_dir() and d.name != "master" and (d / f"{d.name}.json").exists()
    )

    if args.orgs:
        selected = set(args.orgs.split(","))
        org_dirs = [d for d in org_dirs if d.name in selected]

    if not org_dirs:
        logger.info("沒有找到任何 KG JSON 檔案。")
        return

    total = len(org_dirs)
    created = 0
    skipped = 0

    for d in org_dirs:
        org = d.name
        json_path = d / f"{org}.json"
        png_path = d / f"{org}_graph.png"

        if png_path.exists() and not args.force:
            logger.info(f"  {org}: PNG 已存在，跳過（用 --force 強制重建）")
            skipped += 1
            continue

        logger.info(f"[{created + skipped + 1}/{total}] 產出 {org} 視覺化...")
        with open(json_path, encoding="utf-8") as f:
            graph = json.load(f)

        visualize(graph, png_path, logger)
        created += 1

    logger.info(f"\n完成！新建 {created} 個 PNG，跳過 {skipped} 個已存在。")


if __name__ == "__main__":
    main()
