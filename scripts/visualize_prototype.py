#!/usr/bin/env python3
"""
visualize_prototype.py — 繪製 APT Prototype 子圖的關聯圖譜

用法：
    uv run python scripts/visualize_prototype.py --apt APT-C-23
    uv run python scripts/visualize_prototype.py --apt APT-C-23 --focus 0fb4d09a  # 聚焦某節點的局部圖
    uv run python scripts/visualize_prototype.py --apt APT16                       # 小型全圖
"""

from __future__ import annotations

import argparse
import json
import math
from collections import Counter, defaultdict
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import networkx as nx
import numpy as np

BASE_DIR = Path(__file__).resolve().parent.parent
PROTO_DIR = BASE_DIR / "prototype_subgraphs"
OUTPUT_DIR = BASE_DIR / "output" / "figures"

# ── 視覺設定 ──────────────────────────────────────────────────────────────────

NODE_COLORS = {
    "file":   {"d0": "#3B82F6", "d1": "#93C5FD"},   # 藍
    "ip":     {"d0": "#10B981", "d1": "#6EE7B7"},   # 綠
    "domain": {"d0": "#8B5CF6", "d1": "#C4B5FD"},   # 紫
    "ttp":    {"d0": "#F59E0B", "d1": "#FCD34D"},   # 黃
}

EDGE_COLORS = {
    "contacted_ips":     "#EF4444",   # 紅
    "contacted_domains": "#F97316",   # 橙
    "dropped_files":     "#3B82F6",   # 藍
    "execution_parents": "#06B6D4",   # 青
    "resolutions":       "#10B981",   # 綠
    "co_occurrence":     "#9CA3AF",   # 灰
}

EDGE_STYLES = {
    "contacted_ips":     "-",
    "contacted_domains": "-",
    "dropped_files":     "--",
    "execution_parents": "--",
    "resolutions":       ":",
    "co_occurrence":     ":",
}

NODE_SHAPES = {"file": "o", "ip": "s", "domain": "D", "ttp": "^"}


def short_label(node: dict, max_len: int = 18) -> str:
    """產出節點的短標籤"""
    t = node.get("type", "?")
    v = node.get("value", "")
    if t == "file":
        return v[:10] + "..."
    elif t in ("ip", "domain"):
        if len(v) > max_len:
            return v[:max_len-3] + "..."
        return v
    elif t == "ttp":
        return v
    return v[:max_len]


def load_prototype(apt_name: str) -> dict:
    path = PROTO_DIR / f"{apt_name}.json"
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def build_graph(data: dict) -> nx.DiGraph:
    G = nx.DiGraph()
    for n in data["nodes"]:
        G.add_node(n["id"], **n)
    for e in data["edges"]:
        G.add_edge(e["source"], e["target"], relationship=e.get("relationship", "unknown"))
    return G


def extract_subgraph(G: nx.DiGraph, focus_value: str, hops: int = 2) -> nx.DiGraph:
    """提取以 focus 節點為中心的 k-hop 子圖"""
    center = None
    for nid, ndata in G.nodes(data=True):
        if focus_value in ndata.get("value", ""):
            center = nid
            break
    if center is None:
        raise ValueError(f"找不到包含 '{focus_value}' 的節點")

    # BFS 收集 k-hop 鄰居
    undirected = G.to_undirected()
    nodes_in_range = set()
    frontier = {center}
    for _ in range(hops):
        next_frontier = set()
        for n in frontier:
            for nb in undirected.neighbors(n):
                if nb not in nodes_in_range and nb != center:
                    next_frontier.add(nb)
        nodes_in_range |= frontier
        frontier = next_frontier
    nodes_in_range |= frontier

    return G.subgraph(nodes_in_range).copy()


def draw_graph(
    G: nx.DiGraph,
    apt_name: str,
    title_suffix: str = "",
    output_path: Path | None = None,
    figsize: tuple = (20, 16),
):
    """繪製關聯圖譜"""
    fig, ax = plt.subplots(1, 1, figsize=figsize, facecolor="white")

    # ── Layout ──
    n_nodes = len(G.nodes())
    if n_nodes <= 50:
        pos = nx.spring_layout(G, k=2.5/math.sqrt(max(n_nodes, 1)), iterations=80, seed=42)
    else:
        pos = nx.kamada_kawai_layout(G)

    # ── 按 type + depth 分組繪製節點 ──
    for node_type in ["file", "ip", "domain", "ttp"]:
        for depth_key, depth_vals in [("d0", [0]), ("d1", [1, 2, 3])]:
            node_list = [
                n for n, d in G.nodes(data=True)
                if d.get("type") == node_type and d.get("depth", 0) in depth_vals
            ]
            if not node_list:
                continue

            color = NODE_COLORS.get(node_type, {"d0": "#888", "d1": "#ccc"})[depth_key]

            # depth=0 大，depth=1 小
            if depth_key == "d0":
                sizes = []
                for n in node_list:
                    mal = G.nodes[n].get("malicious", 0) or 0
                    sizes.append(max(300, 200 + mal * 8))
                edgecolors = "#1F2937"
                linewidths = 2.0
            else:
                sizes = [120] * len(node_list)
                edgecolors = "#6B7280"
                linewidths = 0.8

            marker = NODE_SHAPES.get(node_type, "o")
            nx.draw_networkx_nodes(
                G, pos, nodelist=node_list,
                node_color=color, node_size=sizes,
                node_shape=marker, edgecolors=edgecolors,
                linewidths=linewidths, alpha=0.9, ax=ax,
            )

    # ── 按 relationship type 分組繪製邊 ──
    edge_by_rel = defaultdict(list)
    for u, v, d in G.edges(data=True):
        rel = d.get("relationship", "unknown")
        edge_by_rel[rel].append((u, v))

    for rel, edges in edge_by_rel.items():
        color = EDGE_COLORS.get(rel, "#D1D5DB")
        style = EDGE_STYLES.get(rel, "-")
        nx.draw_networkx_edges(
            G, pos, edgelist=edges,
            edge_color=color, style=style,
            alpha=0.5, width=1.2,
            arrows=True, arrowsize=10,
            connectionstyle="arc3,rad=0.05",
            ax=ax,
        )

    # ── 標籤（只標 depth=0 和度數高的 depth=1）──
    labels = {}
    for n, d in G.nodes(data=True):
        deg = G.degree(n)
        if d.get("depth", 0) == 0 or deg >= 3:
            labels[n] = short_label(d)

    nx.draw_networkx_labels(
        G, pos, labels,
        font_size=7, font_family="monospace",
        font_color="#1F2937", ax=ax,
    )

    # ── 圖例 ──
    legend_handles = []

    # 節點類型
    for ntype, label in [("file", "File (Hash)"), ("ip", "IP Address"),
                         ("domain", "Domain"), ("ttp", "TTP (ATT&CK)")]:
        c = NODE_COLORS.get(ntype, {"d0": "#888"})["d0"]
        m = NODE_SHAPES.get(ntype, "o")
        legend_handles.append(
            plt.scatter([], [], c=c, marker=m, s=100, edgecolors="#1F2937",
                        linewidths=1.5, label=f"{label} (depth=0)")
        )

    # depth 區分
    legend_handles.append(
        plt.scatter([], [], c="#93C5FD", marker="o", s=50, edgecolors="#6B7280",
                    linewidths=0.5, label="depth=1 (VT expanded)")
    )

    # 空白分隔
    legend_handles.append(mpatches.Patch(color="none", label=""))

    # 邊類型
    for rel, label in [
        ("contacted_ips", "File → IP (C2 connection)"),
        ("contacted_domains", "File → Domain (C2 DNS)"),
        ("dropped_files", "File → File (payload delivery)"),
        ("resolutions", "IP ↔ Domain (DNS history)"),
    ]:
        c = EDGE_COLORS.get(rel, "#D1D5DB")
        s = EDGE_STYLES.get(rel, "-")
        ls = {"--": "dashed", ":": "dotted"}.get(s, "solid")
        legend_handles.append(
            plt.Line2D([0], [0], color=c, linestyle=ls, linewidth=2, label=label)
        )

    ax.legend(
        handles=legend_handles,
        loc="upper left", fontsize=9, framealpha=0.9,
        title="Legend", title_fontsize=10,
    )

    # ── 統計文字 ──
    type_counts = Counter(d.get("type") for _, d in G.nodes(data=True))
    depth_counts = Counter(d.get("depth", 0) for _, d in G.nodes(data=True))
    edge_counts = Counter(d.get("relationship") for _, _, d in G.edges(data=True))

    stats_text = (
        f"Nodes: {len(G.nodes())}  Edges: {len(G.edges())}\n"
        f"Types: {', '.join(f'{t}={c}' for t, c in sorted(type_counts.items()))}\n"
        f"Depth: {', '.join(f'd{k}={v}' for k, v in sorted(depth_counts.items()))}\n"
        f"Edges: {', '.join(f'{t}={c}' for t, c in sorted(edge_counts.items()))}"
    )
    ax.text(
        0.99, 0.02, stats_text, transform=ax.transAxes,
        fontsize=8, fontfamily="monospace",
        verticalalignment="bottom", horizontalalignment="right",
        bbox=dict(boxstyle="round,pad=0.4", facecolor="white", edgecolor="#D1D5DB", alpha=0.9),
    )

    title = f"{apt_name} Prototype Subgraph — Heterogeneous Threat Graph"
    if title_suffix:
        title += f"\n{title_suffix}"
    ax.set_title(title, fontsize=14, fontweight="bold", pad=15)
    ax.axis("off")

    plt.tight_layout()

    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        fig.savefig(output_path, dpi=300, bbox_inches="tight", facecolor="white")
        print(f"已儲存: {output_path}")

    plt.close(fig)


def main():
    parser = argparse.ArgumentParser(description="繪製 APT Prototype 關聯圖譜")
    parser.add_argument("--apt", required=True, help="APT 名稱 (如 APT-C-23)")
    parser.add_argument("--focus", default=None, help="聚焦節點的 value 子字串 (局部圖)")
    parser.add_argument("--hops", type=int, default=2, help="focus 模式的 k-hop 範圍")
    parser.add_argument("--output", default=None, help="輸出檔案路徑 (預設 output/figures/)")
    args = parser.parse_args()

    data = load_prototype(args.apt)
    G = build_graph(data)

    if args.focus:
        G = extract_subgraph(G, args.focus, hops=args.hops)
        suffix = f"Focus: *{args.focus}* ({args.hops}-hop neighborhood, {len(G.nodes())} nodes)"
        fname = f"{args.apt}_focus_{args.focus[:12]}.png"
    else:
        suffix = ""
        fname = f"{args.apt}_full.png"

    out_path = Path(args.output) if args.output else OUTPUT_DIR / fname
    draw_graph(G, args.apt, title_suffix=suffix, output_path=out_path)


if __name__ == "__main__":
    main()
