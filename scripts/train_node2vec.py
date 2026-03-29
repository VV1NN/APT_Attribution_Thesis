#!/usr/bin/env python3
"""
在 Master KG 上訓練 Node2Vec 嵌入（64d）。
移除 apt 節點，轉無向圖，p=1.0, q=0.5（偏 BFS，捕捉社區結構）。
輸出：scripts/features/node2vec_embeddings.npz
"""

import json
import logging
from pathlib import Path

import numpy as np
import networkx as nx
from node2vec import Node2Vec

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S")
logger = logging.getLogger(__name__)

KG_JSON = Path("knowledge_graphs/master/merged_kg.json")
OUTPUT = Path("scripts/features/node2vec_embeddings.npz")

DIMENSIONS = 64
WALK_LENGTH = 30
NUM_WALKS = 20
P = 1.0
Q = 0.5
WINDOW = 10
WORKERS = 8


def main():
    logger.info("Loading Master KG...")
    with open(KG_JSON) as f:
        data = json.load(f)

    G = nx.Graph()  # 無向圖
    apt_nodes = set()

    for n in data["nodes"]:
        nid = n["id"]
        if n.get("type") == "apt":
            apt_nodes.add(nid)
            continue
        G.add_node(nid)

    for e in data["edges"]:
        src, tgt = e["source"], e["target"]
        if src in apt_nodes or tgt in apt_nodes:
            continue
        if e.get("relationship") == "has_ioc":
            continue
        if G.has_node(src) and G.has_node(tgt):
            G.add_edge(src, tgt)

    logger.info(f"Graph: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")

    # 移除孤立節點（加速訓練）
    isolates = list(nx.isolates(G))
    G.remove_nodes_from(isolates)
    logger.info(f"After removing {len(isolates)} isolates: {G.number_of_nodes()} nodes")

    logger.info(f"Training Node2Vec (d={DIMENSIONS}, walks={NUM_WALKS}, len={WALK_LENGTH}, p={P}, q={Q})...")
    n2v = Node2Vec(G, dimensions=DIMENSIONS, walk_length=WALK_LENGTH,
                   num_walks=NUM_WALKS, p=P, q=Q, workers=WORKERS, quiet=False)

    logger.info("Fitting Word2Vec model...")
    model = n2v.fit(window=WINDOW, min_count=1, batch_words=4)

    # 匯出 embeddings
    node_ids = []
    embeddings = []
    for node in G.nodes():
        try:
            vec = model.wv[node]
            node_ids.append(node)
            embeddings.append(vec)
        except KeyError:
            continue

    embeddings = np.array(embeddings, dtype=np.float32)
    logger.info(f"Embeddings: {embeddings.shape}")

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(OUTPUT, node_ids=np.array(node_ids), embeddings=embeddings)
    logger.info(f"Saved to {OUTPUT}")


if __name__ == "__main__":
    main()
