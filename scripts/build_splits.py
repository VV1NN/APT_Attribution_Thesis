#!/usr/bin/env python3
"""Build train/valid/test splits for link prediction.

Protocols:
  A  — Random 80/10/10 (stratified by relation type, transductive)
  B  — Temporal split by year (≤2024 train, 2025 valid, 2026 test)
       Variants: B-Pragmatic, B-Strict, B-DNS
  C  — Report-group split (GroupKFold, for downstream attribution)

All protocols EXCLUDE has_ioc edges from prediction targets.

Output: scripts/splits/{protocol_name}.json
"""

from __future__ import annotations

import json
import random
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np

SCRIPTS = Path(__file__).resolve().parent
KG_PATH = SCRIPTS.parent / "knowledge_graphs" / "master" / "merged_kg.json"
SPLITS_DIR = SCRIPTS / "splits"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def load_kg():
    """Load merged KG, return nodes list, edges list, and node_id→index map."""
    print("Loading KG ...")
    with open(KG_PATH) as f:
        kg = json.load(f)
    nodes = kg["nodes"]
    edges = kg["edges"]
    nid2idx = {n["id"]: i for i, n in enumerate(nodes)}
    return nodes, edges, nid2idx


def get_edge_timestamp(e: dict) -> str | None:
    """Return unified timestamp string (resolution_date preferred)."""
    attrs = e.get("attributes", {})
    ts = attrs.get("resolution_date") or attrs.get("last_analysis_date")
    return ts if ts else None


def get_edge_year(e: dict) -> int | None:
    """Return year from unified timestamp, or None."""
    ts = get_edge_timestamp(e)
    if ts:
        try:
            return int(ts[:4])
        except (ValueError, TypeError):
            return None
    return None


def filter_lp_edges(edges: list[dict]) -> list[dict]:
    """Exclude has_ioc edges (not prediction targets)."""
    return [e for e in edges if e.get("relationship") != "has_ioc"]


def edge_to_triple(e: dict) -> tuple[str, str, str]:
    """Return (source, relationship, target) tuple."""
    return (e["source"], e["relationship"], e["target"])


def compute_node_set(edges: list[dict]) -> set[str]:
    """Return set of all node IDs appearing in edges."""
    s = set()
    for e in edges:
        s.add(e["source"])
        s.add(e["target"])
    return s


def partition_transductive_inductive(
    train_edges: list[dict],
    test_edges: list[dict],
) -> tuple[list[int], list[int]]:
    """Partition test edge indices into transductive / inductive.

    Transductive: both endpoints appear in train graph.
    Inductive: at least one endpoint is unseen in train.
    """
    train_nodes = compute_node_set(train_edges)
    trans_idx, ind_idx = [], []
    for i, e in enumerate(test_edges):
        if e["source"] in train_nodes and e["target"] in train_nodes:
            trans_idx.append(i)
        else:
            ind_idx.append(i)
    return trans_idx, ind_idx


def build_positive_set(edges: list[dict]) -> set[tuple[str, str, str]]:
    """Build set of all (source, rel, target) triples for filtered ranking."""
    return {edge_to_triple(e) for e in edges}


def save_split(name: str, data: dict) -> Path:
    """Save split to JSON."""
    SPLITS_DIR.mkdir(exist_ok=True)
    out = SPLITS_DIR / f"{name}.json"
    with open(out, "w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"  Saved: {out}")
    return out


# ---------------------------------------------------------------------------
# Node type → candidate set (for type-constrained ranking)
# ---------------------------------------------------------------------------

def build_type_constraint_map(nodes: list[dict]) -> dict[str, list[str]]:
    """Build node_type → list of node IDs."""
    type_map: dict[str, list[str]] = defaultdict(list)
    for n in nodes:
        type_map[n["type"]].append(n["id"])
    return dict(type_map)


def infer_tail_type(rel: str, edges: list[dict]) -> str:
    """Infer the node type of the tail for a given relation."""
    # Sample a few edges to determine tail type
    for e in edges:
        if e["relationship"] == rel:
            # We need node type info — extract from ID prefix
            target = e["target"]
            if target.startswith("file_"):
                return "file"
            elif target.startswith("domain_"):
                return "domain"
            elif target.startswith("ip_"):
                return "ip"
            elif target.startswith("email_"):
                return "email"
            elif target.startswith("apt_") or not target.startswith(("file_", "domain_", "ip_", "email_")):
                return "apt"
    return "unknown"


def build_relation_tail_types(edges: list[dict]) -> dict[str, str]:
    """For each relation, determine the expected tail node type."""
    rels = {e["relationship"] for e in edges}
    return {r: infer_tail_type(r, edges) for r in rels}


# ---------------------------------------------------------------------------
# Protocol A: Random Split
# ---------------------------------------------------------------------------

def build_protocol_a(
    lp_edges: list[dict],
    nodes: list[dict],
    seed: int = 42,
) -> dict:
    """Random 80/10/10 split, stratified by relation type, transductive."""
    rng = random.Random(seed)

    # Group by relation type
    by_rel: dict[str, list[int]] = defaultdict(list)
    for i, e in enumerate(lp_edges):
        by_rel[e["relationship"]].append(i)

    train_idx, valid_idx, test_idx = [], [], []

    for rel, indices in by_rel.items():
        rng.shuffle(indices)
        n = len(indices)
        n_test = max(1, int(n * 0.1))
        n_valid = max(1, int(n * 0.1))
        test_idx.extend(indices[:n_test])
        valid_idx.extend(indices[n_test : n_test + n_valid])
        train_idx.extend(indices[n_test + n_valid :])

    train_edges = [lp_edges[i] for i in train_idx]
    valid_edges = [lp_edges[i] for i in valid_idx]
    test_edges = [lp_edges[i] for i in test_idx]

    # Ensure transductive: move test/valid edges with unseen nodes to train
    train_nodes = compute_node_set(train_edges)

    def ensure_transductive(candidate_edges, candidate_idx):
        kept_edges, kept_idx = [], []
        moved_edges, moved_idx = [], []
        for e, idx in zip(candidate_edges, candidate_idx):
            if e["source"] in train_nodes and e["target"] in train_nodes:
                kept_edges.append(e)
                kept_idx.append(idx)
            else:
                moved_edges.append(e)
                moved_idx.append(idx)
        return kept_edges, kept_idx, moved_edges, moved_idx

    valid_edges, valid_idx, v_moved, v_moved_idx = ensure_transductive(valid_edges, valid_idx)
    train_edges.extend(v_moved)
    train_idx.extend(v_moved_idx)
    train_nodes = compute_node_set(train_edges)  # Update after moving

    test_edges, test_idx, t_moved, t_moved_idx = ensure_transductive(test_edges, test_idx)
    train_edges.extend(t_moved)
    train_idx.extend(t_moved_idx)

    # Stats
    rel_tail_types = build_relation_tail_types(lp_edges)

    train_triples = [edge_to_triple(e) for e in train_edges]
    valid_triples = [edge_to_triple(e) for e in valid_edges]
    test_triples = [edge_to_triple(e) for e in test_edges]

    # Per-relation counts
    train_rel = Counter(e["relationship"] for e in train_edges)
    valid_rel = Counter(e["relationship"] for e in valid_edges)
    test_rel = Counter(e["relationship"] for e in test_edges)

    return {
        "protocol": "A_random",
        "seed": seed,
        "train": train_triples,
        "valid": valid_triples,
        "test": test_triples,
        "train_count": len(train_triples),
        "valid_count": len(valid_triples),
        "test_count": len(test_triples),
        "relation_tail_types": rel_tail_types,
        "stats": {
            "train_per_rel": dict(train_rel),
            "valid_per_rel": dict(valid_rel),
            "test_per_rel": dict(test_rel),
            "transductive_note": "All test/valid edges have both endpoints in train graph",
        },
    }


# ---------------------------------------------------------------------------
# Protocol B: Temporal Split
# ---------------------------------------------------------------------------

def build_protocol_b(
    lp_edges: list[dict],
    nodes: list[dict],
    variant: str = "pragmatic",
) -> dict:
    """Temporal split: train ≤2024, valid 2025, test 2026.

    Variants:
      pragmatic — no-timestamp edges go to train
      strict    — no-timestamp edges excluded
      dns       — only resolves_to edges (resolution_date)
    """
    if variant == "dns":
        lp_edges = [e for e in lp_edges if e["relationship"] == "resolves_to"]

    train_edges, valid_edges, test_edges, excluded = [], [], [], []

    for e in lp_edges:
        year = get_edge_year(e)
        if year is None:
            if variant == "strict":
                excluded.append(e)
            else:
                train_edges.append(e)  # pragmatic: no-timestamp → train
        elif year <= 2024:
            train_edges.append(e)
        elif year == 2025:
            valid_edges.append(e)
        else:  # >= 2026
            test_edges.append(e)

    # Transductive / inductive partition
    trans_idx, ind_idx = partition_transductive_inductive(train_edges, test_edges)
    v_trans_idx, v_ind_idx = partition_transductive_inductive(train_edges, valid_edges)

    rel_tail_types = build_relation_tail_types(lp_edges)

    train_triples = [edge_to_triple(e) for e in train_edges]
    valid_triples = [edge_to_triple(e) for e in valid_edges]
    test_triples = [edge_to_triple(e) for e in test_edges]

    # Per-relation counts
    train_rel = Counter(e["relationship"] for e in train_edges)
    valid_rel = Counter(e["relationship"] for e in valid_edges)
    test_rel = Counter(e["relationship"] for e in test_edges)

    return {
        "protocol": f"B_{variant}",
        "train": train_triples,
        "valid": valid_triples,
        "test": test_triples,
        "train_count": len(train_triples),
        "valid_count": len(valid_triples),
        "test_count": len(test_triples),
        "excluded_count": len(excluded),
        "relation_tail_types": rel_tail_types,
        "stats": {
            "train_per_rel": dict(train_rel),
            "valid_per_rel": dict(valid_rel),
            "test_per_rel": dict(test_rel),
            "test_transductive": len(trans_idx),
            "test_inductive": len(ind_idx),
            "valid_transductive": len(v_trans_idx),
            "valid_inductive": len(v_ind_idx),
        },
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    nodes, edges, nid2idx = load_kg()
    lp_edges = filter_lp_edges(edges)
    print(f"  Total edges: {len(edges):,}")
    print(f"  LP edges (excl. has_ioc): {len(lp_edges):,}")

    # Type constraint map (for evaluator)
    type_map = build_type_constraint_map(nodes)
    SPLITS_DIR.mkdir(exist_ok=True)
    with open(SPLITS_DIR / "type_constraint_map.json", "w") as f:
        json.dump({k: len(v) for k, v in type_map.items()}, f, indent=2)
    # Save full map
    with open(SPLITS_DIR / "type_node_ids.json", "w") as f:
        json.dump(type_map, f)
    print(f"  Saved type constraint map: {len(type_map)} types")

    # Protocol A
    print("\n--- Protocol A: Random Split ---")
    pa = build_protocol_a(lp_edges, nodes)
    save_split("protocol_A_random", pa)
    print(f"  Train: {pa['train_count']:,} / Valid: {pa['valid_count']:,} / Test: {pa['test_count']:,}")

    # Protocol B variants
    for variant in ["pragmatic", "strict", "dns"]:
        print(f"\n--- Protocol B-{variant.capitalize()} ---")
        pb = build_protocol_b(lp_edges, nodes, variant=variant)
        save_split(f"protocol_B_{variant}", pb)
        print(f"  Train: {pb['train_count']:,} / Valid: {pb['valid_count']:,} / Test: {pb['test_count']:,}")
        if pb["excluded_count"]:
            print(f"  Excluded (no timestamp): {pb['excluded_count']:,}")
        s = pb["stats"]
        print(f"  Test transductive: {s['test_transductive']:,} / inductive: {s['test_inductive']:,}")

    print("\nDone.")


if __name__ == "__main__":
    main()
