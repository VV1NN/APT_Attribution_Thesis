#!/usr/bin/env python3
"""Freeze the merged KG into a verified data snapshot.

Reads merged_kg.json once, computes all counts, and writes
data_snapshot.json with the canonical numbers for the thesis.
"""

from __future__ import annotations

import hashlib
import json
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

KG_PATH = Path(__file__).resolve().parent.parent / "knowledge_graphs" / "master" / "merged_kg.json"
OUT_PATH = Path(__file__).resolve().parent / "data_snapshot.json"


def main() -> None:
    print(f"Loading {KG_PATH} ...")
    with open(KG_PATH) as f:
        raw = f.read()
    kg = json.loads(raw)

    # File hash for reproducibility
    file_hash = hashlib.sha256(raw.encode()).hexdigest()[:16]

    nodes = kg["nodes"]
    edges = kg["edges"]

    # --- Node stats ---
    node_type_counts: Counter[str] = Counter()
    vt_found_counts: Counter[str] = Counter()
    depth_counts: Counter[str] = Counter()
    for n in nodes:
        ntype = n.get("type", "unknown")
        node_type_counts[ntype] += 1
        vt_found_counts[str(n.get("vt_found", "N/A"))] += 1
        d = n.get("depth")
        depth_counts[str(d)] += 1

    # --- Edge stats ---
    edge_type_counts: Counter[str] = Counter()
    edge_with_resolution_date = 0
    edge_with_last_analysis_date = 0
    edge_no_date = 0
    org_counts: Counter[str] = Counter()
    source_reports_set: set[str] = set()
    has_ioc_count = 0

    for e in edges:
        rel = e.get("relationship", "unknown")
        edge_type_counts[rel] += 1
        org = e.get("org", "unknown")
        org_counts[org] += 1

        attrs = e.get("attributes", {})
        has_res = "resolution_date" in attrs and attrs["resolution_date"]
        has_la = "last_analysis_date" in attrs and attrs["last_analysis_date"]

        if has_res:
            edge_with_resolution_date += 1
        elif has_la:
            edge_with_last_analysis_date += 1
        else:
            edge_no_date += 1

        if rel == "has_ioc":
            has_ioc_count += 1
            reports = attrs.get("source_reports", [])
            source_reports_set.update(reports)

    # --- Temporal distribution by year ---
    year_counts: Counter[str] = Counter()
    for e in edges:
        attrs = e.get("attributes", {})
        ts = attrs.get("resolution_date") or attrs.get("last_analysis_date")
        if ts:
            try:
                year = ts[:4]
                year_counts[year] += 1
            except (TypeError, IndexError):
                pass

    # Edges available for link prediction (excluding has_ioc)
    lp_edges = len(edges) - has_ioc_count
    timed_lp_edges = edge_with_resolution_date + edge_with_last_analysis_date - has_ioc_count
    # has_ioc has 0 timestamps, so timed_lp_edges = total timed edges

    # --- Build snapshot ---
    snapshot = {
        "frozen_at": datetime.now().isoformat(),
        "source_file": str(KG_PATH),
        "source_sha256_prefix": file_hash,
        "total_nodes": len(nodes),
        "total_edges": len(edges),
        "node_types": dict(sorted(node_type_counts.items(), key=lambda x: -x[1])),
        "edge_types": dict(sorted(edge_type_counts.items(), key=lambda x: -x[1])),
        "organizations": sorted(org_counts.keys()),
        "organization_count": len(org_counts),
        "organization_edge_counts": dict(sorted(org_counts.items(), key=lambda x: -x[1])),
        "vt_found": dict(vt_found_counts),
        "depth_distribution": dict(depth_counts),
        "has_ioc_count": has_ioc_count,
        "unique_source_reports": len(source_reports_set),
        "temporal": {
            "edges_with_resolution_date": edge_with_resolution_date,
            "edges_with_last_analysis_date": edge_with_last_analysis_date,
            "edges_no_date": edge_no_date,
            "total_timed_edges": edge_with_resolution_date + edge_with_last_analysis_date,
            "year_distribution": dict(sorted(year_counts.items())),
        },
        "link_prediction": {
            "target_edges": lp_edges,
            "target_edges_note": "total_edges - has_ioc (has_ioc excluded from prediction)",
            "timed_target_edges": timed_lp_edges,
        },
    }

    with open(OUT_PATH, "w") as f:
        json.dump(snapshot, f, indent=2, ensure_ascii=False)

    # --- Print summary ---
    print(f"\n{'='*60}")
    print(f"  DATA SNAPSHOT FROZEN")
    print(f"{'='*60}")
    print(f"  Source:  {KG_PATH.name}")
    print(f"  SHA256:  {file_hash}...")
    print(f"  Nodes:   {len(nodes):,}")
    print(f"  Edges:   {len(edges):,}")
    print(f"  Orgs:    {len(org_counts)}")
    print(f"  Reports: {len(source_reports_set)}")
    print(f"")
    print(f"  Node types:")
    for t, c in sorted(node_type_counts.items(), key=lambda x: -x[1]):
        print(f"    {t:10s} {c:>8,}")
    print(f"")
    print(f"  Edge types:")
    for t, c in sorted(edge_type_counts.items(), key=lambda x: -x[1]):
        print(f"    {t:22s} {c:>8,}")
    print(f"")
    print(f"  Temporal:")
    print(f"    resolution_date:     {edge_with_resolution_date:>8,}")
    print(f"    last_analysis_date:  {edge_with_last_analysis_date:>8,}")
    print(f"    no date:             {edge_no_date:>8,}")
    print(f"")
    print(f"  Link Prediction target edges: {lp_edges:,} (excl. has_ioc)")
    print(f"  Timed target edges:           {timed_lp_edges:,}")
    print(f"")
    print(f"  Year distribution:")
    for y, c in sorted(year_counts.items()):
        print(f"    {y}: {c:>8,}")
    print(f"")
    print(f"  Output: {OUT_PATH}")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
