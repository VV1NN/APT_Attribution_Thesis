#!/usr/bin/env python3
"""
APT Attribution Graph Builder

Builds a multi-layer graph from cleaned IoC data + VT scan results.

Three edge layers (can be toggled independently for ablation study):
  Layer 1 — Co-occurrence:    IoCs from the same source report
  Layer 2 — HIN Attributes:   IoCs sharing threat_name / imphash / tag / ASN
  Layer 3 — VT Relationships:  contacted_ips, dropped_files, etc.

Usage:
    python build_graph.py --vt-results path/to/vt_results.json \
                          --output-dir ./graph_output \
                          --layers cooccurrence,hin,vt_relationship \
                          --vt-rel-dir ./vt_relationships

Output:
    graph_output/
    ├── nodes.csv            (node_id, node_type, label, attributes...)
    ├── edges.csv            (source, target, edge_type, weight, metadata)
    ├── graph_stats.json     (topology statistics)
    ├── graph.graphml        (for Gephi / Cytoscape visualization)
    └── graph.gpickle        (NetworkX pickle for Python pipeline)
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
from collections import Counter, defaultdict
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import networkx as nx

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════
#  Configuration
# ═══════════════════════════════════════════════════════════════════

# Tags with real discriminative power (for HIN attribute nodes)
MEANINGFUL_TAGS: Set[str] = {
    "exploit", "cve-2016-4117", "cve-2017-0199", "cve-2017-11882",
    "rtf", "ole-control", "external-resources",
    "peexe", "pedll", "assembly", "64bits", "overlay",
    "malware",
}

# Threat names that directly leak APT group identity → exclude from HIN
LEAKY_THREAT_NAMES: Set[str] = {
    "apt28", "apt29", "apt30", "apt32", "apt33", "apt34", "apt35",
    "apt37", "apt38", "apt39", "apt40", "apt41",
    "lazarus", "kimsuky", "turla", "sandworm", "cozy", "fancy",
    "equation", "charming",
}


# ═══════════════════════════════════════════════════════════════════
#  Data Extraction Helpers
# ═══════════════════════════════════════════════════════════════════

def make_ioc_id(ioc_type: str, value: str) -> str:
    return f"ioc:{ioc_type}:{value.lower().strip()}"

def make_attr_id(attr_type: str, value: str) -> str:
    return f"attr:{attr_type}:{value.lower().strip()}"

def extract_ioc_attributes(record: Dict[str, Any]) -> Dict[str, Any]:
    attrs: Dict[str, Any] = {}
    ad = record.get("additional_details") or {}
    fi = record.get("file_info") or {}
    ni = record.get("network_info") or {}
    pe = fi.get("pe_info") or {}
    ptc = ad.get("popular_threat_classification") or {}

    attrs["threat_label"] = ptc.get("suggested_threat_label", "")
    attrs["threat_names"] = [
        tn["value"] for tn in ptc.get("popular_threat_name", [])
        if tn.get("value") and tn["value"].lower() not in LEAKY_THREAT_NAMES
    ]
    attrs["threat_categories"] = [
        tc["value"] for tc in ptc.get("popular_threat_category", [])
        if tc.get("value")
    ]
    attrs["file_type"] = fi.get("type_description", "")
    attrs["file_size"] = fi.get("size", 0)
    attrs["ssdeep"] = fi.get("ssdeep", "")
    attrs["tlsh"] = fi.get("tlsh", "")
    attrs["vhash"] = fi.get("vhash", "")
    attrs["imphash"] = pe.get("imphash", "")
    attrs["asn"] = ni.get("asn")
    attrs["as_owner"] = ni.get("as_owner", "")
    attrs["country"] = ni.get("country", "")
    all_tags = ad.get("tags") or []
    attrs["tags"] = [t for t in all_tags if t in MEANINGFUL_TAGS]
    attrs["all_tags"] = all_tags
    attrs["malicious_count"] = record.get("malicious_count", 0)
    attrs["total_engines"] = record.get("total_engines", 0)
    attrs["malicious_ratio"] = (
        attrs["malicious_count"] / attrs["total_engines"]
        if attrs["total_engines"] > 0 else 0.0
    )
    attrs["reputation"] = record.get("reputation", 0)
    sv = ad.get("sandbox_verdicts") or {}
    sandbox_cats = [v.get("category", "") for v in sv.values()]
    attrs["sandbox_malicious"] = sandbox_cats.count("malicious")
    attrs["sandbox_total"] = len(sandbox_cats)
    return attrs


# ═══════════════════════════════════════════════════════════════════
#  Layer 1: Co-occurrence Edges
# ═══════════════════════════════════════════════════════════════════

def build_cooccurrence_edges(
    records: List[Dict[str, Any]],
) -> Tuple[List[Dict], List[Dict]]:
    logger.info("Building Layer 1: Co-occurrence edges...")
    source_to_iocs: Dict[str, List[str]] = defaultdict(list)
    ioc_registry: Dict[str, Dict] = {}

    for r in records:
        ioc_type = r["ioc"]["type"]
        ioc_value = r["ioc"]["value"]
        ioc_id = make_ioc_id(ioc_type, ioc_value)

        if ioc_id not in ioc_registry:
            attrs = extract_ioc_attributes(r)
            ioc_registry[ioc_id] = {
                "id": ioc_id, "node_type": "ioc", "ioc_type": ioc_type,
                "label": ioc_value[:40], "value": ioc_value,
                "sources": list(set(r["ioc"].get("sources", []))),
                **attrs,
            }
        else:
            existing = set(ioc_registry[ioc_id].get("sources", []))
            new = set(r["ioc"].get("sources", []))
            ioc_registry[ioc_id]["sources"] = list(existing | new)

        for s in r["ioc"].get("sources", []):
            source_to_iocs[s].append(ioc_id)

    for s in source_to_iocs:
        source_to_iocs[s] = list(set(source_to_iocs[s]))

    nodes = list(ioc_registry.values())

    edge_set: Dict[Tuple[str, str], Dict] = {}
    for source, ioc_ids in source_to_iocs.items():
        short_source = source.split("/")[-1][:50] if "/" in source else source[:50]
        for i in range(len(ioc_ids)):
            for j in range(i + 1, len(ioc_ids)):
                a, b = min(ioc_ids[i], ioc_ids[j]), max(ioc_ids[i], ioc_ids[j])
                key = (a, b)
                if key in edge_set:
                    edge_set[key]["weight"] += 1
                    edge_set[key]["source_reports"].append(short_source)
                else:
                    edge_set[key] = {
                        "source": a, "target": b,
                        "edge_type": "co-occurrence", "weight": 1,
                        "source_reports": [short_source],
                    }

    edges = list(edge_set.values())
    logger.info(f"  Co-occurrence: {len(nodes)} IoC nodes, {len(edges)} edges from {len(source_to_iocs)} reports")
    return nodes, edges


# ═══════════════════════════════════════════════════════════════════
#  Layer 2: HIN Attribute Nodes & Edges
# ═══════════════════════════════════════════════════════════════════

def build_hin_edges(ioc_nodes: List[Dict]) -> Tuple[List[Dict], List[Dict]]:
    logger.info("Building Layer 2: HIN attribute nodes & edges...")
    attr_nodes: Dict[str, Dict] = {}
    attr_edges: List[Dict] = []

    for ioc_node in ioc_nodes:
        ioc_id = ioc_node["id"]

        for tn in ioc_node.get("threat_names", []):
            attr_id = make_attr_id("threat_name", tn)
            if attr_id not in attr_nodes:
                attr_nodes[attr_id] = {"id": attr_id, "node_type": "threat_name", "label": tn, "value": tn}
            attr_edges.append({"source": ioc_id, "target": attr_id, "edge_type": "has_threat_name", "weight": 1})

        imphash = ioc_node.get("imphash", "")
        if imphash:
            attr_id = make_attr_id("imphash", imphash)
            if attr_id not in attr_nodes:
                attr_nodes[attr_id] = {"id": attr_id, "node_type": "imphash", "label": imphash[:12] + "...", "value": imphash}
            attr_edges.append({"source": ioc_id, "target": attr_id, "edge_type": "has_imphash", "weight": 1})

        for tag in ioc_node.get("tags", []):
            attr_id = make_attr_id("tag", tag)
            if attr_id not in attr_nodes:
                attr_nodes[attr_id] = {"id": attr_id, "node_type": "tag", "label": tag, "value": tag}
            attr_edges.append({"source": ioc_id, "target": attr_id, "edge_type": "has_tag", "weight": 1})

        asn = ioc_node.get("asn")
        if asn:
            attr_id = make_attr_id("asn", str(asn))
            if attr_id not in attr_nodes:
                attr_nodes[attr_id] = {"id": attr_id, "node_type": "asn", "label": f"AS{asn}", "value": str(asn), "as_owner": ioc_node.get("as_owner", "")}
            attr_edges.append({"source": ioc_id, "target": attr_id, "edge_type": "has_asn", "weight": 1})

    logger.info(f"  HIN: {len(attr_nodes)} attribute nodes, {len(attr_edges)} attribute edges")
    attr_to_iocs: Dict[str, Set[str]] = defaultdict(set)
    for e in attr_edges:
        attr_to_iocs[e["target"]].add(e["source"])
    bridging = {k: v for k, v in attr_to_iocs.items() if len(v) >= 2}
    logger.info(f"  HIN: {len(bridging)} attribute nodes bridge 2+ IoCs")
    return list(attr_nodes.values()), attr_edges


# ═══════════════════════════════════════════════════════════════════
#  Layer 3: VT Relationship Edges
# ═══════════════════════════════════════════════════════════════════

def build_vt_relationship_edges(
    vt_relationships_dir: Optional[Path],
    org_name: str = "",
    mode: str = "per-org",
) -> Tuple[List[Dict], List[Dict]]:
    """
    Build edges from VT Relationship API data.

    mode:
      - "per-org": reads from {vt_relationships_dir}/{org_name}/files/, ips/, domains/
      - "flat":    reads from {vt_relationships_dir}/files/, ips/, domains/
      - "cache":   reads from {vt_relationships_dir}/.cache/files/, ips/, domains/
    """
    if not vt_relationships_dir or not vt_relationships_dir.exists():
        logger.info("Layer 3: VT Relationships — skipped (no data directory)")
        return [], []

    # Determine actual paths based on mode
    if mode == "per-org" and org_name:
        base = vt_relationships_dir / org_name
    elif mode == "cache":
        base = vt_relationships_dir / ".cache"
    else:
        base = vt_relationships_dir

    files_dir = base / "files"
    ips_dir = base / "ips"
    domains_dir = base / "domains"

    if not base.exists():
        logger.info(f"Layer 3: VT Relationships — skipped ({base} not found)")
        return [], []

    logger.info(f"Building Layer 3: VT Relationship edges from {base}...")
    new_nodes: Dict[str, Dict] = {}
    rel_edges: List[Dict] = []

    # ── Process file relationships ──
    if files_dir.exists():
        for fpath in files_dir.glob("*.json"):
            try:
                with fpath.open("r") as f:
                    rel_data = json.load(f)
            except Exception:
                continue

            file_hash = fpath.stem
            file_id = make_ioc_id("sha256", file_hash)

            for ip_rec in rel_data.get("contacted_ips", []):
                ip_val = ip_rec.get("id", "")
                if not ip_val:
                    continue
                ip_id = make_ioc_id("ipv4", ip_val)
                if ip_id not in new_nodes:
                    new_nodes[ip_id] = {
                        "id": ip_id, "node_type": "ioc", "ioc_type": "ipv4",
                        "label": ip_val, "value": ip_val, "discovered_via": "vt_relationship",
                    }
                rel_edges.append({"source": file_id, "target": ip_id, "edge_type": "contacted_ip", "weight": 1})

            for dom_rec in rel_data.get("contacted_domains", []):
                dom_val = dom_rec.get("id", "")
                if not dom_val:
                    continue
                dom_id = make_ioc_id("domain", dom_val)
                if dom_id not in new_nodes:
                    new_nodes[dom_id] = {
                        "id": dom_id, "node_type": "ioc", "ioc_type": "domain",
                        "label": dom_val, "value": dom_val, "discovered_via": "vt_relationship",
                    }
                rel_edges.append({"source": file_id, "target": dom_id, "edge_type": "contacted_domain", "weight": 1})

            for drop_rec in rel_data.get("dropped_files", []):
                drop_hash = drop_rec.get("id", "")
                if not drop_hash:
                    continue
                drop_id = make_ioc_id("sha256", drop_hash)
                if drop_id not in new_nodes:
                    new_nodes[drop_id] = {
                        "id": drop_id, "node_type": "ioc", "ioc_type": "sha256",
                        "label": drop_hash[:16] + "...", "value": drop_hash, "discovered_via": "vt_relationship",
                    }
                rel_edges.append({"source": file_id, "target": drop_id, "edge_type": "dropped_file", "weight": 1})

            for parent_rec in rel_data.get("execution_parents", []):
                parent_hash = parent_rec.get("id", "")
                if not parent_hash:
                    continue
                parent_id = make_ioc_id("sha256", parent_hash)
                if parent_id not in new_nodes:
                    new_nodes[parent_id] = {
                        "id": parent_id, "node_type": "ioc", "ioc_type": "sha256",
                        "label": parent_hash[:16] + "...", "value": parent_hash, "discovered_via": "vt_relationship",
                    }
                rel_edges.append({"source": parent_id, "target": file_id, "edge_type": "execution_parent", "weight": 1})

    # ── Process IP resolutions ──
    if ips_dir.exists():
        for fpath in ips_dir.glob("*.json"):
            try:
                with fpath.open("r") as f:
                    rel_data = json.load(f)
            except Exception:
                continue
            ip_val = fpath.stem
            ip_id = make_ioc_id("ipv4", ip_val)
            for res in rel_data.get("resolutions", []):
                domain = res.get("host_name", "")
                if not domain:
                    continue
                dom_id = make_ioc_id("domain", domain)
                if dom_id not in new_nodes:
                    new_nodes[dom_id] = {
                        "id": dom_id, "node_type": "ioc", "ioc_type": "domain",
                        "label": domain, "value": domain, "discovered_via": "vt_relationship",
                    }
                rel_edges.append({"source": ip_id, "target": dom_id, "edge_type": "resolves_to", "weight": 1})

    # ── Process domain resolutions ──
    if domains_dir.exists():
        for fpath in domains_dir.glob("*.json"):
            try:
                with fpath.open("r") as f:
                    rel_data = json.load(f)
            except Exception:
                continue
            domain = fpath.stem
            dom_id = make_ioc_id("domain", domain)
            for res in rel_data.get("resolutions", []):
                ip_val = res.get("ip_address", "")
                if not ip_val:
                    continue
                ip_id = make_ioc_id("ipv4", ip_val)
                if ip_id not in new_nodes:
                    new_nodes[ip_id] = {
                        "id": ip_id, "node_type": "ioc", "ioc_type": "ipv4",
                        "label": ip_val, "value": ip_val, "discovered_via": "vt_relationship",
                    }
                rel_edges.append({"source": dom_id, "target": ip_id, "edge_type": "resolves_to", "weight": 1})

    logger.info(f"  VT Relationships: {len(new_nodes)} new nodes discovered, {len(rel_edges)} edges")
    return list(new_nodes.values()), rel_edges


# ═══════════════════════════════════════════════════════════════════
#  Graph Assembly & Export
# ═══════════════════════════════════════════════════════════════════

def build_networkx_graph(all_nodes: List[Dict], all_edges: List[Dict]) -> nx.Graph:
    G = nx.Graph()
    for node in all_nodes:
        node_id = node["id"]
        flat_attrs = {}
        for k, v in node.items():
            if k == "id":
                continue
            if isinstance(v, (list, dict)):
                flat_attrs[k] = json.dumps(v, ensure_ascii=False)
            else:
                flat_attrs[k] = v
        G.add_node(node_id, **flat_attrs)

    for edge in all_edges:
        src, tgt = edge["source"], edge["target"]
        flat_attrs = {}
        for k, v in edge.items():
            if k in ("source", "target"):
                continue
            if isinstance(v, (list, dict)):
                flat_attrs[k] = json.dumps(v, ensure_ascii=False)
            else:
                flat_attrs[k] = v
        if G.has_edge(src, tgt):
            existing = G[src][tgt]
            existing["weight"] = existing.get("weight", 1) + flat_attrs.get("weight", 1)
            existing_types = set(existing.get("edge_type", "").split(","))
            existing_types.add(flat_attrs.get("edge_type", ""))
            existing["edge_type"] = ",".join(sorted(existing_types - {""}))
        else:
            G.add_edge(src, tgt, **flat_attrs)
    return G


def compute_graph_stats(G: nx.Graph, org_name: str = "") -> Dict:
    components = list(nx.connected_components(G))
    comp_sizes = sorted([len(c) for c in components], reverse=True)
    node_types = Counter(G.nodes[n].get("node_type", "unknown") for n in G.nodes())
    ioc_subtypes = Counter(G.nodes[n].get("ioc_type", "") for n in G.nodes() if G.nodes[n].get("node_type") == "ioc")
    edge_types = Counter(G[u][v].get("edge_type", "unknown") for u, v in G.edges())

    stats = {
        "organization": org_name,
        "total_nodes": G.number_of_nodes(),
        "total_edges": G.number_of_edges(),
        "connected_components": len(components),
        "component_sizes": comp_sizes[:20],
        "largest_component_pct": comp_sizes[0] / G.number_of_nodes() * 100 if comp_sizes else 0,
        "graph_density": nx.density(G),
        "node_type_distribution": dict(node_types),
        "ioc_subtype_distribution": dict(ioc_subtypes),
        "edge_type_distribution": dict(edge_types),
        "avg_degree": sum(dict(G.degree()).values()) / G.number_of_nodes() if G.number_of_nodes() > 0 else 0,
    }
    for layer_type in ["co-occurrence", "has_threat_name", "has_imphash", "has_tag", "has_asn",
                       "contacted_ip", "contacted_domain", "dropped_file", "execution_parent", "resolves_to"]:
        layer_edges = [(u, v) for u, v in G.edges() if layer_type in G[u][v].get("edge_type", "")]
        stats[f"edges_{layer_type.replace('-', '_')}"] = len(layer_edges)
    return stats


def export_graph(G: nx.Graph, all_nodes: List[Dict], all_edges: List[Dict], stats: Dict, output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)

    # nodes.csv
    nodes_path = output_dir / "nodes.csv"
    if all_nodes:
        all_keys = sorted({k for n in all_nodes for k in n.keys()})
        with nodes_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=all_keys, extrasaction="ignore")
            writer.writeheader()
            for n in all_nodes:
                row = {k: json.dumps(n[k], ensure_ascii=False) if isinstance(n.get(k), (list, dict)) else n.get(k, "") for k in all_keys}
                writer.writerow(row)
    logger.info(f"  Exported {len(all_nodes)} nodes → {nodes_path}")

    # edges.csv
    edges_path = output_dir / "edges.csv"
    if all_edges:
        edge_keys = sorted({k for e in all_edges for k in e.keys()})
        with edges_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=edge_keys, extrasaction="ignore")
            writer.writeheader()
            for e in all_edges:
                row = {k: json.dumps(e[k], ensure_ascii=False) if isinstance(e.get(k), (list, dict)) else e.get(k, "") for k in edge_keys}
                writer.writerow(row)
    logger.info(f"  Exported {len(all_edges)} edges → {edges_path}")

    # graph_stats.json
    with (output_dir / "graph_stats.json").open("w", encoding="utf-8") as f:
        json.dump(stats, f, indent=2, ensure_ascii=False)

    # graph.graphml (None → "" for compatibility)
    G_export = G.copy()
    for n in G_export.nodes():
        for k, v in list(G_export.nodes[n].items()):
            if v is None:
                G_export.nodes[n][k] = ""
    for u, v in G_export.edges():
        for k, val in list(G_export[u][v].items()):
            if val is None:
                G_export[u][v][k] = ""
    nx.write_graphml(G_export, str(output_dir / "graph.graphml"))

    # graph.gpickle
    import pickle
    with (output_dir / "graph.gpickle").open("wb") as f:
        pickle.dump(G, f, protocol=pickle.HIGHEST_PROTOCOL)

    logger.info(f"  Exported all formats to {output_dir}")


# ═══════════════════════════════════════════════════════════════════
#  Main Pipeline
# ═══════════════════════════════════════════════════════════════════

def build_graph(
    vt_results_path: Path,
    output_dir: Path,
    layers: Set[str],
    vt_relationships_dir: Optional[Path] = None,
    vt_rel_mode: str = "per-org",
) -> nx.Graph:
    logger.info(f"Loading VT results from {vt_results_path}")
    with vt_results_path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    org_name = data.get("organization", "unknown")
    results = [r for r in data.get("results", []) if r.get("vt_found")]
    logger.info(f"Organization: {org_name} | {len(results)} IoCs with VT data")

    all_nodes: List[Dict] = []
    all_edges: List[Dict] = []

    # Layer 1
    ioc_nodes, cooc_edges = build_cooccurrence_edges(results)
    all_nodes.extend(ioc_nodes)
    if "cooccurrence" in layers:
        all_edges.extend(cooc_edges)

    # Layer 2
    if "hin" in layers:
        attr_nodes, attr_edges = build_hin_edges(ioc_nodes)
        all_nodes.extend(attr_nodes)
        all_edges.extend(attr_edges)

    # Layer 3 — uses org_name to find per-org directory
    if "vt_relationship" in layers:
        vt_nodes, vt_edges = build_vt_relationship_edges(
            vt_relationships_dir, org_name=org_name, mode=vt_rel_mode
        )
        all_nodes.extend(vt_nodes)
        all_edges.extend(vt_edges)

    # Assemble
    G = build_networkx_graph(all_nodes, all_edges)
    stats = compute_graph_stats(G, org_name)
    stats["layers_enabled"] = sorted(layers)

    logger.info(f"\n{'='*50}")
    logger.info(f"Graph Summary: {org_name}")
    logger.info(f"  Nodes: {stats['total_nodes']}")
    logger.info(f"  Edges: {stats['total_edges']}")
    logger.info(f"  Components: {stats['connected_components']}")
    logger.info(f"  Largest component: {stats['largest_component_pct']:.1f}%")
    logger.info(f"  Density: {stats['graph_density']:.6f}")
    logger.info(f"  Node types: {stats['node_type_distribution']}")
    logger.info(f"  Edge types: {stats['edge_type_distribution']}")
    logger.info(f"{'='*50}\n")

    export_graph(G, all_nodes, all_edges, stats, output_dir)
    return G


# ═══════════════════════════════════════════════════════════════════
#  CLI
# ═══════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="Build multi-layer APT attribution graph")
    parser.add_argument("--vt-results", type=Path, required=True, help="Path to vt_results.json")
    parser.add_argument("--output-dir", type=Path, default=Path("./graph_output"), help="Output directory")
    parser.add_argument("--layers", type=str, default="cooccurrence,hin", help="Comma-separated: cooccurrence,hin,vt_relationship")
    parser.add_argument("--vt-rel-dir", type=Path, default=None, help="VT relationship directory (default: ./vt_relationships)")
    parser.add_argument("--vt-rel-mode", type=str, default="per-org", choices=["per-org", "flat", "cache"],
                        help="How to find VT relationship files: per-org (default), flat, or cache")
    args = parser.parse_args()

    layers = set(args.layers.split(","))
    valid_layers = {"cooccurrence", "hin", "vt_relationship"}
    invalid = layers - valid_layers
    if invalid:
        parser.error(f"Invalid layers: {invalid}. Valid: {valid_layers}")

    build_graph(
        vt_results_path=args.vt_results,
        output_dir=args.output_dir,
        layers=layers,
        vt_relationships_dir=args.vt_rel_dir,
        vt_rel_mode=args.vt_rel_mode,
    )

if __name__ == "__main__":
    main()
