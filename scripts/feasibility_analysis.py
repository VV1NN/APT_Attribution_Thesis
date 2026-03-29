#!/usr/bin/env python3
"""
APT IoC 歸因可行性分析
讀取所有 per-org KG JSON，合併成統一圖，驗證：
1. 資料規模是否足夠？
2. Overlap Detection 歸因是否可行？
3. VT metadata 特徵的跨 org 區分力如何？
4. 圖結構是否有意義？
5. ML Baseline 快速測試
"""

import json, os, math, sys, logging
from collections import Counter, defaultdict
from pathlib import Path
from datetime import datetime

import networkx as nx
import numpy as np

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s",
                    datefmt="%H:%M:%S")
logger = logging.getLogger(__name__)

KG_DIR = Path("knowledge_graphs")
OUTPUT_JSON = Path("scripts/feasibility_report.json")

# ────────────────────────────────────────────────────────────
# Helper: load all org KGs into one NetworkX graph
# ────────────────────────────────────────────────────────────
def load_all_kgs():
    """Load all per-org KG JSONs into a single NetworkX DiGraph.
    Returns (G, org_list, node_orgs_map).
    node_orgs_map[node_id] = set of org names that claim this node via has_ioc.
    """
    orgs = sorted([
        d for d in os.listdir(KG_DIR)
        if (KG_DIR / d).is_dir() and d != "master"
        and (KG_DIR / d / f"{d}.json").exists()
    ])
    logger.info(f"Found {len(orgs)} orgs: {orgs}")

    G = nx.DiGraph()
    node_orgs = defaultdict(set)   # node_id -> set of orgs (via has_ioc)
    node_meta = {}                  # node_id -> {type, depth, attributes, ...}

    for org in orgs:
        with open(KG_DIR / org / f"{org}.json") as f:
            data = json.load(f)

        nodes = data.get("nodes", [])
        # edges 可能在 "edges" 或 "links" 欄位
        edges = data.get("edges", data.get("links", []))

        for n in nodes:
            nid = n["id"]
            if nid not in node_meta:
                node_meta[nid] = {
                    "type":       n.get("type"),
                    "depth":      n.get("depth"),
                    "vt_found":   n.get("vt_found"),
                    "attributes": n.get("attributes") or {},
                }
            if not G.has_node(nid):
                G.add_node(nid, **node_meta[nid])

        for e in edges:
            src = e.get("source")
            tgt = e.get("target")
            rel = e.get("relationship", "unknown")

            if rel == "has_ioc":
                # src is apt_XXX, tgt is the ioc node
                org_name = src.replace("apt_", "") if src.startswith("apt_") else org
                node_orgs[tgt].add(org_name)

            # 避免重複邊（取第一條）
            if not G.has_edge(src, tgt):
                G.add_edge(src, tgt, relationship=rel,
                           attributes=e.get("attributes") or {})

    # Ensure apt nodes exist
    for org in orgs:
        apt_nid = f"apt_{org}"
        if not G.has_node(apt_nid):
            G.add_node(apt_nid, type="apt", depth=None, attributes={})

    return G, orgs, dict(node_orgs)


# ════════════════════════════════════════════════════════════
# PART 1: 基本統計
# ════════════════════════════════════════════════════════════
def part1_basic_stats(G, orgs, node_orgs):
    logger.info("PART 1: 基本統計")
    results = {}

    # 節點 / 邊
    results["total_nodes"] = G.number_of_nodes()
    results["total_edges"] = G.number_of_edges()
    results["num_orgs"]    = len(orgs)

    # 各節點類型
    type_counts = Counter()
    for nid, d in G.nodes(data=True):
        type_counts[d.get("type", "unknown")] += 1
    results["node_types"] = dict(type_counts)

    # 各邊類型
    rel_counts = Counter()
    for u, v, d in G.edges(data=True):
        rel_counts[d.get("relationship", "unknown")] += 1
    results["edge_types"] = dict(rel_counts)

    # 各 org 的 L0 / L1 節點數
    org_stats = {}
    for org in orgs:
        apt_nid = f"apt_{org}"
        l0_nodes = set()
        for _, tgt, d in G.out_edges(apt_nid, data=True):
            if d.get("relationship") == "has_ioc":
                l0_nodes.add(tgt)
        # Count L1 nodes for this org: nodes in the org's KG with depth=1
        with open(KG_DIR / org / f"{org}.json") as f:
            org_data = json.load(f)
        l1_count = sum(1 for n in org_data.get("nodes", [])
                       if n.get("depth") == 1)
        org_stats[org] = {
            "l0_iocs": len(l0_nodes),
            "l1_nodes": l1_count,
            "total_nodes": len(org_data.get("nodes", [])),
        }
    results["org_stats"] = org_stats

    # VT metadata 覆蓋率（取樣 top-level attributes）
    coverage = defaultdict(lambda: {"present": 0, "total": 0})
    for ntype in ["file", "domain", "ip"]:
        for nid, d in G.nodes(data=True):
            if d.get("type") != ntype:
                continue
            attrs = d.get("attributes") or {}
            for key in attrs:
                fk = f"{ntype}.{key}"
                coverage[fk]["total"] += 1
                v = attrs[key]
                if v is not None and v != "" and v != [] and v != {}:
                    coverage[fk]["present"] += 1

    cov_report = {}
    for fk in sorted(coverage):
        c = coverage[fk]
        cov_report[fk] = round(c["present"] / max(c["total"], 1), 4)
    results["metadata_coverage"] = cov_report

    return results


# ════════════════════════════════════════════════════════════
# PART 2: Overlap Detection 可行性
# ════════════════════════════════════════════════════════════
def part2_overlap_detection(G, orgs, node_orgs):
    logger.info("PART 2: Overlap Detection 可行性")
    results = {}

    # 收集所有 L0 IoC（有 has_ioc 邊的非 apt 節點）
    l0_iocs = []
    for nid, org_set in node_orgs.items():
        if len(org_set) > 0:
            l0_iocs.append(nid)

    results["total_l0_iocs"] = len(l0_iocs)

    # 對每個 L0 IoC 做 leave-one-out：
    #   看它的 VT relationship 鄰居（非 has_ioc 邊）中，
    #   有多少也是某個 org 的 L0 IoC
    has_vt_neighbor = 0
    has_org_overlap = 0
    correct_vote    = 0
    total_evaluated = 0

    by_type = defaultdict(lambda: {"total": 0, "has_neighbor": 0,
                                   "has_overlap": 0, "correct": 0})
    by_org  = defaultdict(lambda: {"total": 0, "has_neighbor": 0,
                                   "has_overlap": 0, "correct": 0})

    for nid in l0_iocs:
        ntype = G.nodes[nid].get("type", "unknown")
        true_orgs = node_orgs[nid]

        # 取所有 VT relationship 鄰居（不含 has_ioc 邊）
        vt_neighbors = set()
        for u, v, d in G.out_edges(nid, data=True):
            if d.get("relationship") != "has_ioc":
                vt_neighbors.add(v)
        for u, v, d in G.in_edges(nid, data=True):
            if d.get("relationship") != "has_ioc":
                vt_neighbors.add(u)

        # 排除 apt 節點
        vt_neighbors = {n for n in vt_neighbors
                        if G.nodes.get(n, {}).get("type") != "apt"}

        total_evaluated += 1
        for org in true_orgs:
            by_org[org]["total"] += 1
        by_type[ntype]["total"] += 1

        if not vt_neighbors:
            continue
        has_vt_neighbor += 1
        by_type[ntype]["has_neighbor"] += 1
        for org in true_orgs:
            by_org[org]["has_neighbor"] += 1

        # 鄰居中哪些有 org 標記？（不含自己的 org）
        org_votes = Counter()
        for nb in vt_neighbors:
            nb_orgs = node_orgs.get(nb, set())
            for o in nb_orgs:
                org_votes[o] += 1

        # 移除自己的 org 的 self-vote（同 org 的其他 IoC 投票）
        # 但保留！因為現實場景中我們不知道答案
        # → leave-one-out: 只移除「這個 node 本身」的 org label，
        #   但其他同 org 的 node 可以投票（這模擬已知 KG 的情況）

        if not org_votes:
            continue
        has_org_overlap += 1
        by_type[ntype]["has_overlap"] += 1
        for org in true_orgs:
            by_org[org]["has_overlap"] += 1

        # 最高票 org
        top_org = org_votes.most_common(1)[0][0]
        if top_org in true_orgs:
            correct_vote += 1
            by_type[ntype]["correct"] += 1
            for org in true_orgs:
                by_org[org]["correct"] += 1

    results["connectivity_rate"]     = round(has_vt_neighbor / max(total_evaluated, 1), 4)
    results["overlap_rate"]          = round(has_org_overlap / max(total_evaluated, 1), 4)
    results["overlap_accuracy"]      = round(correct_vote / max(has_org_overlap, 1), 4)
    results["overlap_accuracy_all"]  = round(correct_vote / max(total_evaluated, 1), 4)

    results["by_type"] = {}
    for t, d in by_type.items():
        results["by_type"][t] = {
            "total":         d["total"],
            "has_neighbor":  d["has_neighbor"],
            "has_overlap":   d["has_overlap"],
            "correct":       d["correct"],
            "connectivity":  round(d["has_neighbor"] / max(d["total"], 1), 4),
            "overlap_rate":  round(d["has_overlap"] / max(d["total"], 1), 4),
            "accuracy":      round(d["correct"] / max(d["has_overlap"], 1), 4),
        }

    results["by_org"] = {}
    for org in orgs:
        d = by_org[org]
        results["by_org"][org] = {
            "total":         d["total"],
            "has_neighbor":  d["has_neighbor"],
            "has_overlap":   d["has_overlap"],
            "correct":       d["correct"],
            "connectivity":  round(d["has_neighbor"] / max(d["total"], 1), 4),
            "overlap_rate":  round(d["has_overlap"] / max(d["total"], 1), 4),
            "accuracy":      round(d["correct"] / max(d["has_overlap"], 1), 4),
        }

    return results


# ════════════════════════════════════════════════════════════
# PART 3: 跨 org 共享節點分析
# ════════════════════════════════════════════════════════════
def part3_shared_nodes(G, orgs, node_orgs):
    logger.info("PART 3: 跨 org 共享節點分析")
    results = {}

    # 找出被 ≥2 個 org 共用的節點
    shared = {nid: org_set for nid, org_set in node_orgs.items()
              if len(org_set) >= 2}
    results["total_shared_nodes"] = len(shared)

    # 按節點類型分
    shared_by_type = Counter()
    for nid in shared:
        ntype = G.nodes[nid].get("type", "unknown")
        shared_by_type[ntype] += 1
    results["shared_by_type"] = dict(shared_by_type)

    # org pair 共享分布
    pair_counts = Counter()
    for nid, org_set in shared.items():
        org_list = sorted(org_set)
        for i in range(len(org_list)):
            for j in range(i + 1, len(org_list)):
                pair_counts[(org_list[i], org_list[j])] += 1

    top_pairs = pair_counts.most_common(20)
    results["top_org_pairs"] = [
        {"pair": list(p), "shared_count": c} for p, c in top_pairs
    ]

    # Top 20 最多 org 共享的節點
    top_shared = sorted(shared.items(), key=lambda x: -len(x[1]))[:20]
    results["top_shared_nodes"] = [
        {
            "node_id": nid,
            "type": G.nodes[nid].get("type", "unknown"),
            "num_orgs": len(org_set),
            "orgs": sorted(org_set),
        }
        for nid, org_set in top_shared
    ]

    # 也找 L1 層的間接共享（兩個不同 org 的 L0 IoC 都連到同一個 L1 node）
    l1_shared = defaultdict(set)
    for nid, d in G.nodes(data=True):
        if d.get("type") == "apt":
            continue
        if d.get("depth") == 1 or (d.get("depth") is None and nid not in node_orgs):
            # 這是 L1 node，看哪些 L0 node 連過來
            for u, v, ed in G.in_edges(nid, data=True):
                if ed.get("relationship") != "has_ioc":
                    parent_orgs = node_orgs.get(u, set())
                    l1_shared[nid].update(parent_orgs)
            for u, v, ed in G.out_edges(nid, data=True):
                if ed.get("relationship") != "has_ioc":
                    parent_orgs = node_orgs.get(v, set())
                    l1_shared[nid].update(parent_orgs)

    l1_multi = {nid: orgs for nid, orgs in l1_shared.items() if len(orgs) >= 2}
    results["l1_indirect_shared"] = len(l1_multi)

    return results


# ════════════════════════════════════════════════════════════
# PART 4: VT Metadata 跨 org 區分力
# ════════════════════════════════════════════════════════════
def part4_discriminative_power(G, orgs, node_orgs):
    logger.info("PART 4: VT Metadata 跨 org 區分力")

    # 收集每個 org 的 L0 IoC 屬性
    org_l0 = defaultdict(list)  # org -> list of node_ids
    for nid, org_set in node_orgs.items():
        for org in org_set:
            org_l0[org].append(nid)

    # 定義要分析的欄位
    feature_extractors = {
        # IP features
        "ip.country":   lambda a: a.get("country"),
        "ip.continent": lambda a: a.get("continent"),
        "ip.asn":       lambda a: str(a["asn"]) if a.get("asn") else None,
        "ip.as_owner":  lambda a: a.get("as_owner"),
        "ip.rir":       lambda a: a.get("regional_internet_registry"),
        "ip.jarm":      lambda a: a.get("jarm", "")[:20] if a.get("jarm") else None,
        # Domain features
        "domain.registrar": lambda a: a.get("registrar", "").strip() if a.get("registrar") else None,
        "domain.tld":       lambda a: a.get("tld"),
        "domain.jarm":      lambda a: a.get("jarm", "")[:20] if a.get("jarm") else None,
        "domain.creation_year": lambda a: a["creation_date"][:4] if a.get("creation_date") and len(a.get("creation_date","")) >= 4 else None,
        # File features
        "file.type_tag":    lambda a: a.get("type_tag"),
        "file.pe_imphash":  lambda a: (a.get("pe_info") or {}).get("imphash"),
        "file.pe_machine":  lambda a: str((a.get("pe_info") or {}).get("machine_type")) if (a.get("pe_info") or {}).get("machine_type") else None,
        "file.threat_label": lambda a: (a.get("popular_threat_classification") or {}).get("suggested_threat_label"),
        "file.pe_resource_lang": "SPECIAL",  # multi-value
    }

    def compute_kl(org_vals):
        """Average KL(P_org || Q_global)."""
        global_counter = Counter()
        org_counters = {}
        for org, vals in org_vals.items():
            if not vals:
                continue
            c = Counter(vals)
            org_counters[org] = c
            global_counter += c
        if len(org_counters) < 3 or len(global_counter) < 2:
            return 0.0
        total = sum(global_counter.values())
        global_dist = {k: v / total for k, v in global_counter.items()}
        total_kl = 0
        for org, c in org_counters.items():
            org_total = sum(c.values())
            org_dist = {k: v / org_total for k, v in c.items()}
            kl = 0
            for k in org_dist:
                if k in global_dist and global_dist[k] > 0 and org_dist[k] > 0:
                    kl += org_dist[k] * math.log2(org_dist[k] / global_dist[k])
            total_kl += kl
        return total_kl / len(org_counters)

    results = {}
    for fname, extractor in feature_extractors.items():
        target_type = fname.split(".")[0]  # ip, domain, file

        org_vals = defaultdict(list)
        for org in orgs:
            for nid in org_l0[org]:
                nd = G.nodes.get(nid)
                if not nd or nd.get("type") != target_type:
                    continue
                attrs = nd.get("attributes") or {}
                if fname == "file.pe_resource_lang":
                    pe = attrs.get("pe_info") or {}
                    rl = pe.get("resource_langs") or {}
                    if isinstance(rl, dict):
                        for lang in rl:
                            org_vals[org].append(lang)
                else:
                    val = extractor(attrs)
                    if val is not None:
                        org_vals[org].append(val)

        kl = compute_kl(org_vals)
        global_c = Counter()
        total_vals = 0
        for org in orgs:
            global_c += Counter(org_vals[org])
            total_vals += len(org_vals[org])
        top5 = global_c.most_common(5)

        # per-org top-3
        org_top3 = {}
        for org in orgs:
            c = Counter(org_vals[org])
            org_top3[org] = c.most_common(3)

        results[fname] = {
            "kl_divergence":  round(kl, 4),
            "total_values":   total_vals,
            "unique_values":  len(global_c),
            "global_top5":    [{"value": v, "count": c} for v, c in top5],
            "org_top3":       {org: [{"value": v, "count": c} for v, c in t3]
                               for org, t3 in org_top3.items()},
        }

    # Sort by KL
    sorted_features = sorted(results.items(), key=lambda x: -x[1]["kl_divergence"])
    return {"features": dict(sorted_features)}


# ════════════════════════════════════════════════════════════
# PART 5: 圖結構分析
# ════════════════════════════════════════════════════════════
def part5_graph_structure(G, orgs, node_orgs):
    logger.info("PART 5: 圖結構分析")
    results = {}

    # 轉為無向圖做連通分量
    UG = G.to_undirected()
    components = list(nx.connected_components(UG))
    comp_sizes = sorted([len(c) for c in components], reverse=True)
    results["num_components"] = len(components)
    results["largest_component_size"] = comp_sizes[0] if comp_sizes else 0
    results["component_size_distribution"] = {
        ">1000": sum(1 for s in comp_sizes if s > 1000),
        "100-1000": sum(1 for s in comp_sizes if 100 <= s <= 1000),
        "10-99": sum(1 for s in comp_sizes if 10 <= s < 100),
        "2-9": sum(1 for s in comp_sizes if 2 <= s < 10),
        "1 (isolated)": sum(1 for s in comp_sizes if s == 1),
    }

    # 最大連通分量涵蓋幾個 org
    if components:
        largest = max(components, key=len)
        orgs_in_largest = set()
        for nid in largest:
            for org in node_orgs.get(nid, set()):
                orgs_in_largest.add(org)
        results["orgs_in_largest_component"] = sorted(orgs_in_largest)
    else:
        results["orgs_in_largest_component"] = []

    # Degree 統計
    degree_by_type = defaultdict(list)
    for nid, d in G.nodes(data=True):
        ntype = d.get("type", "unknown")
        deg = G.degree(nid)
        degree_by_type[ntype].append(deg)

    results["avg_degree_by_type"] = {}
    for ntype, degs in degree_by_type.items():
        results["avg_degree_by_type"][ntype] = {
            "mean":   round(np.mean(degs), 2),
            "median": round(np.median(degs), 2),
            "max":    int(np.max(degs)),
            "count":  len(degs),
        }

    # L0 vs L1 平均鄰居數
    l0_degs, l1_degs = [], []
    for nid, d in G.nodes(data=True):
        if d.get("type") == "apt":
            continue
        depth = d.get("depth")
        deg = G.degree(nid)
        if nid in node_orgs:
            l0_degs.append(deg)
        elif depth == 1:
            l1_degs.append(deg)

    results["l0_avg_degree"] = round(np.mean(l0_degs), 2) if l0_degs else 0
    results["l1_avg_degree"] = round(np.mean(l1_degs), 2) if l1_degs else 0

    # Density
    results["density"] = round(nx.density(G), 6)

    return results


# ════════════════════════════════════════════════════════════
# PART 6: ML Baseline
# ════════════════════════════════════════════════════════════
def part6_ml_baseline(G, orgs, node_orgs):
    logger.info("PART 6: ML Baseline 快速測試")
    results = {}

    try:
        from sklearn.model_selection import train_test_split
        from sklearn.preprocessing import LabelEncoder
        from sklearn.metrics import f1_score, accuracy_score
        from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
    except ImportError as e:
        results["error"] = f"Missing dependency: {e}. Install with: pip install scikit-learn"
        return results

    # 收集 L0 IoC 的特徵
    samples = []
    labels  = []

    # org -> index
    org_list = sorted(orgs)
    org_idx  = {o: i for i, o in enumerate(org_list)}
    n_orgs   = len(org_list)

    for nid, org_set in node_orgs.items():
        if len(org_set) != 1:
            continue  # 跳過多 org 共享的（label ambiguous）
        org = list(org_set)[0]
        if org not in org_idx:
            continue

        nd = G.nodes.get(nid)
        if not nd:
            continue
        attrs = nd.get("attributes") or {}
        ntype = nd.get("type", "unknown")

        # Feature vector
        feat = []

        # 1. detection_ratio (1d)
        feat.append(attrs.get("detection_ratio", 0) or 0)

        # 2. node type one-hot (4d: file, domain, ip, email)
        for t in ["file", "domain", "ip", "email"]:
            feat.append(1.0 if ntype == t else 0.0)

        # 3. degree (1d)
        feat.append(G.degree(nid))

        # 4. 鄰居的 org 投票分布 (n_orgs 維)
        org_votes = [0] * n_orgs
        neighbors = set()
        for u, v, d in G.out_edges(nid, data=True):
            if d.get("relationship") != "has_ioc":
                neighbors.add(v)
        for u, v, d in G.in_edges(nid, data=True):
            if d.get("relationship") != "has_ioc":
                neighbors.add(u)

        for nb in neighbors:
            nb_orgs = node_orgs.get(nb, set())
            for o in nb_orgs:
                if o in org_idx:
                    org_votes[org_idx[o]] += 1
        # Normalize
        total_votes = sum(org_votes)
        if total_votes > 0:
            org_votes = [v / total_votes for v in org_votes]
        feat.extend(org_votes)

        # 5. 鄰居平均 detection_ratio (1d)
        nb_drs = []
        for nb in neighbors:
            nb_attrs = (G.nodes.get(nb) or {}).get("attributes") or {}
            dr = nb_attrs.get("detection_ratio")
            if dr is not None:
                nb_drs.append(dr)
        feat.append(np.mean(nb_drs) if nb_drs else 0.0)

        # 6. 鄰居 country top-3 (3d: counts of top-3 countries)
        country_counter = Counter()
        for nb in neighbors:
            nb_attrs = (G.nodes.get(nb) or {}).get("attributes") or {}
            c = nb_attrs.get("country")
            if c:
                country_counter[c] += 1
        top3_countries = country_counter.most_common(3)
        for i in range(3):
            feat.append(top3_countries[i][1] if i < len(top3_countries) else 0)

        # 7. 鄰居 ASN top-3 (3d)
        asn_counter = Counter()
        for nb in neighbors:
            nb_attrs = (G.nodes.get(nb) or {}).get("attributes") or {}
            a = nb_attrs.get("asn")
            if a:
                asn_counter[a] += 1
        top3_asn = asn_counter.most_common(3)
        for i in range(3):
            feat.append(top3_asn[i][1] if i < len(top3_asn) else 0)

        samples.append(feat)
        labels.append(org_idx[org])

    if len(samples) < 50:
        results["error"] = f"Too few samples ({len(samples)})"
        return results

    X = np.array(samples, dtype=np.float32)
    y = np.array(labels, dtype=np.int32)

    logger.info(f"  ML dataset: {X.shape[0]} samples, {X.shape[1]} features, {n_orgs} classes")

    # Stratified split
    try:
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.3, random_state=42, stratify=y
        )
    except ValueError:
        # Some classes may have too few samples
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.3, random_state=42
        )

    # RandomForest (no native dependency issues)
    clf = RandomForestClassifier(
        n_estimators=300,
        max_depth=12,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1,
    )
    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_test)
    y_prob = clf.predict_proba(X_test)

    micro_f1 = f1_score(y_test, y_pred, average="micro")
    macro_f1 = f1_score(y_test, y_pred, average="macro")

    # Top-3 accuracy
    top3_correct = 0
    for i in range(len(y_test)):
        top3_classes = np.argsort(y_prob[i])[-3:]
        if y_test[i] in top3_classes:
            top3_correct += 1
    top3_acc = top3_correct / len(y_test)

    results["num_samples"]     = int(X.shape[0])
    results["num_features"]    = int(X.shape[1])
    results["num_classes"]     = n_orgs
    results["train_size"]      = int(len(X_train))
    results["test_size"]       = int(len(X_test))
    results["micro_f1"]        = round(micro_f1, 4)
    results["macro_f1"]        = round(macro_f1, 4)
    results["top3_accuracy"]   = round(top3_acc, 4)

    # Per-class F1
    from sklearn.metrics import classification_report
    # Only include classes that actually appear in the data
    present_classes = sorted(set(y))
    present_names = [org_list[i] for i in present_classes]
    report = classification_report(y_test, y_pred, labels=present_classes,
                                   target_names=present_names,
                                   output_dict=True, zero_division=0)
    results["per_class_f1"] = {
        org: round(report[org]["f1-score"], 4) for org in present_names if org in report
    }

    # Feature importance
    importances = clf.feature_importances_
    feat_names = ["detection_ratio", "type_file", "type_domain", "type_ip", "type_email",
                  "degree"] + [f"org_vote_{o}" for o in org_list] + \
                 ["nb_avg_dr", "nb_country_1", "nb_country_2", "nb_country_3",
                  "nb_asn_1", "nb_asn_2", "nb_asn_3"]
    if len(feat_names) == len(importances):
        fi = sorted(zip(feat_names, importances), key=lambda x: -x[1])
        results["feature_importance_top10"] = [
            {"feature": n, "importance": round(float(v), 4)} for n, v in fi[:10]
        ]

    return results


# ════════════════════════════════════════════════════════════
# PART 7: 過濾合法基礎設施後的 Overlap 分析
# ════════════════════════════════════════════════════════════
LEGIT_INFRA_KEYWORDS = [
    "microsoft", "amazon", "amazonaws", "google", "akamai", "cloudflare",
    "fastly", "azure", "office365", "outlook", "live.com", "hotmail",
    "googleapis", "gstatic", "cloudfront", "akadns", "edgekey",
    "msedge", "windows.net", "windowsupdate", "digicert", "verisign",
    "letsencrypt", "godaddy", "namecheap", "wordpress", "github",
    "facebook", "twitter", "linkedin", "apple", "icloud",
]


def _get_detection_ratio(G, nid):
    """Get detection_ratio for a node. Returns None if not available."""
    attrs = (G.nodes.get(nid) or {}).get("attributes") or {}
    return attrs.get("detection_ratio")


def _is_legit_infra(G, nid):
    """Heuristic: check if node ID or attributes suggest legitimate infrastructure."""
    nid_lower = nid.lower()
    attrs = (G.nodes.get(nid) or {}).get("attributes") or {}

    # Check node ID
    for kw in LEGIT_INFRA_KEYWORDS:
        if kw in nid_lower:
            return kw
    # Check as_owner
    as_owner = (attrs.get("as_owner") or "").lower()
    for kw in LEGIT_INFRA_KEYWORDS:
        if kw in as_owner:
            return kw
    # Check registrar
    registrar = (attrs.get("registrar") or "").lower()
    for kw in LEGIT_INFRA_KEYWORDS:
        if kw in registrar:
            return kw
    return None


def part7_filtered_overlap(G, orgs, node_orgs):
    logger.info("PART 7: 過濾低惡意度節點後的 Overlap 分析")
    results = {}

    DR_THRESHOLD = 0.1

    # ── 1. 重跑 overlap 分析，但過濾掉 detection_ratio < 0.1 的鄰居 ──
    l0_iocs = [nid for nid, org_set in node_orgs.items() if len(org_set) > 0]

    # Original (unfiltered) counters for comparison
    orig_has_overlap = 0
    orig_correct     = 0
    # Filtered counters
    filt_has_neighbor = 0
    filt_has_overlap  = 0
    filt_correct      = 0
    total_evaluated   = 0

    filt_by_type = defaultdict(lambda: {"total": 0, "has_neighbor": 0,
                                         "has_overlap": 0, "correct": 0})
    filt_by_org  = defaultdict(lambda: {"total": 0, "has_neighbor": 0,
                                         "has_overlap": 0, "correct": 0})

    for nid in l0_iocs:
        ntype = G.nodes[nid].get("type", "unknown")
        true_orgs = node_orgs[nid]
        total_evaluated += 1
        filt_by_type[ntype]["total"] += 1
        for org in true_orgs:
            filt_by_org[org]["total"] += 1

        # All VT relationship neighbors (same as part2)
        vt_neighbors_all = set()
        for u, v, d in G.out_edges(nid, data=True):
            if d.get("relationship") != "has_ioc":
                vt_neighbors_all.add(v)
        for u, v, d in G.in_edges(nid, data=True):
            if d.get("relationship") != "has_ioc":
                vt_neighbors_all.add(u)
        vt_neighbors_all = {n for n in vt_neighbors_all
                            if G.nodes.get(n, {}).get("type") != "apt"}

        # ── Original (unfiltered) overlap for comparison ──
        orig_org_votes = Counter()
        for nb in vt_neighbors_all:
            for o in node_orgs.get(nb, set()):
                orig_org_votes[o] += 1
        if orig_org_votes:
            orig_has_overlap += 1
            top_org_orig = orig_org_votes.most_common(1)[0][0]
            if top_org_orig in true_orgs:
                orig_correct += 1

        # ── Filtered: remove neighbors with detection_ratio < threshold ──
        vt_neighbors_filtered = set()
        for nb in vt_neighbors_all:
            dr = _get_detection_ratio(G, nb)
            if dr is not None and dr < DR_THRESHOLD:
                continue  # 過濾掉低惡意度節點
            vt_neighbors_filtered.add(nb)

        if not vt_neighbors_filtered:
            continue
        filt_has_neighbor += 1
        filt_by_type[ntype]["has_neighbor"] += 1
        for org in true_orgs:
            filt_by_org[org]["has_neighbor"] += 1

        # Org votes from filtered neighbors
        org_votes = Counter()
        for nb in vt_neighbors_filtered:
            for o in node_orgs.get(nb, set()):
                org_votes[o] += 1

        if not org_votes:
            continue
        filt_has_overlap += 1
        filt_by_type[ntype]["has_overlap"] += 1
        for org in true_orgs:
            filt_by_org[org]["has_overlap"] += 1

        top_org = org_votes.most_common(1)[0][0]
        if top_org in true_orgs:
            filt_correct += 1
            filt_by_type[ntype]["correct"] += 1
            for org in true_orgs:
                filt_by_org[org]["correct"] += 1

    results["dr_threshold"] = DR_THRESHOLD
    results["total_l0_iocs"] = total_evaluated

    # Original (unfiltered) accuracy for comparison
    results["original_overlap_accuracy"] = round(
        orig_correct / max(orig_has_overlap, 1), 4)
    results["original_has_overlap"] = orig_has_overlap

    # Filtered results
    results["filtered_connectivity_rate"] = round(
        filt_has_neighbor / max(total_evaluated, 1), 4)
    results["filtered_overlap_rate"] = round(
        filt_has_overlap / max(total_evaluated, 1), 4)
    results["filtered_overlap_accuracy"] = round(
        filt_correct / max(filt_has_overlap, 1), 4)
    results["filtered_overlap_accuracy_all"] = round(
        filt_correct / max(total_evaluated, 1), 4)
    results["filtered_has_overlap"] = filt_has_overlap

    # Accuracy delta
    results["accuracy_delta"] = round(
        results["filtered_overlap_accuracy"] - results["original_overlap_accuracy"], 4)

    results["filtered_by_type"] = {}
    for t, d in filt_by_type.items():
        results["filtered_by_type"][t] = {
            "total":        d["total"],
            "has_neighbor":  d["has_neighbor"],
            "has_overlap":   d["has_overlap"],
            "correct":       d["correct"],
            "connectivity":  round(d["has_neighbor"] / max(d["total"], 1), 4),
            "overlap_rate":  round(d["has_overlap"] / max(d["total"], 1), 4),
            "accuracy":      round(d["correct"] / max(d["has_overlap"], 1), 4),
        }

    results["filtered_by_org"] = {}
    for org in orgs:
        d = filt_by_org[org]
        results["filtered_by_org"][org] = {
            "total":        d["total"],
            "has_neighbor":  d["has_neighbor"],
            "has_overlap":   d["has_overlap"],
            "correct":       d["correct"],
            "connectivity":  round(d["has_neighbor"] / max(d["total"], 1), 4),
            "overlap_rate":  round(d["has_overlap"] / max(d["total"], 1), 4),
            "accuracy":      round(d["correct"] / max(d["has_overlap"], 1), 4),
        }

    # ── 2. Top 20 共享節點，標記合法基礎設施 ──
    # 收集所有 L1 間接共享節點（被 ≥2 org 的 L0 IoC 連到的節點）
    l1_shared = defaultdict(set)
    for nid, d in G.nodes(data=True):
        if d.get("type") == "apt":
            continue
        if nid in node_orgs:
            continue  # L0 node, skip
        # Check which orgs' L0 nodes connect to this L1 node
        for u, v, ed in G.in_edges(nid, data=True):
            if ed.get("relationship") != "has_ioc":
                parent_orgs = node_orgs.get(u, set())
                l1_shared[nid].update(parent_orgs)
        for u, v, ed in G.out_edges(nid, data=True):
            if ed.get("relationship") != "has_ioc":
                parent_orgs = node_orgs.get(v, set())
                l1_shared[nid].update(parent_orgs)

    # Also include L0 shared nodes
    all_shared = {}
    for nid, org_set in node_orgs.items():
        if len(org_set) >= 2:
            all_shared[nid] = {"orgs": org_set, "layer": "L0"}
    for nid, org_set in l1_shared.items():
        if len(org_set) >= 2:
            all_shared[nid] = {"orgs": org_set, "layer": "L1"}

    # Sort by number of orgs (descending)
    top_shared = sorted(all_shared.items(), key=lambda x: -len(x[1]["orgs"]))[:20]

    top_shared_annotated = []
    for nid, info in top_shared:
        dr = _get_detection_ratio(G, nid)
        legit = _is_legit_infra(G, nid)
        attrs = (G.nodes.get(nid) or {}).get("attributes") or {}
        top_shared_annotated.append({
            "node_id":          nid,
            "type":             G.nodes[nid].get("type", "unknown"),
            "layer":            info["layer"],
            "num_orgs":         len(info["orgs"]),
            "orgs":             sorted(info["orgs"]),
            "detection_ratio":  dr,
            "is_legit_infra":   legit,  # None or matching keyword
            "as_owner":         attrs.get("as_owner"),
            "country":          attrs.get("country"),
        })
    results["top20_shared_nodes"] = top_shared_annotated

    legit_count = sum(1 for s in top_shared_annotated if s["is_legit_infra"])
    low_dr_count = sum(1 for s in top_shared_annotated
                       if s["detection_ratio"] is not None
                       and s["detection_ratio"] < DR_THRESHOLD)
    results["top20_legit_infra_count"] = legit_count
    results["top20_low_dr_count"] = low_dr_count

    # ── 4. L1 共享節點中 detection_ratio < 0.1 的比例 ──
    l1_multi = {nid: orgs for nid, orgs in l1_shared.items() if len(orgs) >= 2}
    l1_total = len(l1_multi)
    l1_low_dr = 0
    l1_no_dr = 0
    for nid in l1_multi:
        dr = _get_detection_ratio(G, nid)
        if dr is None:
            l1_no_dr += 1
        elif dr < DR_THRESHOLD:
            l1_low_dr += 1

    results["l1_shared_total"] = l1_total
    results["l1_shared_low_dr"] = l1_low_dr
    results["l1_shared_no_dr"] = l1_no_dr
    results["l1_shared_low_dr_ratio"] = round(
        l1_low_dr / max(l1_total, 1), 4)
    results["l1_shared_low_dr_with_unknown_ratio"] = round(
        (l1_low_dr + l1_no_dr) / max(l1_total, 1), 4)

    return results


# ════════════════════════════════════════════════════════════
# 最終報告
# ════════════════════════════════════════════════════════════
def generate_summary(p1, p2, p3, p4, p5, p6, p7=None):
    """Generate human-readable summary."""

    # Overlap 結論
    if p2["overlap_accuracy"] >= 0.7:
        overlap_conclusion = "可行（準確率 ≥ 70%）"
    elif p2["overlap_accuracy"] >= 0.4:
        overlap_conclusion = "部分可行（準確率 40-70%，需結合其他特徵）"
    else:
        overlap_conclusion = "不可行（準確率 < 40%，overlap 不足以單獨歸因）"

    # 共享結論
    if p3["total_shared_nodes"] > 100:
        shared_conclusion = f"共享豐富（{p3['total_shared_nodes']} 個共享節點）"
    elif p3["total_shared_nodes"] > 20:
        shared_conclusion = f"共享中等（{p3['total_shared_nodes']} 個共享節點）"
    else:
        shared_conclusion = f"共享稀疏（{p3['total_shared_nodes']} 個共享節點）"

    # 區分力結論
    strong_features = []
    weak_features   = []
    for fname, fdata in p4["features"].items():
        if fdata["kl_divergence"] > 1.0:
            strong_features.append(fname)
        elif fdata["kl_divergence"] < 0.3:
            weak_features.append(fname)

    # ML 結論
    ml_f1 = p6.get("micro_f1", 0)
    if ml_f1 >= 0.7:
        ml_conclusion = f"資料高度可用（Micro-F1 = {ml_f1:.2%}）"
    elif ml_f1 >= 0.5:
        ml_conclusion = f"資料可用（Micro-F1 = {ml_f1:.2%}），精細化特徵工程可進一步提升"
    elif ml_f1 > 0:
        ml_conclusion = f"資料有基本區分力（Micro-F1 = {ml_f1:.2%}），需更多 org 或特徵"
    else:
        ml_conclusion = f"ML baseline 未執行或失敗"

    # 整體
    score = 0
    if p2["overlap_accuracy"] >= 0.4: score += 1
    if p3["total_shared_nodes"] > 20: score += 1
    if len(strong_features) >= 3: score += 1
    if ml_f1 >= 0.5: score += 1

    if score >= 3:
        overall = "方法可行，建議繼續擴充資料並精細化歸因模型"
    elif score >= 2:
        overall = "方法部分可行，建議結合多種歸因線索（overlap + metadata + 圖結構）"
    else:
        overall = "資料不足或方法需調整，建議增加更多 APT 組織的 KG 資料"

    lines = [
        "",
        "═" * 60,
        "APT IoC 歸因可行性分析報告",
        f"分析時間: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "═" * 60,
        "",
        f"資料規模: {p1['total_nodes']:,} nodes, {p1['total_edges']:,} edges, {p1['num_orgs']} orgs",
        f"  節點類型: {p1['node_types']}",
        f"  邊類型:   {p1['edge_types']}",
        "",
        "─" * 60,
        "Overlap Detection:",
        f"  L0 IoC 總數:        {p2['total_l0_iocs']}",
        f"  連通率 (有 VT 鄰居): {p2['connectivity_rate']:.1%}",
        f"  Overlap 率:          {p2['overlap_rate']:.1%}",
        f"  Overlap 歸因準確率:  {p2['overlap_accuracy']:.1%}",
        f"  全體歸因準確率:      {p2['overlap_accuracy_all']:.1%}",
        f"  結論: {overlap_conclusion}",
        "",
        "  按節點類型:",
    ]
    for t, d in sorted(p2["by_type"].items()):
        lines.append(f"    {t:8s}  n={d['total']:4d}  connectivity={d['connectivity']:.1%}  overlap={d['overlap_rate']:.1%}  accuracy={d['accuracy']:.1%}")
    lines.append("")
    lines.append("  按組織:")
    for org in sorted(p2["by_org"], key=lambda o: -p2["by_org"][o]["total"]):
        d = p2["by_org"][org]
        lines.append(f"    {org:20s}  n={d['total']:4d}  connectivity={d['connectivity']:.1%}  overlap={d['overlap_rate']:.1%}  accuracy={d['accuracy']:.1%}")

    lines += [
        "",
        "─" * 60,
        "跨 org 共享:",
        f"  共享節點數 (L0 直接): {p3['total_shared_nodes']}",
        f"  按類型: {p3['shared_by_type']}",
        f"  L1 間接共享節點數:    {p3['l1_indirect_shared']}",
        f"  結論: {shared_conclusion}",
        "",
        "  Top-5 共享 org pairs:",
    ]
    for item in p3["top_org_pairs"][:5]:
        lines.append(f"    {item['pair'][0]:20s} ↔ {item['pair'][1]:20s}  共享 {item['shared_count']} 個節點")

    lines += [
        "",
        "─" * 60,
        "VT Metadata 區分力 (KL divergence, 只看 L0 IoC):",
        f"  強區分力 (KL>1.0): {strong_features}",
        f"  弱區分力 (KL<0.3): {weak_features}",
        "",
    ]
    for fname, fdata in p4["features"].items():
        top3_str = ", ".join(f"{v['value']}({v['count']})" for v in fdata["global_top5"][:3])
        lines.append(f"  {fname:25s}  KL={fdata['kl_divergence']:.3f}  unique={fdata['unique_values']:4d}  top3: {top3_str}")

    lines += [
        "",
        "─" * 60,
        "圖結構:",
        f"  連通分量數: {p5['num_components']}",
        f"  最大分量:   {p5['largest_component_size']:,} nodes ({len(p5['orgs_in_largest_component'])} orgs)",
        f"  分量大小分布: {p5['component_size_distribution']}",
        f"  L0 平均 degree: {p5['l0_avg_degree']}",
        f"  L1 平均 degree: {p5['l1_avg_degree']}",
        f"  圖密度: {p5['density']}",
        "",
        "  平均 degree by type:",
    ]
    for t, d in sorted(p5["avg_degree_by_type"].items()):
        lines.append(f"    {t:8s}  mean={d['mean']:.1f}  median={d['median']:.0f}  max={d['max']}")

    lines += [
        "",
        "─" * 60,
        "ML Baseline (XGBoost):",
    ]
    if "error" in p6:
        lines.append(f"  Error: {p6['error']}")
    else:
        lines.append(f"  樣本數:    {p6.get('num_samples', 'N/A')}")
        lines.append(f"  特徵維度:  {p6.get('num_features', 'N/A')}")
        lines.append(f"  Micro-F1:  {p6.get('micro_f1', 0):.2%}")
        lines.append(f"  Macro-F1:  {p6.get('macro_f1', 0):.2%}")
        lines.append(f"  Top-3 Acc: {p6.get('top3_accuracy', 0):.2%}")
        lines.append(f"  結論: {ml_conclusion}")
        if "per_class_f1" in p6:
            lines.append("")
            lines.append("  Per-class F1:")
            for org, f1 in sorted(p6["per_class_f1"].items(), key=lambda x: -x[1]):
                lines.append(f"    {org:20s}  F1={f1:.2%}")
        if "feature_importance_top10" in p6:
            lines.append("")
            lines.append("  Feature importance top-10:")
            for fi in p6["feature_importance_top10"]:
                lines.append(f"    {fi['feature']:25s}  {fi['importance']:.4f}")

    # ── PART 7: 過濾合法基礎設施後的 Overlap 分析 ──
    if p7:
        lines += [
            "",
            "─" * 60,
            f"過濾低惡意度節點後的 Overlap 分析 (detection_ratio < {p7['dr_threshold']}):",
            f"  過濾前 overlap 準確率: {p7['original_overlap_accuracy']:.1%} ({p7['original_has_overlap']} IoCs with overlap)",
            f"  過濾後 overlap 準確率: {p7['filtered_overlap_accuracy']:.1%} ({p7['filtered_has_overlap']} IoCs with overlap)",
            f"  準確率變化:            {p7['accuracy_delta']:+.1%}",
            f"  過濾後連通率:          {p7['filtered_connectivity_rate']:.1%}",
            f"  過濾後 overlap 率:     {p7['filtered_overlap_rate']:.1%}",
            f"  過濾後全體歸因準確率:  {p7['filtered_overlap_accuracy_all']:.1%}",
            "",
            "  過濾後按節點類型:",
        ]
        for t, d in sorted(p7["filtered_by_type"].items()):
            lines.append(f"    {t:8s}  n={d['total']:4d}  connectivity={d['connectivity']:.1%}  overlap={d['overlap_rate']:.1%}  accuracy={d['accuracy']:.1%}")

        lines += [
            "",
            "  過濾後按組織:",
        ]
        for org in sorted(p7["filtered_by_org"], key=lambda o: -p7["filtered_by_org"][o]["total"]):
            d = p7["filtered_by_org"][org]
            lines.append(f"    {org:20s}  n={d['total']:4d}  connectivity={d['connectivity']:.1%}  overlap={d['overlap_rate']:.1%}  accuracy={d['accuracy']:.1%}")

        lines += [
            "",
            "  Top-20 共享節點（標記合法基礎設施）:",
            f"  （其中 {p7['top20_legit_infra_count']}/20 為合法基礎設施，{p7['top20_low_dr_count']}/20 detection_ratio < {p7['dr_threshold']}）",
        ]
        for s in p7["top20_shared_nodes"]:
            dr_str = f"{s['detection_ratio']:.3f}" if s['detection_ratio'] is not None else "N/A"
            legit_str = f" ⚠️ LEGIT({s['is_legit_infra']})" if s['is_legit_infra'] else ""
            lines.append(
                f"    {s['node_id'][:50]:50s}  {s['type']:7s}  {s['layer']}  "
                f"orgs={s['num_orgs']}  dr={dr_str}  "
                f"as_owner={s.get('as_owner', 'N/A')}{legit_str}"
            )

        lines += [
            "",
            f"  L1 共享節點 detection_ratio 統計:",
            f"    總數:                        {p7['l1_shared_total']}",
            f"    detection_ratio < {p7['dr_threshold']}:      {p7['l1_shared_low_dr']} ({p7['l1_shared_low_dr_ratio']:.1%})",
            f"    detection_ratio 未知:        {p7['l1_shared_no_dr']}",
            f"    低惡意度+未知 佔比:          {p7['l1_shared_low_dr_with_unknown_ratio']:.1%}",
        ]

        # Conclusion for Part 7
        if p7["filtered_overlap_accuracy"] >= 0.85:
            filt_conclusion = "✅ 過濾後準確率 ≥ 85%，overlap 方法 solid"
        elif p7["filtered_overlap_accuracy"] >= 0.50:
            filt_conclusion = "⚠️ 過濾後準確率 50-85%，建議加入 detection_ratio 加權"
        else:
            filt_conclusion = "❌ 過濾後準確率 < 50%，需重新設計 overlap 投票機制（加 detection_ratio 權重）"
        lines.append(f"  結論: {filt_conclusion}")

    lines += [
        "",
        "═" * 60,
        f"整體結論: {overall}",
        "═" * 60,
        "",
    ]

    return "\n".join(lines)


# ════════════════════════════════════════════════════════════
# Main
# ════════════════════════════════════════════════════════════
def main():
    logger.info("載入所有 KG...")
    G, orgs, node_orgs = load_all_kgs()
    logger.info(f"合併完成: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")

    p1 = part1_basic_stats(G, orgs, node_orgs)
    p2 = part2_overlap_detection(G, orgs, node_orgs)
    p3 = part3_shared_nodes(G, orgs, node_orgs)
    p4 = part4_discriminative_power(G, orgs, node_orgs)
    p5 = part5_graph_structure(G, orgs, node_orgs)
    p6 = part6_ml_baseline(G, orgs, node_orgs)
    p7 = part7_filtered_overlap(G, orgs, node_orgs)

    # Save JSON
    full_report = {
        "timestamp":  datetime.now().isoformat(),
        "part1_basic_stats":        p1,
        "part2_overlap_detection":  p2,
        "part3_shared_nodes":       p3,
        "part4_discriminative":     p4,
        "part5_graph_structure":    p5,
        "part6_ml_baseline":        p6,
        "part7_filtered_overlap":   p7,
    }
    OUTPUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_JSON, "w") as f:
        json.dump(full_report, f, indent=2, ensure_ascii=False, default=str)
    logger.info(f"JSON 報告已儲存: {OUTPUT_JSON}")

    # Print summary
    summary = generate_summary(p1, p2, p3, p4, p5, p6, p7)
    print(summary)

    # Also save summary as text
    summary_path = OUTPUT_JSON.with_suffix(".txt")
    with open(summary_path, "w") as f:
        f.write(summary)
    logger.info(f"文字報告已儲存: {summary_path}")


if __name__ == "__main__":
    main()
