#!/usr/bin/env python3
"""
四層特徵提取 — Layer 1（節點自身 88d）+ Layer 2（鄰域統計 35d）+ Layer 3（Overlap 7+Kd）。
輸出：scripts/features/features_l1_l2_l3.npz + feature_names.json
"""

import json
import math
import logging
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

import numpy as np

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S")
logger = logging.getLogger(__name__)

KG_JSON = Path("knowledge_graphs/master/merged_kg.json")
VOCAB_PATH = Path("scripts/vocabularies.json")
OUTPUT_DIR = Path("scripts/features")

REF_DATE = datetime(2026, 1, 1)
MIN_IOCS = 100  # org 門檻


# ════════════════════════════════════════════════════════════
# Data Loading
# ════════════════════════════════════════════════════════════

def load_kg():
    """載入 Master KG，回傳 nodes dict + adjacency。"""
    logger.info("Loading Master KG...")
    with open(KG_JSON) as f:
        data = json.load(f)

    nodes = {}  # id -> {type, depth, attributes, orgs}
    for n in data["nodes"]:
        nodes[n["id"]] = {
            "type": n.get("type"),
            "depth": n.get("depth"),
            "attributes": n.get("attributes") or {},
            "orgs": set(n.get("orgs") or []),
        }

    # 建立鄰接表（不含 has_ioc 和 apt 節點）+ 記錄 has_ioc 邊
    adj = defaultdict(set)              # node_id -> set of neighbor ids
    edge_by_node = defaultdict(list)    # node_id -> list of (neighbor_id, rel, edge_attrs)
    has_ioc_orgs = defaultdict(set)     # node_id -> set of orgs (from has_ioc edges only)
    for e in data["edges"]:
        rel = e.get("relationship", "unknown")
        src, tgt = e["source"], e["target"]
        if rel == "has_ioc":
            org = src.replace("apt_", "") if src.startswith("apt_") else src
            has_ioc_orgs[tgt].add(org)
            continue
        if nodes.get(src, {}).get("type") == "apt" or nodes.get(tgt, {}).get("type") == "apt":
            continue
        adj[src].add(tgt)
        adj[tgt].add(src)
        ea = e.get("attributes") or {}
        edge_by_node[src].append((tgt, rel, ea))
        edge_by_node[tgt].append((src, rel, ea))

    logger.info(f"  {len(nodes)} nodes, adj covers {len(adj)} nodes, "
                f"has_ioc targets: {len(has_ioc_orgs)}")
    return nodes, adj, edge_by_node, has_ioc_orgs


def build_overlap_dict(has_ioc_orgs):
    """node_id -> set of orgs。只用 has_ioc 邊的目標（L0 IoC），不含 L1 transitive label。"""
    return dict(has_ioc_orgs)


# ════════════════════════════════════════════════════════════
# Helpers
# ════════════════════════════════════════════════════════════

def _ord(vocab, value):
    """Ordinal encode: value -> index (0=OTHER)。"""
    if value is None:
        return np.nan
    return float(vocab.get(value, vocab.get("__OTHER__", 0)))


def _freq_dim(value_counts, value):
    """第二維：log1p(此值在 KG 中的出現次數)。"""
    if value is None:
        return np.nan
    return math.log1p(value_counts.get(value, 0))


def _parse_date(s):
    if not s or not isinstance(s, str):
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d"):
        try:
            return datetime.strptime(s[:len(fmt.replace('%', 'X'))], fmt)
        except (ValueError, IndexError):
            continue
    try:
        return datetime(int(s[:4]), 6, 15) if len(s) >= 4 and s[:4].isdigit() else None
    except ValueError:
        return None


def _days_since(s):
    dt = _parse_date(s)
    if dt is None:
        return np.nan
    return float(max((REF_DATE - dt).days, 0))


NAN = np.nan


# ════════════════════════════════════════════════════════════
# Layer 1: Node Self Features (88d)
# ════════════════════════════════════════════════════════════

L1_NAMES = [
    # Shared (6d)
    "detection_ratio", "malicious", "suspicious", "harmless", "undetected", "reputation",
    # Node type (4d)
    "is_file", "is_domain", "is_ip", "is_email",
    # File (37d)
    "file_log_size", "file_type_tag", "file_type_extension", "file_has_pe",
    "file_section_count", "file_avg_entropy", "file_max_entropy", "file_std_entropy",
    "file_total_raw_size", "file_entry_point", "file_machine_type", "file_imphash_freq",
    "file_resource_lang_count", "file_dominant_resource_lang", "file_import_dll_count",
    "file_days_since_creation", "file_days_since_first_seen", "file_days_since_first_sub",
    "file_days_since_last_sub", "file_first_seen_to_sub_gap",
    "file_log_times_submitted", "file_log_unique_sources",
    "file_votes_malicious", "file_votes_harmless", "file_is_signed", "file_has_packer",
    "file_threat_label", "file_threat_label_2", "file_threat_category", "file_threat_category_2",
    "file_tag_count", "file_has_anti_analysis", "file_has_overlay",
    "file_has_bundle", "file_bundle_children", "file_has_version_info", "file_compiler_count",
    # Domain (20d)
    "domain_registrar", "domain_registrar_2", "domain_tld", "domain_tld_2",
    "domain_creation_age_days", "domain_last_update_age_days", "domain_creation_to_update_gap",
    "domain_cat_malware", "domain_cat_phishing", "domain_cat_c2", "domain_cat_botnet",
    "domain_cat_vendor_count", "domain_has_dns_a", "domain_has_dns_aaaa", "domain_has_dns_mx",
    "domain_dns_record_count", "domain_has_whois", "domain_jarm_nonzero", "domain_jarm_freq",
    "domain_votes_diff",
    # IP (15d)
    "ip_country", "ip_country_2", "ip_continent", "ip_log_asn",
    "ip_as_owner", "ip_as_owner_2", "ip_rir", "ip_cidr_prefix",
    "ip_jarm_nonzero", "ip_jarm_freq", "ip_votes_diff",
    "ip_tag_count", "ip_has_malware_tag", "ip_has_cert", "ip_is_self_signed",
    # Email (6d)
    "email_is_protonmail", "email_is_tutanota", "email_is_yandex",
    "email_is_mailru", "email_is_mainstream", "email_is_custom_domain",
]
assert len(L1_NAMES) == 88, f"Expected 88, got {len(L1_NAMES)}"


def extract_l1(nid, nd, vocabs, value_counts, freq_tables):
    """回傳長度 88 的 list（float 或 NaN）。"""
    a = nd["attributes"]
    t = nd["type"]
    f = [NAN] * 88
    i = 0

    # ── Shared (6d) ──
    f[0] = float(a.get("detection_ratio") or NAN)
    f[1] = float(a["malicious"]) if a.get("malicious") is not None else NAN
    f[2] = float(a["suspicious"]) if a.get("suspicious") is not None else NAN
    f[3] = float(a["harmless"]) if a.get("harmless") is not None else NAN
    f[4] = float(a["undetected"]) if a.get("undetected") is not None else NAN
    f[5] = float(a["reputation"]) if a.get("reputation") is not None else NAN

    # ── Node type (4d) ──
    f[6] = 1.0 if t == "file" else 0.0
    f[7] = 1.0 if t == "domain" else 0.0
    f[8] = 1.0 if t == "ip" else 0.0
    f[9] = 1.0 if t == "email" else 0.0

    # ── File (37d, index 10-46) ──
    if t == "file":
        f[10] = math.log1p(a.get("size") or 0)
        f[11] = _ord(vocabs["type_tag"], a.get("type_tag"))
        f[12] = _ord(vocabs["type_extension"], a.get("type_extension"))

        pe = a.get("pe_info") or {}
        f[13] = 1.0 if pe else 0.0

        sections = pe.get("sections") or []
        f[14] = float(len(sections))
        ents = [s["entropy"] for s in sections if isinstance(s, dict) and s.get("entropy") is not None]
        if ents:
            f[15] = float(np.mean(ents))
            f[16] = float(np.max(ents))
            f[17] = float(np.std(ents)) if len(ents) > 1 else 0.0
        f[18] = float(sum(s.get("raw_size", 0) for s in sections if isinstance(s, dict)))
        f[19] = math.log1p(pe.get("entry_point") or 0) if pe.get("entry_point") is not None else NAN
        f[20] = float(pe["machine_type"]) if pe.get("machine_type") is not None else NAN

        imphash = pe.get("imphash")
        f[21] = float(freq_tables["imphash"].get(imphash, 0)) if imphash else NAN

        rl = pe.get("resource_langs") or {}
        if isinstance(rl, dict) and rl:
            f[22] = float(len(rl))
            dominant = max(rl, key=rl.get)
            f[23] = _ord(vocabs["resource_lang"], dominant)
        else:
            f[22] = 0.0

        imports = pe.get("imports") or []
        f[24] = float(len(imports)) if isinstance(imports, (list, dict)) else NAN

        f[25] = _days_since(a.get("creation_time"))
        f[26] = _days_since(a.get("first_seen_itw"))
        f[27] = _days_since(a.get("first_submission"))
        f[28] = _days_since(a.get("last_submission"))

        d1 = _parse_date(a.get("first_seen_itw"))
        d2 = _parse_date(a.get("first_submission"))
        f[29] = float((d2 - d1).days) if d1 and d2 else NAN

        f[30] = math.log1p(a.get("times_submitted") or 0)
        f[31] = math.log1p(a.get("unique_sources") or 0)

        tv = a.get("total_votes") or {}
        f[32] = float(tv.get("malicious", 0)) if isinstance(tv, dict) else 0.0
        f[33] = float(tv.get("harmless", 0)) if isinstance(tv, dict) else 0.0

        f[34] = 1.0 if a.get("signature_verified") == "Signed" else 0.0
        packers = a.get("packers")
        f[35] = 1.0 if packers and (len(packers) > 0 if isinstance(packers, (list, dict)) else True) else 0.0

        tc = a.get("popular_threat_classification") or {}
        tl = tc.get("suggested_threat_label")
        f[36] = _ord(vocabs["threat_label"], tl)
        f[37] = _freq_dim(value_counts.get("threat_label", {}), tl)

        cats = tc.get("popular_threat_category") or []
        if cats and isinstance(cats, list):
            c0 = cats[0].get("value", "") if isinstance(cats[0], dict) else str(cats[0])
            f[38] = _ord(vocabs["threat_category"], c0)
            if len(cats) > 1:
                c1 = cats[1].get("value", "") if isinstance(cats[1], dict) else str(cats[1])
                f[39] = _ord(vocabs["threat_category"], c1)

        tags = a.get("tags") or []
        f[40] = float(len(tags))
        tags_low = [x.lower() for x in tags] if tags else []
        f[41] = 1.0 if any(x in tags_low for x in ["long-sleeps", "detect-debug-environment"]) else 0.0
        f[42] = 1.0 if "overlay" in tags_low else 0.0

        bundle = a.get("bundle_info")
        f[43] = 1.0 if bundle else 0.0
        f[44] = float((bundle or {}).get("num_children", 0))

        f[45] = 1.0 if a.get("file_version_info") else 0.0
        f[46] = float(len(pe.get("compiler_product_versions") or []))

    # ── Domain (20d, index 47-66) ──
    if t == "domain":
        reg = (a.get("registrar") or "").strip() or None
        f[47] = _ord(vocabs["registrar"], reg)
        f[48] = _freq_dim(value_counts.get("registrar", {}), reg)

        tld = a.get("tld")
        f[49] = _ord(vocabs["tld"], tld)
        f[50] = _freq_dim(value_counts.get("tld", {}), tld)

        f[51] = _days_since(a.get("creation_date"))
        f[52] = _days_since(a.get("last_update_date"))
        d1 = _parse_date(a.get("creation_date"))
        d2 = _parse_date(a.get("last_update_date"))
        f[53] = float((d2 - d1).days) if d1 and d2 else NAN

        cats = a.get("categories") or {}
        cv = " ".join(str(v).lower() for v in cats.values()) if isinstance(cats, dict) else str(cats).lower()
        f[54] = 1.0 if "malware" in cv else 0.0
        f[55] = 1.0 if "phishing" in cv else 0.0
        f[56] = 1.0 if any(k in cv for k in ["command", "c2", "c&c"]) else 0.0
        f[57] = 1.0 if "botnet" in cv else 0.0
        f[58] = float(len(cats)) if isinstance(cats, dict) else 0.0

        dns = a.get("last_dns_records") or []
        f[59] = 1.0 if any(r.get("type") == "A" for r in dns if isinstance(r, dict)) else 0.0
        f[60] = 1.0 if any(r.get("type") == "AAAA" for r in dns if isinstance(r, dict)) else 0.0
        f[61] = 1.0 if any(r.get("type") == "MX" for r in dns if isinstance(r, dict)) else 0.0
        f[62] = float(len(dns))

        f[63] = 1.0 if a.get("has_whois") else 0.0

        jarm = a.get("jarm") or ""
        f[64] = 1.0 if jarm and jarm.replace("0", "") != "" else 0.0
        f[65] = float(freq_tables["jarm"].get(jarm, 0)) if jarm and jarm.replace("0", "") != "" else NAN

        tv = a.get("total_votes") or {}
        f[66] = float(tv.get("malicious", 0) - tv.get("harmless", 0)) if isinstance(tv, dict) else 0.0

    # ── IP (15d, index 67-81) ──
    if t == "ip":
        f[67] = _ord(vocabs["country"], a.get("country"))
        f[68] = _freq_dim(value_counts.get("country", {}), a.get("country"))
        f[69] = _ord(vocabs["continent"], a.get("continent"))
        f[70] = math.log1p(a.get("asn") or 0) if a.get("asn") else NAN

        f[71] = _ord(vocabs["as_owner"], a.get("as_owner"))
        f[72] = _freq_dim(value_counts.get("as_owner", {}), a.get("as_owner"))
        f[73] = _ord(vocabs["rir"], a.get("regional_internet_registry"))

        net = str(a.get("network") or "")
        f[74] = float(net.split("/")[1]) if "/" in net else NAN

        jarm = a.get("jarm") or ""
        f[75] = 1.0 if jarm and jarm.replace("0", "") != "" else 0.0
        f[76] = float(freq_tables["jarm"].get(jarm, 0)) if jarm and jarm.replace("0", "") != "" else NAN

        tv = a.get("total_votes") or {}
        f[77] = float(tv.get("malicious", 0) - tv.get("harmless", 0)) if isinstance(tv, dict) else 0.0

        tags = a.get("tags") or []
        f[78] = float(len(tags))
        f[79] = 1.0 if "malware" in str(tags).lower() else 0.0

        cert = a.get("last_https_certificate")
        f[80] = 1.0 if cert else 0.0
        if cert and isinstance(cert, dict):
            f[81] = 1.0 if cert.get("issuer") == cert.get("subject") else 0.0

    # ── Email (6d, index 82-87) ──
    if t == "email":
        domain_part = nid.replace("email_", "", 1).split("@")[-1].lower() if "@" in nid else ""
        f[82] = 1.0 if any(k in domain_part for k in ["protonmail", "proton.me"]) else 0.0
        f[83] = 1.0 if any(k in domain_part for k in ["tutanota", "tuta.io"]) else 0.0
        f[84] = 1.0 if "yandex" in domain_part else 0.0
        f[85] = 1.0 if "mail.ru" in domain_part else 0.0
        f[86] = 1.0 if any(k in domain_part for k in ["gmail", "outlook", "hotmail", "yahoo"]) else 0.0
        known = ["gmail", "outlook", "hotmail", "yahoo", "protonmail", "proton.me",
                 "tutanota", "tuta.io", "yandex", "mail.ru"]
        f[87] = 1.0 if domain_part and not any(k in domain_part for k in known) else 0.0

    return f


# ════════════════════════════════════════════════════════════
# Layer 2: Neighborhood Statistics (35d)
# ════════════════════════════════════════════════════════════

EDGE_TYPES = [
    "contacted_ip", "contacted_domain", "contacted_url",
    "dropped_file", "execution_parent", "bundled_file",
    "resolves_to", "has_subdomain", "communicating_file", "referrer_file",
]  # 10 types + total_degree = 11d; 再加一個 log_degree = 12d

L2_NAMES = (
    # A. 邊類型分布 (12d)
    [f"edge_{et}" for et in EDGE_TYPES] + ["edge_other", "log_degree"]
    # B. 1-hop 鄰居統計 (10d)
    + ["nb_dr_mean", "nb_dr_max", "nb_dr_std",
       "nb_ratio_file", "nb_ratio_domain", "nb_ratio_ip", "nb_ratio_email",
       "nb_ip_country_entropy", "nb_ip_asn_entropy", "nb_domain_tld_entropy"]
    # C. 2-hop 統計 (5d)
    + ["hop2_log_count", "hop2_dr_mean",
       "hop2_ratio_file", "hop2_ratio_domain", "hop2_ratio_ip"]
    # D. 邊屬性統計 (8d)
    + ["ea_mal_mean", "ea_mal_max", "ea_undet_mean",
       "ea_resolution_count", "ea_dropped_type_distinct",
       "ea_ratio_depth0", "ea_ratio_depth1", "ea_log_source_reports"]
)
assert len(L2_NAMES) == 35, f"Expected 35, got {len(L2_NAMES)}"


def _entropy(counter):
    """Shannon entropy of a Counter."""
    total = sum(counter.values())
    if total == 0:
        return 0.0
    probs = np.array(list(counter.values()), dtype=np.float64) / total
    return float(-np.sum(probs * np.log2(probs + 1e-10)))


def extract_l2(nid, adj, edge_by_node, nodes):
    """回傳長度 35 的 list。"""
    neighbors = adj.get(nid, set())
    edges = edge_by_node.get(nid, [])
    f = [0.0] * 35

    # ── A. 邊類型分布 (12d) ──
    et_counter = Counter()
    for _, rel, _ in edges:
        et_counter[rel] += 1
    for i, et in enumerate(EDGE_TYPES):
        f[i] = math.log1p(et_counter.get(et, 0))
    f[10] = math.log1p(sum(c for r, c in et_counter.items() if r not in EDGE_TYPES))  # other
    f[11] = math.log1p(len(neighbors))  # log_degree

    if not neighbors:
        return f

    # ── B. 1-hop 鄰居統計 (10d) ──
    det_ratios = []
    type_counter = Counter()
    ip_countries = Counter()
    ip_asns = Counter()
    domain_tlds = Counter()

    for nb in neighbors:
        nd = nodes.get(nb)
        if not nd:
            continue
        ntype = nd["type"]
        type_counter[ntype] += 1
        attrs = nd["attributes"]
        dr = attrs.get("detection_ratio")
        if dr is not None:
            det_ratios.append(dr)

        if ntype == "ip":
            c = attrs.get("country")
            if c:
                ip_countries[c] += 1
            a = attrs.get("asn")
            if a:
                ip_asns[a] += 1
        elif ntype == "domain":
            t = attrs.get("tld")
            if t:
                domain_tlds[t] += 1

    n_nb = max(len(neighbors), 1)
    f[12] = float(np.mean(det_ratios)) if det_ratios else 0.0
    f[13] = float(np.max(det_ratios)) if det_ratios else 0.0
    f[14] = float(np.std(det_ratios)) if len(det_ratios) > 1 else 0.0
    f[15] = type_counter.get("file", 0) / n_nb
    f[16] = type_counter.get("domain", 0) / n_nb
    f[17] = type_counter.get("ip", 0) / n_nb
    f[18] = type_counter.get("email", 0) / n_nb
    f[19] = _entropy(ip_countries)
    f[20] = _entropy(ip_asns)
    f[21] = _entropy(domain_tlds)

    # ── C. 2-hop 統計 (5d) — 截斷 500 ──
    hop2 = set()
    for nb in neighbors:
        for nb2 in adj.get(nb, set()):
            if nb2 != nid and nb2 not in neighbors:
                hop2.add(nb2)
            if len(hop2) >= 500:
                break
        if len(hop2) >= 500:
            break

    f[22] = math.log1p(len(hop2))
    if hop2:
        h2_drs = []
        h2_types = Counter()
        for nb2 in hop2:
            nd2 = nodes.get(nb2)
            if not nd2:
                continue
            h2_types[nd2["type"]] += 1
            dr2 = nd2["attributes"].get("detection_ratio")
            if dr2 is not None:
                h2_drs.append(dr2)
        f[23] = float(np.mean(h2_drs)) if h2_drs else 0.0
        h2_total = max(sum(h2_types.values()), 1)
        f[24] = h2_types.get("file", 0) / h2_total
        f[25] = h2_types.get("domain", 0) / h2_total
        f[26] = h2_types.get("ip", 0) / h2_total

    # ── D. 邊屬性統計 (8d) ──
    edge_mals = []
    edge_undets = []
    resolution_count = 0
    dropped_types = set()
    depth0_count = 0
    depth1_count = 0
    source_report_count = 0

    for nb, rel, ea in edges:
        m = ea.get("malicious")
        if m is not None:
            edge_mals.append(m)
        u = ea.get("undetected")
        if u is not None:
            edge_undets.append(u)
        if ea.get("resolution_date"):
            resolution_count += 1
        if rel == "dropped_file" and ea.get("type_tag"):
            dropped_types.add(ea["type_tag"])

        nd_nb = nodes.get(nb)
        if nd_nb:
            d = nd_nb.get("depth")
            if d == 0:
                depth0_count += 1
            elif d == 1:
                depth1_count += 1

    f[27] = float(np.mean(edge_mals)) if edge_mals else 0.0
    f[28] = float(np.max(edge_mals)) if edge_mals else 0.0
    f[29] = float(np.mean(edge_undets)) if edge_undets else 0.0
    f[30] = float(resolution_count)
    f[31] = float(len(dropped_types))
    total_depth = max(depth0_count + depth1_count, 1)
    f[32] = depth0_count / total_depth
    f[33] = depth1_count / total_depth
    f[34] = math.log1p(source_report_count)

    return f


# ════════════════════════════════════════════════════════════
# Layer 3: Overlap Detection (7 + K dimensions)
# ════════════════════════════════════════════════════════════

def extract_l3(nid, adj, overlap_dict, org_list, exclude_org=None):
    """回傳長度 7+K 的 numpy array。"""
    neighbors = adj.get(nid, set())
    votes = Counter()
    overlap_count = 0

    for n in neighbors:
        if n not in overlap_dict:
            continue
        orgs = overlap_dict[n]
        if exclude_org:
            orgs = orgs - {exclude_org}
        if not orgs:
            continue

        overlap_count += 1

        # 加權投票：dr-based weight × IDF degree penalty
        nb_attrs = _node_attrs.get(n, {})
        dr = nb_attrs.get("detection_ratio", 0) or 0
        if dr < 0.1:
            w_dr = 0.1
        elif dr < 0.3:
            w_dr = 0.5
        else:
            w_dr = 1.0

        # IDF: 被越多 org 共用的節點，單次投票權重越低
        n_orgs = len(overlap_dict.get(n, set()))
        idf = 1.0 / math.log2(1 + n_orgs)  # 1 org → 1.0, 2 orgs → 0.63, 5 orgs → 0.39, 10 orgs → 0.29

        w = w_dr * idf

        for org in orgs:
            votes[org] += w

    # Part A: 直接 Overlap (3d)
    direct = overlap_dict.get(nid, set())
    if exclude_org:
        direct = direct - {exclude_org}
    f0 = float(len(direct))
    f1 = 1.0 if len(direct) == 1 else 0.0
    f2 = 1.0 if len(direct) > 1 else 0.0

    # Part B: 鄰居 Overlap 統計 (4d)
    total_n = max(len(neighbors), 1)
    total_v = max(sum(votes.values()), 1e-10)
    f3 = float(overlap_count) / total_n
    f4 = float(len(votes))
    f5 = float(max(votes.values())) / total_v if votes else 0.0
    if votes:
        probs = np.array(list(votes.values())) / sum(votes.values())
        f6 = float(-np.sum(probs * np.log2(probs + 1e-10)))
    else:
        f6 = 0.0

    # Part C: Per-org vote (K 維)
    per_org = np.zeros(len(org_list))
    for i, org in enumerate(org_list):
        per_org[i] = votes.get(org, 0) / total_v if votes else 0.0

    return np.concatenate([[f0, f1, f2, f3, f4, f5, f6], per_org])


# 全域引用，供 extract_l3 讀取 detection_ratio
_node_attrs = {}


def get_l3_names(org_list):
    return (["overlap_direct_count", "overlap_is_unique", "overlap_is_shared",
             "overlap_neighbor_ratio", "overlap_distinct_orgs", "overlap_dominant_ratio",
             "overlap_entropy"]
            + [f"overlap_vote_{org}" for org in org_list])


# ════════════════════════════════════════════════════════════
# Layer 4: Node2Vec (64d)
# ════════════════════════════════════════════════════════════

N2V_PATH = Path("scripts/features/node2vec_embeddings.npz")
N2V_DIM = 64
L4_NAMES = [f"n2v_{i}" for i in range(N2V_DIM)]


def load_node2vec():
    """載入 Node2Vec embeddings，回傳 {node_id: np.array(64,)}。"""
    if not N2V_PATH.exists():
        logger.warning(f"Node2Vec embeddings not found at {N2V_PATH}, L4 will be zeros")
        return {}
    data = np.load(N2V_PATH, allow_pickle=True)
    nids = data["node_ids"]
    embs = data["embeddings"]
    return {str(nid): emb for nid, emb in zip(nids, embs)}


def extract_l4(nid, adj, n2v_embeddings):
    """回傳長度 64 的 numpy array。
    如果節點本身有 embedding，直接用。
    否則取 detection_ratio 最高的鄰居的 embedding（避免跨社群平均的 mean fallacy）。
    """
    if nid in n2v_embeddings:
        return n2v_embeddings[nid]

    neighbors = adj.get(nid, set())
    overlap_nb = [n for n in neighbors if n in n2v_embeddings]
    if overlap_nb:
        # 取 detection_ratio 最高的鄰居（最可能是惡意基礎設施，嵌入最有代表性）
        best_n = max(overlap_nb,
                     key=lambda n: (_node_attrs.get(n, {}).get("detection_ratio", 0) or 0))
        return n2v_embeddings[best_n]

    return np.zeros(N2V_DIM, dtype=np.float32)


# ════════════════════════════════════════════════════════════
# Main
# ════════════════════════════════════════════════════════════

def main():
    global _node_attrs

    nodes, adj, edge_by_node, has_ioc_orgs = load_kg()
    _node_attrs = {nid: nd["attributes"] for nid, nd in nodes.items()}

    logger.info("Loading vocabularies...")
    with open(VOCAB_PATH) as f:
        vdata = json.load(f)
    vocabs = vdata["vocabs"]
    value_counts = vdata["value_counts"]
    freq_tables = vdata["freq"]

    overlap_dict = build_overlap_dict(has_ioc_orgs)
    logger.info(f"Overlap dict: {len(overlap_dict)} L0 IoCs (has_ioc targets only)")

    n2v_embeddings = load_node2vec()
    logger.info(f"Node2Vec embeddings: {len(n2v_embeddings)} nodes")

    # 只用 depth=0（L0 IoC）統計 org 的 IoC 數量
    org_counts = Counter()
    for nid, nd in nodes.items():
        if nd["type"] != "apt" and nd.get("depth") == 0 and nd["orgs"]:
            for org in nd["orgs"]:
                org_counts[org] += 1

    org_list = sorted([org for org, c in org_counts.items() if c >= MIN_IOCS])
    logger.info(f"Major orgs (>= {MIN_IOCS} IoCs): {len(org_list)}")
    for org in org_list:
        logger.info(f"  {org}: {org_counts[org]}")

    l3_names = get_l3_names(org_list)
    all_names = L1_NAMES + L2_NAMES + l3_names + L4_NAMES
    logger.info(f"Feature dimensions: L1={len(L1_NAMES)}, L2={len(L2_NAMES)}, L3={len(l3_names)}, L4={len(L4_NAMES)}, total={len(all_names)}")

    # 提取特徵
    X_rows = []
    y_labels = []
    node_ids = []

    for nid, nd in nodes.items():
        if nd["type"] == "apt":
            continue
        if nd.get("depth") != 0:
            continue  # 只用 L0 IoC 作為訓練樣本
        orgs = nd["orgs"]
        if len(orgs) != 1:
            continue  # 跳過多 org 共享的 IoC（label ambiguous）
        org = list(orgs)[0]
        if org not in org_list:
            continue

        l1 = extract_l1(nid, nd, vocabs, value_counts, freq_tables)
        l2 = extract_l2(nid, adj, edge_by_node, nodes)
        l3 = extract_l3(nid, adj, overlap_dict, org_list, exclude_org=org)
        l4 = extract_l4(nid, adj, n2v_embeddings)

        row = np.array(l1 + l2 + list(l3) + list(l4), dtype=np.float32)
        X_rows.append(row)
        y_labels.append(org)
        node_ids.append(nid)

    X = np.vstack(X_rows)
    y = np.array(y_labels)

    logger.info(f"Feature matrix: {X.shape}")
    logger.info("Label distribution:")
    for org in org_list:
        logger.info(f"  {org}: {np.sum(y == org)}")

    # NaN 統計
    nan_pct = np.isnan(X).mean(axis=0)
    high_nan = [(all_names[i], f"{nan_pct[i]:.1%}") for i in range(len(all_names)) if nan_pct[i] > 0.9]
    if high_nan:
        logger.info(f"High-NaN features (>90%): {high_nan[:10]}")

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(OUTPUT_DIR / "features_all.npz", X=X, y=y, node_ids=node_ids)
    with open(OUTPUT_DIR / "feature_names.json", "w") as f:
        json.dump({"l1": L1_NAMES, "l2": L2_NAMES, "l3": l3_names, "l4": L4_NAMES,
                    "all": all_names, "org_list": org_list}, f, indent=2)

    logger.info(f"Saved to {OUTPUT_DIR}/")


if __name__ == "__main__":
    main()
