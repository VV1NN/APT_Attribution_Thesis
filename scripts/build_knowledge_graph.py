#!/usr/bin/env python3
"""
build_knowledge_graph.py — 為每個 APT 組織建立 Knowledge Graph。

流程：
  1. 讀取 org_iocs_cleaned/{org}/iocs.json
  2. 對每個 IoC 呼叫 VT API，取得完整 Details metadata
  3. 建立圖結構 JSON → knowledge_graphs/{org}.json
  4. （可選）產出視覺化 PNG → knowledge_graphs/{org}_graph.png

節點類型：apt / file / domain / ip / email
邊類型：has_ioc

用法：
  uv run python scripts/build_knowledge_graph.py --org APT18
  uv run python scripts/build_knowledge_graph.py --org APT18 --skip-query
  uv run python scripts/build_knowledge_graph.py --org APT18 --visualize
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import requests
from dotenv import load_dotenv

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

VT_API_BASE = "https://www.virustotal.com/api/v3"
RATE_LIMIT_SEC = 0.1    # academic group: 20K req/min，保守設 600 req/min
MAX_RETRIES = 3          # 429 重試上限

BASE_DIR = Path(__file__).parent.parent  # /thesis/


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def setup_logging() -> logging.Logger:
    """初始化 logger，避免重複 handler。"""
    logger = logging.getLogger("kg_builder")
    if not logger.handlers:
        logger.setLevel(logging.DEBUG)
        fmt = "%(asctime)s [%(levelname)s] %(message)s"
        ch = logging.StreamHandler(sys.stdout)
        ch.setFormatter(logging.Formatter(fmt, "%H:%M:%S"))
        ch.setLevel(logging.INFO)
        logger.addHandler(ch)
    return logger


# ---------------------------------------------------------------------------
# VT API（Connection Pooling + Loop Retry）
# ---------------------------------------------------------------------------

def vt_get(
    endpoint: str,
    session: requests.Session,
    logger: logging.Logger,
    max_retries: int = MAX_RETRIES,
) -> dict | None:
    """
    呼叫 VT API，回傳 JSON dict 或 None。
    遇到 429 以迴圈重試（最多 max_retries 次），不使用遞迴。
    """
    url = f"{VT_API_BASE}/{endpoint}"

    for attempt in range(1, max_retries + 1):
        try:
            resp = session.get(url, timeout=30)

            if resp.status_code == 200:
                return resp.json()
            elif resp.status_code == 404:
                logger.info(f"    404 Not Found: {endpoint}")
                return None
            elif resp.status_code == 429:
                wait = RATE_LIMIT_SEC * attempt  # 遞增等待
                logger.warning(
                    f"    429 Rate limited (attempt {attempt}/{max_retries})，"
                    f"等待 {wait:.0f}s..."
                )
                time.sleep(wait)
                continue
            else:
                logger.warning(f"    HTTP {resp.status_code}: {endpoint}")
                return None

        except requests.exceptions.RequestException as e:
            logger.error(f"    請求失敗 (attempt {attempt}/{max_retries}): {e}")
            if attempt < max_retries:
                time.sleep(RATE_LIMIT_SEC)
                continue
            return None

    logger.error(f"    超過最大重試次數 ({max_retries})：{endpoint}")
    return None


# ---------------------------------------------------------------------------
# Timestamp 轉換
# ---------------------------------------------------------------------------

def _ts(unix: int | None) -> str | None:
    """Unix timestamp → ISO 8601 字串（UTC）。"""
    if unix is None:
        return None
    try:
        return datetime.fromtimestamp(unix, tz=timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
    except (OSError, ValueError, OverflowError):
        return None


# ---------------------------------------------------------------------------
# Metadata 提取器
# ---------------------------------------------------------------------------

def extract_file_metadata(resp: dict) -> dict:
    """從 VT /files/ 回應提取完整 File metadata，缺失欄位一律填 null / []。"""
    attrs = resp["data"]["attributes"]
    stats = attrs.get("last_analysis_stats") or {}
    pe = attrs.get("pe_info") or {}
    total = sum(stats.values()) if stats else 0

    # ── Signature / File Version Info ──
    sig = attrs.get("signature_info") or {}
    file_version_info: dict | None = None
    if isinstance(sig, dict) and sig:
        file_version_info = {
            "copyright":     sig.get("copyright"),
            "product":       sig.get("product"),
            "description":   sig.get("description"),
            "internal_name": sig.get("internal name"),
            "file_version":  sig.get("file version"),
            "verified":      sig.get("verified"),
        }

    # ── TrID ──
    trid = [
        {"file_type": t.get("file_type", ""), "probability": t.get("probability", 0)}
        for t in (attrs.get("trid") or [])
    ]

    # ── DetectItEasy ──
    die_raw = attrs.get("detectiteasy") or {}
    detectiteasy = [
        {
            "type":    e.get("type", ""),
            "name":    e.get("name", ""),
            "version": e.get("version", ""),
        }
        for e in (die_raw.get("values", []) if isinstance(die_raw, dict) else [])
    ]

    # ── Packers（所有引擎，不只 PEiD）──
    packers_raw = attrs.get("packers") or {}
    packers: dict = {}
    if isinstance(packers_raw, dict):
        packers = dict(packers_raw)

    # ── Bundle Info（ZIP / Office / Archive 內部結構）──
    bundle_raw = attrs.get("bundle_info") or {}
    bundle_info: dict | None = None
    if isinstance(bundle_raw, dict) and bundle_raw:
        bundle_info = {
            "num_children":     bundle_raw.get("num_children"),
            "uncompressed_size": bundle_raw.get("uncompressed_size"),
            "type":             bundle_raw.get("type"),
            "extensions":       bundle_raw.get("extensions") or {},
            "file_types":       bundle_raw.get("file_types") or {},
            "lowest_datetime":  bundle_raw.get("lowest_datetime"),
            "highest_datetime": bundle_raw.get("highest_datetime"),
        }

    # ── Popular Threat Classification（VT 威脅分類）──
    threat_raw = attrs.get("popular_threat_classification") or {}
    threat_classification: dict | None = None
    if isinstance(threat_raw, dict) and threat_raw:
        threat_classification = {
            "suggested_threat_label": threat_raw.get("suggested_threat_label"),
            "popular_threat_category": [
                {"value": c.get("value"), "count": c.get("count")}
                for c in (threat_raw.get("popular_threat_category") or [])
            ],
            "popular_threat_name": [
                {"value": n.get("value"), "count": n.get("count")}
                for n in (threat_raw.get("popular_threat_name") or [])
            ],
        }

    # ── PE sections ──
    sections = [
        {
            "name":            s.get("name", ""),
            "virtual_address": s.get("virtual_address"),
            "virtual_size":    s.get("virtual_size"),
            "raw_size":        s.get("raw_size"),
            "entropy":         s.get("entropy"),
            "md5":             s.get("md5", ""),
            "chi2":            s.get("chi2"),
            "flags":           s.get("flags", ""),
        }
        for s in (pe.get("sections") or [])
    ]

    # ── PE imports（只保留 library 名稱）──
    imports = [
        lib.get("library_name", "")
        for lib in (pe.get("import_list") or [])
    ]

    # ── PE resources ──
    resources = [
        {
            "type":     r.get("type", ""),
            "lang":     r.get("lang", ""),
            "filetype": r.get("filetype", ""),
            "entropy":  r.get("entropy"),
            "chi2":     r.get("chi2"),
            "sha256":   r.get("sha256", ""),
        }
        for r in (pe.get("resource_details") or [])
    ]

    return {
        # ── 雜湊家族 ──
        "md5":              attrs.get("md5"),
        "sha1":             attrs.get("sha1"),
        "sha256":           attrs.get("sha256"),
        "vhash":            attrs.get("vhash"),
        "ssdeep":           attrs.get("ssdeep"),
        "tlsh":             attrs.get("tlsh"),
        "authentihash":     attrs.get("authentihash"),
        # ── 偵測統計 ──
        "malicious":        stats.get("malicious", 0),
        "suspicious":       stats.get("suspicious", 0),
        "harmless":         stats.get("harmless", 0),
        "undetected":       stats.get("undetected", 0),
        "total_engines":    total,
        "detection_ratio":  round(stats.get("malicious", 0) / max(total, 1), 4),
        "reputation":       attrs.get("reputation"),
        # ── 檔案屬性 ──
        "size":             attrs.get("size"),
        "type_tag":         attrs.get("type_tag"),
        "type_description": attrs.get("type_description"),
        "magic":            attrs.get("magic"),
        "magika":           attrs.get("magika"),
        "packers":          packers if packers else None,
        "names":            attrs.get("names") or [],
        "meaningful_name":  attrs.get("meaningful_name"),
        "tags":             attrs.get("tags") or [],
        "type_extension":   attrs.get("type_extension"),
        "type_tags":        attrs.get("type_tags") or [],
        # ── 時間戳 ──
        "creation_time":    _ts(attrs.get("creation_date")),
        "first_seen_itw":   _ts(attrs.get("first_seen_itw_date")),
        "first_submission": _ts(attrs.get("first_submission_date")),
        "last_submission":  _ts(attrs.get("last_submission_date")),
        "last_analysis":    _ts(attrs.get("last_analysis_date")),
        # ── 提交統計 ──
        "times_submitted":  attrs.get("times_submitted"),
        "unique_sources":   attrs.get("unique_sources"),
        "total_votes":      attrs.get("total_votes") or {},
        # ── 識別工具 ──
        "trid":             trid,
        "detectiteasy":     detectiteasy,
        # ── 威脅分類 ──
        "popular_threat_classification": threat_classification,
        # ── Bundle Info（ZIP/Office 內部結構）──
        "bundle_info":      bundle_info,
        # ── 簽章 & File Version Info ──
        "signature_verified": (file_version_info or {}).get("verified"),
        "file_version_info":  file_version_info,
        # ── PE Info（非 PE 檔案則為 null）──
        "pe_info": {
            "imphash":                   pe.get("imphash"),
            "rich_pe_header_hash":       attrs.get("rich_pe_header_hash"),
            "compilation_timestamp":     _ts(pe.get("timestamp")),
            "entry_point":               pe.get("entry_point"),
            "machine_type":              pe.get("machine_type"),
            "compiler_product_versions": pe.get("compiler_product_versions") or [],
            "sections":                  sections,
            "imports":                   imports,
            "resources":                 resources,
            "resource_langs":            pe.get("resource_langs") or {},
            "resource_types":            pe.get("resource_types") or {},
        } if pe else None,
    }


def _extract_https_cert(cert_raw: dict | None) -> dict | None:
    """從 VT 的 last_https_certificate 提取精簡的憑證資訊。"""
    if not cert_raw or not isinstance(cert_raw, dict):
        return None
    validity = cert_raw.get("validity") or {}
    extensions = cert_raw.get("extensions") or {}
    return {
        "thumbprint":       cert_raw.get("thumbprint"),
        "thumbprint_sha256": cert_raw.get("thumbprint_sha256"),
        "serial_number":    cert_raw.get("serial_number"),
        "version":          cert_raw.get("version"),
        "issuer":           cert_raw.get("issuer"),
        "subject":          cert_raw.get("subject"),
        "validity": {
            "not_before":   validity.get("not_before"),
            "not_after":    validity.get("not_after"),
        },
        "subject_alternative_name": extensions.get("subject_alternative_name") or [],
    }


def extract_domain_metadata(resp: dict) -> dict:
    """從 VT /domains/ 回應提取完整 Domain metadata，缺失欄位一律填 null / []。"""
    attrs = resp["data"]["attributes"]
    stats = attrs.get("last_analysis_stats") or {}
    total = sum(stats.values()) if stats else 0
    whois_raw = attrs.get("whois") or ""

    # ── DNS records ──
    dns_records = [
        {
            "type":  r.get("type", ""),
            "value": r.get("value", ""),
            "ttl":   r.get("ttl"),
        }
        for r in (attrs.get("last_dns_records") or [])
    ]

    # ── Popularity ranks ──
    popularity_ranks: dict = {}
    for provider, info in (attrs.get("popularity_ranks") or {}).items():
        if isinstance(info, dict):
            popularity_ranks[provider] = {
                "rank":      info.get("rank"),
                "timestamp": _ts(info.get("timestamp")),
            }

    return {
        # ── 偵測統計 ──
        "malicious":        stats.get("malicious", 0),
        "suspicious":       stats.get("suspicious", 0),
        "harmless":         stats.get("harmless", 0),
        "undetected":       stats.get("undetected", 0),
        "total_engines":    total,
        "detection_ratio":  round(stats.get("malicious", 0) / max(total, 1), 4),
        "reputation":       attrs.get("reputation"),
        "total_votes":      attrs.get("total_votes") or {},
        # ── 網域屬性 ──
        "registrar":        attrs.get("registrar"),
        "tld":              attrs.get("tld"),
        "creation_date":    _ts(attrs.get("creation_date")),
        "last_update_date": _ts(attrs.get("last_update_date")),
        "last_analysis":    _ts(attrs.get("last_analysis_date")),
        "categories":       attrs.get("categories") or {},
        "tags":             attrs.get("tags") or [],
        "popularity_ranks": popularity_ranks,
        # ── WHOIS ──
        "has_whois":        bool(whois_raw),
        "whois":            whois_raw if whois_raw else None,
        # ── DNS ──
        "last_dns_records":      dns_records,
        "last_dns_records_date": _ts(attrs.get("last_dns_records_date")),
        # ── HTTPS 憑證 & JARM ──
        "jarm":                  attrs.get("jarm"),
        "last_https_certificate": _extract_https_cert(attrs.get("last_https_certificate")),
        # ── 社群情資 ──
        "crowdsourced_context":  attrs.get("crowdsourced_context") or [],
    }


def extract_ip_metadata(resp: dict) -> dict:
    """從 VT /ip_addresses/ 回應提取完整 IP metadata，缺失欄位一律填 null / []。"""
    attrs = resp["data"]["attributes"]
    stats = attrs.get("last_analysis_stats") or {}
    total = sum(stats.values()) if stats else 0

    return {
        # ── 偵測統計 ──
        "malicious":       stats.get("malicious", 0),
        "suspicious":      stats.get("suspicious", 0),
        "harmless":        stats.get("harmless", 0),
        "undetected":      stats.get("undetected", 0),
        "total_engines":   total,
        "detection_ratio": round(stats.get("malicious", 0) / max(total, 1), 4),
        "reputation":      attrs.get("reputation"),
        "total_votes":     attrs.get("total_votes") or {},
        # ── 網路屬性 ──
        "country":                    attrs.get("country"),
        "continent":                  attrs.get("continent"),
        "asn":                        attrs.get("asn"),
        "as_owner":                   attrs.get("as_owner"),
        "network":                    attrs.get("network"),
        "regional_internet_registry": attrs.get("regional_internet_registry"),
        "tags":                       attrs.get("tags") or [],
        # ── WHOIS ──
        "whois":           attrs.get("whois") or None,
        # ── HTTPS 憑證 & JARM ──
        "jarm":                      attrs.get("jarm"),
        "last_https_certificate":    _extract_https_cert(attrs.get("last_https_certificate")),
        # ── 社群情資 ──
        "crowdsourced_context":      attrs.get("crowdsourced_context") or [],
    }


# ---------------------------------------------------------------------------
# IoC 正規化 (Normalization)
# ---------------------------------------------------------------------------

def normalize_ioc(ioc: dict) -> tuple[str, str | None]:
    """
    回傳 (endpoint_type, query_value)。
    - file hash   → ("files", hash_value)
    - domain      → ("domains", domain)
    - ipv4/ipv6   → ("ip_addresses", ip)
    - url         → ("domains", extracted_domain)  ← 提取 domain 建節點
    - email       → ("email", address)             ← 不查 VT
    - 其他        → ("skip", None)
    """
    t = ioc.get("type", "").lower()
    v = ioc.get("value", "").strip()

    if not v:
        return ("skip", None)

    if t in ("md5", "sha1", "sha256"):
        return ("files", v.lower())

    if t in ("domain", "hostname"):
        return ("domains", v.lower().strip("."))

    if t in ("ipv4", "ipv6"):
        return ("ip_addresses", v)

    if t == "url":
        # 優先使用 iocs.json 中已提取的 domain 欄位
        domain = ioc.get("domain", "").strip()
        if not domain:
            try:
                parsed = urlparse(v if "://" in v else f"http://{v}")
                # parsed.hostname 自動去除 port
                domain = parsed.hostname or ""
            except Exception:
                return ("skip", None)
        domain = domain.lower().strip(".")
        return ("domains", domain) if domain else ("skip", None)

    if t == "email":
        return ("email", v.lower())

    return ("skip", None)


def make_node_id(endpoint_type: str, value: str) -> str:
    """根據 endpoint 類型產生節點 ID。"""
    prefix_map = {
        "files":        "file",
        "domains":      "domain",
        "ip_addresses": "ip",
        "email":        "email",
    }
    return f"{prefix_map.get(endpoint_type, 'unknown')}_{value}"


def get_node_type(endpoint_type: str) -> str:
    """endpoint 類型 → 節點類型字串。"""
    return {
        "files":        "file",
        "domains":      "domain",
        "ip_addresses": "ip",
        "email":        "email",
    }.get(endpoint_type, "unknown")


# ---------------------------------------------------------------------------
# Graph Builder
# ---------------------------------------------------------------------------

def _load_relationships(org: str) -> dict[str, dict]:
    """
    從 vt_relationships/{org}/ 載入所有 relationship 資料。
    回傳 dict: node_id → relationship data
    """
    rel_dir = BASE_DIR / "vt_relationships" / org
    result: dict[str, dict] = {}

    if not rel_dir.exists():
        return result

    # Files
    files_dir = rel_dir / "files"
    if files_dir.exists():
        for f in files_dir.glob("*.json"):
            sha256 = f.stem
            data = json.loads(f.read_text(encoding="utf-8"))
            result[f"file_{sha256}"] = data

    # Domains
    domains_dir = rel_dir / "domains"
    if domains_dir.exists():
        for f in domains_dir.glob("*.json"):
            domain = f.stem
            data = json.loads(f.read_text(encoding="utf-8"))
            result[f"domain_{domain}"] = data

    # IPs
    ips_dir = rel_dir / "ips"
    if ips_dir.exists():
        for f in ips_dir.glob("*.json"):
            ip = f.stem
            data = json.loads(f.read_text(encoding="utf-8"))
            result[f"ip_{ip}"] = data

    return result


def build_graph(org: str, iocs: list[dict], vt_cache: dict[str, dict],
                logger: logging.Logger | None = None) -> dict:
    """
    根據 IoC 清單和 VT cache，組建 Knowledge Graph。
    - 同一實體（md5/sha256 → 同一 file、多 URL → 同一 domain）合併為一個節點 + 一條邊
    - 邊的 ioc_original_types / ioc_original_values 為平行陣列，保留所有原始 IoC 記錄
    - source_reports 去重
    - 若有 vt_relationships 資料，加入 IoC 之間的橫向關聯邊
    """
    nodes: list[dict] = []
    edges_map: dict[tuple[str, str], dict] = {}  # (source, target) → edge
    seen_nodes: set[str] = set()

    # ── APT 根節點 ──
    apt_nid = f"apt_{org}"
    nodes.append({
        "id":         apt_nid,
        "type":       "apt",
        "attributes": {"name": org},
    })
    seen_nodes.add(apt_nid)

    # ── 遍歷每個 IoC ──
    for ioc in iocs:
        ep_type, query_val = normalize_ioc(ioc)
        if ep_type == "skip" or query_val is None:
            continue

        raw_nid = make_node_id(ep_type, query_val)
        ntype = get_node_type(ep_type)

        # ── 決定 canonical node ID ──
        canonical_nid = raw_nid
        vt_found = False
        attributes: dict = {}

        if ep_type == "email":
            # Email 不查 VT，metadata 只有 value
            attributes = {"value": query_val}
        else:
            # 嘗試從 cache 取得（先用 raw_nid，再試 canonical alias）
            cache_entry = vt_cache.get(raw_nid)

            if ep_type == "files":
                # File 正規化：解析 canonical sha256 ID
                if cache_entry:
                    vt_found = cache_entry.get("vt_found", False)
                    attributes = cache_entry.get("attributes") or {}
                    sha256 = attributes.get("sha256")
                    if sha256:
                        canonical_nid = f"file_{sha256}"
                else:
                    # raw_nid 不在 cache → 可能已透過其他 hash 查到，
                    # 但我們無法反查（除非 VT 已查過），保持 raw_nid
                    pass
            else:
                # Domain / IP：直接用 raw_nid
                if cache_entry:
                    vt_found = cache_entry.get("vt_found", False)
                    attributes = cache_entry.get("attributes") or {}

        # ── 建節點（去重）──
        if canonical_nid not in seen_nodes:
            nodes.append({
                "id":         canonical_nid,
                "type":       ntype,
                "vt_found":   vt_found,
                "attributes": attributes,
            })
            seen_nodes.add(canonical_nid)

        # ── 建邊 / 合併邊 ──
        edge_key = (apt_nid, canonical_nid)
        original_type = ioc.get("type", "")
        original_value = ioc.get("value", "")
        sources = list(ioc.get("sources") or [])

        if edge_key not in edges_map:
            edges_map[edge_key] = {
                "source":       apt_nid,
                "target":       canonical_nid,
                "relationship": "has_ioc",
                "attributes": {
                    "ioc_original_types":  [original_type],
                    "ioc_original_values": [original_value],
                    "source_reports":      list(sources),
                },
            }
        else:
            # 平行陣列追加：types[i] 對應 values[i]
            ea = edges_map[edge_key]["attributes"]
            ea["ioc_original_types"].append(original_type)
            ea["ioc_original_values"].append(original_value)
            for src in sources:
                if src not in ea["source_reports"]:
                    ea["source_reports"].append(src)

    # ── VT Relationships 橫向邊 + 第三層節點 ──
    relationships = _load_relationships(org)
    rel_edge_count = 0
    rel_node_count = 0

    def _ensure_node(target_nid: str, ntype: str) -> bool:
        """若第三層節點不在圖中且有 cache，加入圖譜。回傳是否在圖中。"""
        nonlocal rel_node_count
        if target_nid in seen_nodes:
            return True
        # 從 cache 取 metadata（Phase 2 查詢過的）
        cache_entry = vt_cache.get(target_nid)
        if cache_entry is None:
            return False
        nodes.append({
            "id":         target_nid,
            "type":       ntype,
            "vt_found":   cache_entry.get("vt_found", False),
            "attributes": cache_entry.get("attributes") or {},
            "depth":      1,  # 標記為第三層（relationship 發現）
        })
        seen_nodes.add(target_nid)
        rel_node_count += 1
        return True

    def _add_rel_edge(source: str, target: str, rel_type: str,
                      edge_attrs: dict | None = None) -> None:
        """加入 relationship 邊（去重），附帶邊屬性。"""
        nonlocal rel_edge_count
        edge_key = (source, target)
        if edge_key not in edges_map:
            edges_map[edge_key] = {
                "source": source, "target": target,
                "relationship": rel_type,
                "attributes": edge_attrs or {},
            }
            rel_edge_count += 1

    def _extract_edge_attrs(item: dict, rel_type: str) -> dict:
        """從 VT relationship item 提取邊屬性。"""
        attrs: dict = {}
        # resolution date（domain↔IP）
        if "date" in item:
            attrs["resolution_date"] = _ts(item["date"])
        # dropped file / contacted 的偵測統計摘要
        item_attrs = item.get("attributes") or {}
        if item_attrs.get("last_analysis_stats"):
            stats = item_attrs["last_analysis_stats"]
            attrs["malicious"] = stats.get("malicious", 0)
            attrs["undetected"] = stats.get("undetected", 0)
        if item_attrs.get("last_analysis_date"):
            attrs["last_analysis_date"] = _ts(item_attrs["last_analysis_date"])
        # type info for dropped files
        if rel_type == "dropped_file":
            for key in ("type_tag", "type_description", "meaningful_name"):
                if item_attrs.get(key):
                    attrs[key] = item_attrs[key]
        return attrs

    # ── Helper: 從 relationship items 提取目標並建邊 ──
    def _process_file_rel_items(nid: str, items: list, rel_type: str,
                                target_type: str, id_key: str = "id",
                                id_prefix: str = "", lowercase: bool = False,
                                skip_self: bool = False) -> None:
        """通用處理 file relationship items。"""
        for item in items:
            val = item.get(id_key, "") if isinstance(item, dict) else str(item)
            if lowercase:
                val = val.lower()
            if not val:
                continue
            target_nid = f"{id_prefix}{val}"
            if skip_self and target_nid == nid:
                continue
            if _ensure_node(target_nid, target_type):
                ea = _extract_edge_attrs(item, rel_type) if isinstance(item, dict) else {}
                _add_rel_edge(nid, target_nid, rel_type, ea)

    def _extract_url_domain(url_id: str) -> str:
        """從 URL id 提取 domain。"""
        try:
            parsed = urlparse(url_id if "://" in url_id else f"http://{url_id}")
            return (parsed.hostname or "").lower().strip(".")
        except Exception:
            return ""

    for nid, rel_data in relationships.items():
        if nid not in seen_nodes:
            continue

        if nid.startswith("file_"):
            # contacted_ips → IP nodes
            _process_file_rel_items(nid, rel_data.get("contacted_ips", []),
                                    "contacted_ip", "ip", id_prefix="ip_")
            # contacted_domains → Domain nodes
            _process_file_rel_items(nid, rel_data.get("contacted_domains", []),
                                    "contacted_domain", "domain", id_prefix="domain_")
            # contacted_urls → Domain nodes (extract domain from URL)
            for item in rel_data.get("contacted_urls", []):
                url_id = item.get("id", "") if isinstance(item, dict) else str(item)
                domain = _extract_url_domain(url_id)
                if domain:
                    target_nid = f"domain_{domain}"
                    if _ensure_node(target_nid, "domain"):
                        ea = _extract_edge_attrs(item, "contacted_url") if isinstance(item, dict) else {}
                        _add_rel_edge(nid, target_nid, "contacted_url", ea)
            # dropped_files → File nodes
            _process_file_rel_items(nid, rel_data.get("dropped_files", []),
                                    "dropped_file", "file", id_prefix="file_",
                                    lowercase=True, skip_self=True)
            # execution_parents → File nodes
            _process_file_rel_items(nid, rel_data.get("execution_parents", []),
                                    "execution_parent", "file", id_prefix="file_",
                                    lowercase=True, skip_self=True)
            # embedded_domains → Domain nodes
            _process_file_rel_items(nid, rel_data.get("embedded_domains", []),
                                    "embedded_domain", "domain", id_prefix="domain_")
            # embedded_ips → IP nodes
            _process_file_rel_items(nid, rel_data.get("embedded_ips", []),
                                    "embedded_ip", "ip", id_prefix="ip_")
            # embedded_urls → Domain nodes (extract domain)
            for item in rel_data.get("embedded_urls", []):
                url_id = item.get("id", "") if isinstance(item, dict) else str(item)
                domain = _extract_url_domain(url_id)
                if domain:
                    target_nid = f"domain_{domain}"
                    if _ensure_node(target_nid, "domain"):
                        ea = _extract_edge_attrs(item, "embedded_url") if isinstance(item, dict) else {}
                        _add_rel_edge(nid, target_nid, "embedded_url", ea)
            # itw_urls → Domain nodes (extract domain from distribution URL)
            for item in rel_data.get("itw_urls", []):
                url_id = item.get("id", "") if isinstance(item, dict) else str(item)
                domain = _extract_url_domain(url_id)
                if domain:
                    target_nid = f"domain_{domain}"
                    if _ensure_node(target_nid, "domain"):
                        ea = _extract_edge_attrs(item, "itw_url") if isinstance(item, dict) else {}
                        _add_rel_edge(nid, target_nid, "itw_url", ea)
            # itw_domains → Domain nodes
            _process_file_rel_items(nid, rel_data.get("itw_domains", []),
                                    "itw_domain", "domain", id_prefix="domain_")
            # itw_ips → IP nodes
            _process_file_rel_items(nid, rel_data.get("itw_ips", []),
                                    "itw_ip", "ip", id_prefix="ip_")
            # bundled_files → File nodes
            _process_file_rel_items(nid, rel_data.get("bundled_files", []),
                                    "bundled_file", "file", id_prefix="file_",
                                    lowercase=True, skip_self=True)
            # compressed_parents → File nodes
            _process_file_rel_items(nid, rel_data.get("compressed_parents", []),
                                    "compressed_parent", "file", id_prefix="file_",
                                    lowercase=True, skip_self=True)

        elif nid.startswith("domain_"):
            # resolutions → IP nodes
            for item in rel_data.get("resolutions", []):
                ip = item.get("ip_address", "") if isinstance(item, dict) else ""
                if not ip:
                    ip = (item.get("attributes", {}) or {}).get("ip_address", "")
                target_nid = f"ip_{ip}"
                if ip and _ensure_node(target_nid, "ip"):
                    ea = _extract_edge_attrs(item, "resolves_to") if isinstance(item, dict) else {}
                    _add_rel_edge(nid, target_nid, "resolves_to", ea)
            # communicating_files → File nodes
            _process_file_rel_items(nid, rel_data.get("communicating_files", []),
                                    "communicating_file", "file", id_prefix="file_",
                                    lowercase=True)
            # downloaded_files → File nodes
            _process_file_rel_items(nid, rel_data.get("downloaded_files", []),
                                    "downloaded_file", "file", id_prefix="file_",
                                    lowercase=True)
            # referrer_files → File nodes
            _process_file_rel_items(nid, rel_data.get("referrer_files", []),
                                    "referrer_file", "file", id_prefix="file_",
                                    lowercase=True)
            # subdomains → Domain nodes
            _process_file_rel_items(nid, rel_data.get("subdomains", []),
                                    "has_subdomain", "domain", id_prefix="domain_")

        elif nid.startswith("ip_"):
            # resolutions → Domain nodes
            for item in rel_data.get("resolutions", []):
                host = (item.get("host_name", "") if isinstance(item, dict) else "").lower()
                if not host:
                    host = ((item.get("attributes", {}) or {}).get("host_name", "")).lower()
                target_nid = f"domain_{host}"
                if host and _ensure_node(target_nid, "domain"):
                    ea = _extract_edge_attrs(item, "resolves_to") if isinstance(item, dict) else {}
                    _add_rel_edge(nid, target_nid, "resolves_to", ea)
            # communicating_files → File nodes
            _process_file_rel_items(nid, rel_data.get("communicating_files", []),
                                    "communicating_file", "file", id_prefix="file_",
                                    lowercase=True)
            # downloaded_files → File nodes
            _process_file_rel_items(nid, rel_data.get("downloaded_files", []),
                                    "downloaded_file", "file", id_prefix="file_",
                                    lowercase=True)
            # referrer_files → File nodes
            _process_file_rel_items(nid, rel_data.get("referrer_files", []),
                                    "referrer_file", "file", id_prefix="file_",
                                    lowercase=True)

    if logger:
        if rel_node_count > 0:
            logger.info(f"加入 {rel_node_count} 個第三層節點（relationship 發現）")
        if rel_edge_count > 0:
            logger.info(f"加入 {rel_edge_count} 條 VT relationship 橫向邊")

    return {
        "organization": org,
        "version":      "2.0",
        "created_at":   datetime.now(timezone.utc).isoformat(),
        "node_count":   len(nodes),
        "edge_count":   len(edges_map),
        "nodes":        nodes,
        "edges":        list(edges_map.values()),
    }


# ---------------------------------------------------------------------------
# Visualization（僅 --visualize 時執行）
# ---------------------------------------------------------------------------

def visualize(graph: dict, out_path: Path, logger: logging.Logger) -> None:
    """產出 Knowledge Graph 視覺化 PNG。"""
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

    # 邊標籤（relationship）
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
    logger.info(f"視覺化已儲存：{out_path}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def _query_vt_batch(
    to_query: dict[str, tuple[str, str]],
    vt_cache: dict[str, dict],
    session: "requests.Session",
    cache_file: Path,
    logger: logging.Logger,
    phase_label: str = "",
) -> int:
    """批次查詢 VT API，回傳實際查詢的數量。"""
    uncached = [nid for nid in to_query if nid not in vt_cache]
    logger.info(
        f"{phase_label}：共 {len(to_query)} 個待查，"
        f"其中 {len(uncached)} 個無 cache，"
        f"預計約 {len(uncached) * RATE_LIMIT_SEC / 60:.1f} 分鐘"
    )

    queried = 0
    for nid, (ep_type, value) in to_query.items():
        if nid in vt_cache:
            continue

        if queried > 0:
            time.sleep(RATE_LIMIT_SEC)

        logger.info(f"[{queried + 1}/{len(uncached)}] {ep_type}/{value}")
        resp = vt_get(f"{ep_type}/{value}", session, logger)
        queried += 1

        entry: dict = {
            "nid":         nid,
            "ep_type":     ep_type,
            "query_value": value,
            "query_time":  datetime.now(timezone.utc).isoformat(),
            "vt_found":    resp is not None,
            "attributes":  {},
        }

        if resp:
            try:
                if ep_type == "files":
                    entry["attributes"] = extract_file_metadata(resp)
                    sha256 = entry["attributes"].get("sha256")
                    if sha256:
                        canonical_nid = f"file_{sha256}"
                        entry["canonical_nid"] = canonical_nid
                        if canonical_nid != nid:
                            vt_cache[canonical_nid] = entry

                elif ep_type == "domains":
                    entry["attributes"] = extract_domain_metadata(resp)

                elif ep_type == "ip_addresses":
                    entry["attributes"] = extract_ip_metadata(resp)

                mal = entry["attributes"].get("malicious", "?")
                rep = entry["attributes"].get("reputation", "?")
                logger.info(f"  → Found  malicious={mal}  reputation={rep}")

            except Exception as e:
                logger.error(f"  → 解析失敗: {e}")
        else:
            logger.info("  → Not found in VT")

        vt_cache[nid] = entry

        cache_file.write_text(
            json.dumps(vt_cache, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    return queried


def _discover_relationship_nodes(org: str, graph: dict) -> dict[str, tuple[str, str]]:
    """
    從 vt_relationships 中找出圖譜外的第三層節點。
    回傳 dict: nid → (ep_type, query_value)
    """
    known_nodes = {n["id"] for n in graph["nodes"]}
    relationships = _load_relationships(org)
    new_nodes: dict[str, tuple[str, str]] = {}

    def _add_ip(ip: str) -> None:
        if ip:
            nid = f"ip_{ip}"
            if nid not in known_nodes:
                new_nodes[nid] = ("ip_addresses", ip)

    def _add_domain(d: str) -> None:
        if d:
            nid = f"domain_{d}"
            if nid not in known_nodes:
                new_nodes[nid] = ("domains", d)

    def _add_file(sha256: str) -> None:
        sha256 = sha256.lower()
        if sha256:
            nid = f"file_{sha256}"
            if nid not in known_nodes:
                new_nodes[nid] = ("files", sha256)

    def _get_id(item: dict | str) -> str:
        return item.get("id", "") if isinstance(item, dict) else str(item)

    def _extract_url_domain(url_id: str) -> str:
        try:
            parsed = urlparse(url_id if "://" in url_id else f"http://{url_id}")
            return (parsed.hostname or "").lower().strip(".")
        except Exception:
            return ""

    for nid, rel_data in relationships.items():
        if nid not in known_nodes:
            continue

        if nid.startswith("file_"):
            # IP-producing relationships
            for rel in ("contacted_ips", "embedded_ips", "itw_ips"):
                for item in rel_data.get(rel, []):
                    _add_ip(_get_id(item))
            # Domain-producing relationships
            for rel in ("contacted_domains", "embedded_domains", "itw_domains"):
                for item in rel_data.get(rel, []):
                    _add_domain(_get_id(item))
            # URL-producing relationships → extract domain
            for rel in ("contacted_urls", "embedded_urls", "itw_urls"):
                for item in rel_data.get(rel, []):
                    domain = _extract_url_domain(_get_id(item))
                    _add_domain(domain)
            # File-producing relationships
            for rel in ("dropped_files", "execution_parents", "bundled_files",
                        "compressed_parents"):
                for item in rel_data.get(rel, []):
                    _add_file(_get_id(item))

        elif nid.startswith("domain_"):
            # resolutions → IP
            for item in rel_data.get("resolutions", []):
                ip = item.get("ip_address", "") if isinstance(item, dict) else ""
                if not ip:
                    ip = (item.get("attributes", {}) or {}).get("ip_address", "")
                _add_ip(ip)
            # File-producing relationships
            for rel in ("communicating_files", "downloaded_files", "referrer_files"):
                for item in rel_data.get(rel, []):
                    _add_file(_get_id(item))
            # subdomains → Domain
            for item in rel_data.get("subdomains", []):
                _add_domain(_get_id(item))

        elif nid.startswith("ip_"):
            # resolutions → Domain
            for item in rel_data.get("resolutions", []):
                host = (item.get("host_name", "") if isinstance(item, dict) else "").lower()
                if not host:
                    host = ((item.get("attributes", {}) or {}).get("host_name", "")).lower()
                _add_domain(host)
            # File-producing relationships
            for rel in ("communicating_files", "downloaded_files", "referrer_files"):
                for item in rel_data.get(rel, []):
                    _add_file(_get_id(item))

    return new_nodes


def main() -> None:
    load_dotenv()

    parser = argparse.ArgumentParser(
        description="建立 APT Knowledge Graph（VT Details metadata 豐富化）"
    )
    parser.add_argument("--org", required=True, help="組織名稱，例如 APT18")
    parser.add_argument(
        "--skip-query", action="store_true",
        help="跳過 VT 查詢，直接從現有 cache 重建圖",
    )
    parser.add_argument(
        "--visualize", action="store_true",
        help="產出視覺化 PNG（預設不執行）",
    )
    args = parser.parse_args()

    logger = setup_logging()
    org = args.org

    # ── 路徑配置 ──
    ioc_file   = BASE_DIR / "org_iocs_cleaned" / org / "iocs.json"
    out_dir    = BASE_DIR / "knowledge_graphs" / org
    out_json   = out_dir / f"{org}.json"
    out_png    = out_dir / f"{org}_graph.png"
    cache_file = out_dir / f"{org}_vt_cache.json"

    out_dir.mkdir(parents=True, exist_ok=True)

    # 向下相容：若舊檔案在上層目錄，自動搬移至新資料夾
    old_dir = out_dir.parent
    for old_file, new_file in [
        (old_dir / f"{org}.json",          out_json),
        (old_dir / f"{org}_graph.png",     out_png),
        (old_dir / f"{org}_vt_cache.json", cache_file),
    ]:
        if old_file.exists() and not new_file.exists():
            old_file.rename(new_file)
            logger.info(f"搬移舊檔案：{old_file.name} → {out_dir.name}/")

    if not ioc_file.exists():
        logger.error(f"IoC 檔案不存在：{ioc_file}")
        sys.exit(1)

    iocs: list[dict] = json.loads(ioc_file.read_text(encoding="utf-8"))
    logger.info(f"讀取 {len(iocs)} 個 IoC from {ioc_file}")

    # ── 載入 VT cache（斷點續傳）──
    vt_cache: dict[str, dict] = {}
    if cache_file.exists():
        vt_cache = json.loads(cache_file.read_text(encoding="utf-8"))
        logger.info(f"Resume：已有 {len(vt_cache)} 個快取項目")

    # ── VT 查詢階段 ──
    if not args.skip_query:
        api_key = os.getenv("VT_API_KEY")
        if not api_key:
            logger.error("請在 .env 設定 VT_API_KEY")
            sys.exit(1)

        # Connection Pooling：整個查詢階段共用一個 Session
        session = requests.Session()
        session.headers.update({"x-apikey": api_key})

        # 收集待查詢（去重，email 不查 VT）
        to_query: dict[str, tuple[str, str]] = {}  # nid → (ep_type, value)
        for ioc in iocs:
            ep_type, query_val = normalize_ioc(ioc)
            if ep_type in ("skip", "email") or query_val is None:
                continue
            nid = make_node_id(ep_type, query_val)
            if nid not in to_query:
                to_query[nid] = (ep_type, query_val)

        queried = _query_vt_batch(
            to_query, vt_cache, session, cache_file, logger, "Phase 1（已知 IoC）"
        )
        logger.info(f"Phase 1 完成，共查 {queried} 個新 IoC")

    # ── 建圖階段（第一輪：已知 IoC）──
    logger.info("建立 Knowledge Graph...")
    graph = build_graph(org, iocs, vt_cache, logger)

    # ── Phase 2：Relationship 發現的第三層節點 ──
    if not args.skip_query:
        rel_nodes = _discover_relationship_nodes(org, graph)
        if rel_nodes:
            logger.info(f"Phase 2：發現 {len(rel_nodes)} 個第三層節點需查 VT")
            queried2 = _query_vt_batch(
                rel_nodes, vt_cache, session, cache_file, logger,
                "Phase 2（第三層）",
            )
            logger.info(f"Phase 2 完成，共查 {queried2} 個新節點")

            # 重建圖譜（含第三層節點 + 邊）
            logger.info("重建 Knowledge Graph（含第三層）...")
            graph = build_graph(org, iocs, vt_cache, logger)

    out_json.write_text(
        json.dumps(graph, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    logger.info(f"Knowledge Graph 已儲存：{out_json}")
    logger.info(f"  節點：{graph['node_count']}  邊：{graph['edge_count']}")

    # ── 視覺化（可選）──
    if args.visualize:
        logger.info("產出視覺化圖...")
        visualize(graph, out_png, logger)

    logger.info("完成！")


if __name__ == "__main__":
    main()
