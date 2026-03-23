#!/usr/bin/env python3
"""
fetch_vt_metadata.py — 從 VT API 抓取每個 IoC 的完整 Details 屬性，建立 Knowledge Graph 節點 Metadata。

Input:  org_iocs_cleaned/{org}/iocs.json
Output: VT_results/{org}_VT/metadata.json

支援 IoC 類型：md5, sha1, sha256, domain, hostname, ipv4, ipv6, url（從 url 中提取 domain）
跳過：email, cve, url（直接略過，只處理 domain 欄位）

Rate limit: 4 req/min（每次請求間隔 15 秒）
Resume 支援：已查詢過的 IoC 自動跳過
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import requests
from dotenv import load_dotenv
import os

load_dotenv()

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VT_API_BASE = "https://www.virustotal.com/api/v3"
RATE_LIMIT_INTERVAL = 15.0  # seconds between requests (4 req/min)

SUPPORTED_TYPES = {"md5", "sha1", "sha256", "domain", "hostname", "ipv4", "ipv6", "url"}
SKIP_TYPES = {"email", "cve", "url"}  # url 只取 domain 欄位

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def setup_logging() -> logging.Logger:
    logger = logging.getLogger("vt_meta")
    logger.setLevel(logging.DEBUG)
    fmt = "%(asctime)s [%(levelname)s] %(message)s"
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(logging.Formatter(fmt, "%H:%M:%S"))
    ch.setLevel(logging.INFO)
    logger.addHandler(ch)
    return logger


# ---------------------------------------------------------------------------
# VT API helpers
# ---------------------------------------------------------------------------

def make_request(endpoint: str, api_key: str, logger: logging.Logger) -> dict | None:
    """發送 VT API GET 請求，回傳 JSON 或 None。"""
    url = f"{VT_API_BASE}/{endpoint}"
    headers = {"x-apikey": api_key}
    try:
        resp = requests.get(url, headers=headers, timeout=30)
        if resp.status_code == 200:
            return resp.json()
        elif resp.status_code == 404:
            logger.info(f"  → 404 Not Found: {endpoint}")
            return None
        elif resp.status_code == 429:
            logger.warning(f"  → 429 Rate Limited，等待 60 秒...")
            time.sleep(60)
            return make_request(endpoint, api_key, logger)
        else:
            logger.warning(f"  → HTTP {resp.status_code}: {resp.text[:200]}")
            return None
    except Exception as e:
        logger.error(f"  → 請求失敗: {e}")
        return None


def extract_file_metadata(data: dict) -> dict:
    """從 /files/{hash} 的回應提取節點 metadata。"""
    attrs = data["data"]["attributes"]
    stats = attrs.get("last_analysis_stats", {})
    pe = attrs.get("pe_info", {})

    return {
        "node_type": "file",
        # 雜湊值
        "md5": attrs.get("md5", ""),
        "sha1": attrs.get("sha1", ""),
        "sha256": attrs.get("sha256", ""),
        "vhash": attrs.get("vhash", ""),
        "ssdeep": attrs.get("ssdeep", ""),
        "tlsh": attrs.get("tlsh", ""),
        "authentihash": attrs.get("authentihash", ""),
        # 偵測統計
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "total_engines": sum(stats.values()) if stats else 0,
        "detection_ratio": round(
            stats.get("malicious", 0) / max(sum(stats.values()), 1), 4
        ),
        # 信譽
        "reputation": attrs.get("reputation", 0),
        # 檔案屬性
        "size": attrs.get("size", 0),
        "type_tag": attrs.get("type_tag", ""),
        "type_description": attrs.get("type_description", ""),
        "magic": attrs.get("magic", ""),
        "names": attrs.get("names", []),
        "tags": attrs.get("tags", []),
        # 時間戳
        "creation_time": attrs.get("creation_date", None),
        "first_seen_itw": attrs.get("first_seen_itw_date", None),
        "first_submission": attrs.get("first_submission_date", None),
        "last_submission": attrs.get("last_submission_date", None),
        "last_analysis": attrs.get("last_analysis_date", None),
        # PE 資訊
        "pe_info": {
            "imphash": pe.get("imphash", ""),
            "rich_pe_header_hash": attrs.get("rich_pe_header_hash", ""),
            "timestamp": pe.get("timestamp", None),
            "machine_type": pe.get("machine_type", None),
            "entry_point": pe.get("entry_point", None),
            "compiler_product_versions": pe.get("compiler_product_versions", []),
            "sections": [
                {
                    "name": s.get("name", ""),
                    "virtual_address": s.get("virtual_address", 0),
                    "virtual_size": s.get("virtual_size", 0),
                    "raw_size": s.get("raw_size", 0),
                    "entropy": s.get("entropy", 0),
                    "md5": s.get("md5", ""),
                    "chi2": s.get("chi2", 0),
                    "flags": s.get("flags", ""),
                }
                for s in pe.get("sections", [])
            ],
            "import_list": [
                {
                    "library_name": lib.get("library_name", ""),
                    "imported_functions": lib.get("imported_functions", []),
                }
                for lib in pe.get("import_list", [])
            ],
            "resource_details": pe.get("resource_details", []),
            "resource_langs": pe.get("resource_langs", {}),
            "resource_types": pe.get("resource_types", {}),
        },
        # 簽章
        "signature_info": attrs.get("signature_info", {}),
        # 識別工具
        "trid": attrs.get("trid", []),
        "detectiteasy": attrs.get("detectiteasy", {}),
    }


def extract_domain_metadata(data: dict) -> dict:
    """從 /domains/{domain} 的回應提取節點 metadata。"""
    attrs = data["data"]["attributes"]
    stats = attrs.get("last_analysis_stats", {})

    return {
        "node_type": "domain",
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "total_engines": sum(stats.values()) if stats else 0,
        "detection_ratio": round(
            stats.get("malicious", 0) / max(sum(stats.values()), 1), 4
        ),
        "reputation": attrs.get("reputation", 0),
        "registrar": attrs.get("registrar", ""),
        "creation_date": attrs.get("creation_date", None),
        "last_update_date": attrs.get("last_update_date", None),
        "last_analysis": attrs.get("last_analysis_date", None),
        "categories": attrs.get("categories", {}),
        "tags": attrs.get("tags", []),
        "whois": attrs.get("whois", "")[:500] if attrs.get("whois") else "",
        "has_whois": bool(attrs.get("whois")),
    }


def extract_ip_metadata(data: dict) -> dict:
    """從 /ip_addresses/{ip} 的回應提取節點 metadata。"""
    attrs = data["data"]["attributes"]
    stats = attrs.get("last_analysis_stats", {})

    return {
        "node_type": "ip",
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "total_engines": sum(stats.values()) if stats else 0,
        "detection_ratio": round(
            stats.get("malicious", 0) / max(sum(stats.values()), 1), 4
        ),
        "reputation": attrs.get("reputation", 0),
        "country": attrs.get("country", ""),
        "asn": attrs.get("asn", None),
        "as_owner": attrs.get("as_owner", ""),
        "network": attrs.get("network", ""),
        "tags": attrs.get("tags", []),
    }


# ---------------------------------------------------------------------------
# IoC normalization
# ---------------------------------------------------------------------------

def normalize_ioc(ioc: dict) -> tuple[str, str] | None:
    """
    將清洗後的 IoC 正規化為 (endpoint_type, query_value)。
    endpoint_type: "files" | "domains" | "ip_addresses"
    回傳 None 表示跳過此 IoC。
    """
    ioc_type = ioc.get("type", "").lower()
    value = ioc.get("value", "").strip()

    if ioc_type in ("md5", "sha1", "sha256"):
        return ("files", value)

    elif ioc_type in ("domain", "hostname"):
        # 清理可能的 www. 前綴（保留以便精確查詢）
        return ("domains", value)

    elif ioc_type in ("ipv4", "ipv6"):
        return ("ip_addresses", value)

    elif ioc_type == "url":
        # 從 url 欄位取 domain，或從 value 解析
        domain = ioc.get("domain", "")
        if not domain:
            try:
                parsed = urlparse(value)
                domain = parsed.netloc or parsed.path.split("/")[0]
            except Exception:
                return None
        domain = domain.strip().lstrip("www.")
        if domain:
            return ("domains", domain)
        return None

    # email, cve 等 → 跳過
    return None


def node_id_for(endpoint_type: str, value: str) -> str:
    """產生知識圖節點 ID。"""
    if endpoint_type == "files":
        return f"file_{value}"
    elif endpoint_type == "domains":
        return f"domain_{value}"
    elif endpoint_type == "ip_addresses":
        return f"ip_{value}"
    return f"unknown_{value}"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def run(org: str, base_dir: Path, api_key: str, logger: logging.Logger) -> None:
    ioc_file = base_dir / "org_iocs_cleaned" / org / "iocs.json"
    out_dir = base_dir / "VT_results" / f"{org}_VT"
    out_file = out_dir / "metadata.json"

    if not ioc_file.exists():
        logger.error(f"IoC 檔案不存在：{ioc_file}")
        sys.exit(1)

    out_dir.mkdir(parents=True, exist_ok=True)

    # 讀取清洗後的 IoC
    iocs: list[dict] = json.loads(ioc_file.read_text(encoding="utf-8"))
    logger.info(f"讀取 {len(iocs)} 個 IoC from {ioc_file}")

    # 載入已有的 metadata（resume 支援）
    existing: dict[str, dict] = {}
    if out_file.exists():
        data = json.loads(out_file.read_text(encoding="utf-8"))
        for node in data.get("nodes", []):
            existing[node["node_id"]] = node
        logger.info(f"Resume：已有 {len(existing)} 個節點，跳過重複查詢")

    # 整理待查詢清單（去重）
    to_query: dict[str, tuple[str, str, dict]] = {}  # node_id → (endpoint_type, value, orig_ioc)
    skipped = 0
    for ioc in iocs:
        normalized = normalize_ioc(ioc)
        if normalized is None:
            logger.info(f"跳過 IoC type={ioc.get('type')} value={ioc.get('value','')[:40]}")
            skipped += 1
            continue
        endpoint_type, value = normalized
        nid = node_id_for(endpoint_type, value)
        if nid not in to_query:
            to_query[nid] = (endpoint_type, value, ioc)

    logger.info(f"去重後待查詢：{len(to_query)} 個（跳過 {skipped} 個）")

    # 查詢 VT
    nodes: dict[str, dict] = dict(existing)
    queried = 0
    failed = 0

    for nid, (endpoint_type, value, orig_ioc) in to_query.items():
        if nid in existing:
            logger.info(f"[SKIP] {nid}")
            continue

        logger.info(f"[QUERY] {endpoint_type}/{value}")
        endpoint = f"{endpoint_type}/{value}"
        resp = make_request(endpoint, api_key, logger)

        # Rate limit
        if queried > 0:
            logger.debug(f"  等待 {RATE_LIMIT_INTERVAL}s...")
            time.sleep(RATE_LIMIT_INTERVAL)

        queried += 1

        node: dict = {
            "node_id": nid,
            "ioc_type": orig_ioc.get("type", ""),
            "ioc_value": orig_ioc.get("value", ""),
            "query_value": value,
            "query_time": datetime.now(timezone.utc).isoformat(),
            "vt_found": resp is not None,
            "sources": orig_ioc.get("sources", []),
            "attributes": {},
        }

        if resp:
            try:
                if endpoint_type == "files":
                    node["attributes"] = extract_file_metadata(resp)
                elif endpoint_type == "domains":
                    node["attributes"] = extract_domain_metadata(resp)
                elif endpoint_type == "ip_addresses":
                    node["attributes"] = extract_ip_metadata(resp)
                logger.info(f"  → Found: malicious={node['attributes'].get('malicious', '?')}, "
                            f"reputation={node['attributes'].get('reputation', '?')}")
            except Exception as e:
                logger.error(f"  → 解析回應失敗: {e}")
                node["attributes"] = {"parse_error": str(e)}
                failed += 1
        else:
            failed += 1

        nodes[nid] = node

        # 每查一個就存檔（避免中斷丟失）
        _save(out_file, org, nodes)

    logger.info(f"\n完成！查詢 {queried} 個，失敗 {failed} 個，共 {len(nodes)} 個節點")
    logger.info(f"Metadata 已儲存至：{out_file}")


def _save(out_file: Path, org: str, nodes: dict[str, dict]) -> None:
    found = sum(1 for n in nodes.values() if n.get("vt_found"))
    output = {
        "organization": org,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_nodes": len(nodes),
        "found_in_vt": found,
        "nodes": list(nodes.values()),
    }
    out_file.write_text(json.dumps(output, ensure_ascii=False, indent=2), encoding="utf-8")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="從 VT API 抓取 IoC Details，建立 Knowledge Graph Metadata")
    parser.add_argument("--org", required=True, help="組織名稱，例如 APT18")
    parser.add_argument("--base-dir", default="/Users/vv1n/Documents/thesis",
                        help="專案根目錄（預設：/Users/vv1n/Documents/thesis）")
    args = parser.parse_args()

    api_key = os.getenv("VT_API_KEY")
    if not api_key:
        print("錯誤：請在 .env 中設定 VT_API_KEY")
        sys.exit(1)

    logger = setup_logging()
    base_dir = Path(args.base_dir)

    logger.info(f"=== fetch_vt_metadata.py — 組織：{args.org} ===")
    run(args.org, base_dir, api_key, logger)


if __name__ == "__main__":
    main()
