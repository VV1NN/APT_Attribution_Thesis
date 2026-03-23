#!/usr/bin/env python3
"""
OTX (AlienVault Open Threat Exchange) 關聯資料抓取腳本

從 VT_results/ 讀取各 APT 的 IoC，透過 OTX API 查詢：
  - domain/hostname → passive_dns（domain→IP 邊）
  - domain/hostname → malware（domain→file 邊）
  - IPv4 → passive_dns（IP→domain 邊）
  - IPv4 → malware（IP→file 邊）
  - file (SHA256) → analysis（補充檔案屬性）
  - file (SHA256) → general（pulse 關聯 + adversary 標籤）

輸出格式與 vt_relationships/ 相容，存放在 otx_relationships/。
OTX API 沒有嚴格的每日請求限制，但仍加入 rate limiting 避免被擋。
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import shutil
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any

import requests
from dotenv import load_dotenv

# ── 路徑設定 ─────────────────────────────────────────────────────────────────
SCRIPT_DIR = Path(__file__).resolve().parent
BASE_DIR = SCRIPT_DIR.parent
VT_RESULTS_DIR = BASE_DIR / "VT_results"
OUTPUT_DIR = BASE_DIR / "otx_relationships"
GLOBAL_CACHE_DIR = OUTPUT_DIR / ".cache"

load_dotenv(BASE_DIR / ".env")
OTX_API_KEY = os.getenv("OTX_API_KEY", "")
OTX_BASE_URL = "https://otx.alienvault.com/api/v1"

# ── Logging（在 main() 裡完整初始化，這裡只建 logger）────────────────────────
logger = logging.getLogger(__name__)

# ── Rate limiting ────────────────────────────────────────────────────────────
REQUEST_INTERVAL = 0.2  # 5 req/sec (OTX 較寬鬆)
MAX_RETRIES = 3
RETRY_BACKOFF = 5  # 秒


# ── API 呼叫 ─────────────────────────────────────────────────────────────────
def otx_get(endpoint: str) -> dict | None:
    """呼叫 OTX API，回傳 JSON 或 None（失敗時）。"""
    url = f"{OTX_BASE_URL}/{endpoint}"
    headers = {"X-OTX-API-KEY": OTX_API_KEY}

    for attempt in range(MAX_RETRIES):
        try:
            resp = requests.get(url, headers=headers, timeout=30)
            if resp.status_code == 200:
                return resp.json()
            elif resp.status_code == 429:
                wait = RETRY_BACKOFF * (attempt + 1)
                logger.warning("429 Rate limited, waiting %ds...", wait)
                time.sleep(wait)
                continue
            elif resp.status_code == 404:
                return None
            else:
                logger.warning("HTTP %d for %s", resp.status_code, endpoint)
                return None
        except requests.RequestException as e:
            logger.warning("Request error (%d/%d): %s", attempt + 1, MAX_RETRIES, e)
            time.sleep(RETRY_BACKOFF)

    return None


# ── IoC 收集 ─────────────────────────────────────────────────────────────────
def collect_iocs_from_vt_results(org_name: str) -> dict[str, list[str]]:
    """從 VT_results/{org}_VT/vt_results.json 讀取 IoC，分類回傳。"""
    vt_dir = VT_RESULTS_DIR / f"{org_name}_VT"
    vt_file = vt_dir / "vt_results.json"
    if not vt_file.exists():
        logger.warning("找不到 %s", vt_file)
        return {"files": [], "ips": [], "domains": []}

    with open(vt_file, encoding="utf-8") as f:
        data = json.load(f)

    files: set[str] = set()
    ips: set[str] = set()
    domains: set[str] = set()

    for item in data.get("results", []):
        ioc = item.get("ioc", {})
        ioc_type = ioc.get("type", "")
        value = ioc.get("value", "")
        if not value:
            continue

        if ioc_type in ("sha256",):
            files.add(value)
        elif ioc_type in ("md5", "sha1"):
            files.add(value)  # OTX 接受 md5/sha1/sha256
        elif ioc_type in ("ipv4", "ipv6"):
            ips.add(value)
        elif ioc_type in ("domain", "hostname"):
            domains.add(value)

    return {
        "files": sorted(files),
        "ips": sorted(ips),
        "domains": sorted(domains),
    }


# ── 工具函式 ─────────────────────────────────────────────────────────────────
def _safe_extend_adversary(target: list, advs: Any) -> None:
    """安全地將 adversary 資料加入 list，處理 string/list/其他型別。"""
    if isinstance(advs, list):
        target.extend(a for a in advs if isinstance(a, str) and a.strip())
    elif isinstance(advs, str) and advs.strip():
        target.append(advs.strip())


def get_cached_or_fetch(ioc_type: str, value: str, query_func) -> tuple[dict, bool]:
    """
    全域 cache：跨組織去重。
    回傳 (data, is_cache_hit)。
    """
    safe_name = value.replace("/", "_").replace(":", "_").replace("*", "_")
    cache_path = GLOBAL_CACHE_DIR / ioc_type / f"{safe_name}.json"

    if cache_path.exists():
        with open(cache_path, encoding="utf-8") as f:
            return json.load(f), True

    # Cache miss → 打 API
    result = query_func(value)

    cache_path.parent.mkdir(parents=True, exist_ok=True)
    with open(cache_path, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    return result, False


# ── 查詢函式 ─────────────────────────────────────────────────────────────────
def query_domain(domain: str) -> dict[str, Any]:
    """查詢 domain 的 passive_dns + malware 關聯。"""
    result: dict[str, Any] = {
        "indicator": domain,
        "type": "domain",
        "passive_dns": [],
        "malware": [],
        "pulses": 0,
        "adversary": [],
    }

    # passive_dns: domain → IP
    data = otx_get(f"indicators/domain/{domain}/passive_dns")
    time.sleep(REQUEST_INTERVAL)
    if data and data.get("passive_dns"):
        result["passive_dns"] = [
            {
                "address": rec.get("address"),
                "first": rec.get("first"),
                "last": rec.get("last"),
                "record_type": rec.get("record_type"),
                "asn": rec.get("asn"),
                "flag_title": rec.get("flag_title"),
            }
            for rec in data["passive_dns"][:200]
            if rec.get("address") and rec["address"] != "NXDOMAIN"
        ]

    # malware: domain → 關聯惡意檔案
    data = otx_get(f"indicators/domain/{domain}/malware")
    time.sleep(REQUEST_INTERVAL)
    if data and data.get("data"):
        result["malware"] = [
            {
                "hash": rec.get("hash"),
                "detections": rec.get("detections"),
            }
            for rec in data["data"][:50]
        ]

    # general: pulse info
    data = otx_get(f"indicators/domain/{domain}/general")
    time.sleep(REQUEST_INTERVAL)
    if data and data.get("pulse_info"):
        result["pulses"] = data["pulse_info"].get("count", 0)
        related = data["pulse_info"].get("related", {})
        for source in ("alienvault", "other"):
            advs = related.get(source, {}).get("adversary", [])
            _safe_extend_adversary(result["adversary"], advs)

    return result


def query_ip(ip: str) -> dict[str, Any]:
    """查詢 IP 的 passive_dns + malware + general。"""
    result: dict[str, Any] = {
        "indicator": ip,
        "type": "ip",
        "passive_dns": [],
        "malware": [],
        "geo": {},
        "pulses": 0,
        "adversary": [],
    }

    # passive_dns: IP → domain
    data = otx_get(f"indicators/IPv4/{ip}/passive_dns")
    time.sleep(REQUEST_INTERVAL)
    if data and data.get("passive_dns"):
        result["passive_dns"] = [
            {
                "hostname": rec.get("hostname"),
                "first": rec.get("first"),
                "last": rec.get("last"),
                "record_type": rec.get("record_type"),
            }
            for rec in data["passive_dns"][:200]
            if rec.get("hostname")
        ]

    # malware
    data = otx_get(f"indicators/IPv4/{ip}/malware")
    time.sleep(REQUEST_INTERVAL)
    if data and data.get("data"):
        result["malware"] = [
            {"hash": rec.get("hash"), "detections": rec.get("detections")}
            for rec in data["data"][:50]
        ]

    # general: geo + pulse
    data = otx_get(f"indicators/IPv4/{ip}/general")
    time.sleep(REQUEST_INTERVAL)
    if data:
        result["geo"] = {
            "country_code": data.get("country_code"),
            "country_name": data.get("country_name"),
            "city": data.get("city"),
            "asn": data.get("asn"),
            "latitude": data.get("latitude"),
            "longitude": data.get("longitude"),
        }
        if data.get("pulse_info"):
            result["pulses"] = data["pulse_info"].get("count", 0)
            related = data["pulse_info"].get("related", {})
            for source in ("alienvault", "other"):
                advs = related.get(source, {}).get("adversary", [])
                _safe_extend_adversary(result["adversary"], advs)

    return result


def query_file(file_hash: str) -> dict[str, Any]:
    """查詢 file hash 的 general（pulse + adversary）+ analysis。"""
    result: dict[str, Any] = {
        "indicator": file_hash,
        "type": "file",
        "pulses": 0,
        "adversary": [],
        "malware_families": [],
        "tags": [],
        "analysis": {},
    }

    # general: pulse 關聯
    data = otx_get(f"indicators/file/{file_hash}/general")
    time.sleep(REQUEST_INTERVAL)
    if data:
        if data.get("pulse_info"):
            result["pulses"] = data["pulse_info"].get("count", 0)
            # 收集所有 pulse 的 adversary 和 tags
            for pulse in data["pulse_info"].get("pulses", [])[:20]:
                adv = pulse.get("adversary", "")
                if isinstance(adv, str) and adv.strip():
                    result["adversary"].append(adv.strip())
                elif isinstance(adv, list):
                    result["adversary"].extend(a for a in adv if isinstance(a, str) and a.strip())
                result["tags"].extend(pulse.get("tags", []))
            related = data["pulse_info"].get("related", {})
            for source in ("alienvault", "other"):
                advs = related.get(source, {}).get("adversary", [])
                _safe_extend_adversary(result["adversary"], advs)
                mf = related.get(source, {}).get("malware_families", [])
                if isinstance(mf, list):
                    result["malware_families"].extend(m for m in mf if isinstance(m, str))
                elif isinstance(mf, str) and mf.strip():
                    result["malware_families"].append(mf.strip())

        # base_indicator (可能含 sha256)
        base = data.get("base_indicator", {})
        if base.get("indicator"):
            result["sha256"] = base["indicator"]

    # analysis: 檔案屬性
    data = otx_get(f"indicators/file/{file_hash}/analysis")
    time.sleep(REQUEST_INTERVAL)
    if data and data.get("analysis"):
        info = data["analysis"].get("info", {}).get("results", {})
        result["analysis"] = {
            "file_type": info.get("file_type"),
            "file_class": info.get("file_class"),
            "filesize": info.get("filesize"),
            "md5": info.get("md5"),
            "sha256": info.get("sha256"),
            "ssdeep": info.get("ssdeep"),
        }

    # 去重
    result["adversary"] = sorted(set(result["adversary"]))
    result["tags"] = sorted(set(result["tags"]))
    result["malware_families"] = sorted(set(result["malware_families"]))

    return result


# ── 主流程 ───────────────────────────────────────────────────────────────────
def process_org(org_name: str, iocs: dict[str, list[str]], dry_run: bool = False) -> dict:
    """處理單一組織的所有 IoC。"""
    org_dir = OUTPUT_DIR / org_name
    stats = {"files": 0, "ips": 0, "domains": 0, "api_calls": 0, "with_data": 0}

    for ioc_type in ("files", "ips", "domains"):
        type_dir = org_dir / ioc_type
        items = iocs[ioc_type]
        if not items:
            continue

        if not dry_run:
            type_dir.mkdir(parents=True, exist_ok=True)

        for i, item in enumerate(items):
            # 檔名安全處理
            safe_name = item.replace("/", "_").replace(":", "_")
            out_file = type_dir / f"{safe_name}.json"

            # Skip if already fetched
            if out_file.exists():
                stats[ioc_type] += 1
                continue

            if dry_run:
                stats[ioc_type] += 1
                continue

            # 查詢（透過全域 cache 去重）
            if ioc_type == "domains":
                data, cached = get_cached_or_fetch(ioc_type, item, query_domain)
                if not cached:
                    stats["api_calls"] += 3
            elif ioc_type == "ips":
                data, cached = get_cached_or_fetch(ioc_type, item, query_ip)
                if not cached:
                    stats["api_calls"] += 3
            else:
                data, cached = get_cached_or_fetch(ioc_type, item, query_file)
                if not cached:
                    stats["api_calls"] += 2

            # 判斷是否有有用資料
            has_data = False
            if ioc_type == "domains":
                has_data = bool(data.get("passive_dns") or data.get("malware"))
            elif ioc_type == "ips":
                has_data = bool(data.get("passive_dns") or data.get("malware"))
            else:
                has_data = bool(data.get("pulses", 0) > 0 or data.get("analysis"))

            if has_data:
                stats["with_data"] += 1

            # 儲存
            with open(out_file, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            stats[ioc_type] += 1

            if (i + 1) % 50 == 0:
                logger.info(
                    "  [%s/%s] %d/%d done | api_calls: %d | with_data: %d",
                    ioc_type, org_name, i + 1, len(items),
                    stats["api_calls"], stats["with_data"],
                )

    return stats


def main():
    parser = argparse.ArgumentParser(description="OTX 關聯資料抓取")
    parser.add_argument("--orgs", type=str, help="指定組織（逗號分隔），預設處理所有有 VT 結果的組織")
    parser.add_argument("--dry-run", action="store_true", help="只估算不實際查詢")
    parser.add_argument("--max-orgs", type=int, default=0, help="最多處理幾個組織（0=全部）")
    args = parser.parse_args()

    if not OTX_API_KEY:
        logger.error("OTX_API_KEY 未設定，請在 .env 中加入")
        sys.exit(1)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    # 初始化 logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler(OUTPUT_DIR / "progress.log", mode="a", encoding="utf-8"),
        ],
    )

    # 決定要處理的組織
    if args.orgs:
        org_names = [o.strip() for o in args.orgs.split(",")]
    else:
        org_names = sorted([
            d.name.replace("_VT", "")
            for d in VT_RESULTS_DIR.iterdir()
            if d.is_dir() and d.name.endswith("_VT") and (d / "vt_results.json").exists()
        ])

    if args.max_orgs > 0:
        org_names = org_names[:args.max_orgs]

    logger.info("=" * 60)
    logger.info("OTX Relationship Fetcher")
    logger.info("orgs: %d | dry-run: %s", len(org_names), args.dry_run)
    logger.info("=" * 60)

    # 統計
    total_api = 0
    total_data = 0

    for org in org_names:
        iocs = collect_iocs_from_vt_results(org)
        n_files = len(iocs["files"])
        n_ips = len(iocs["ips"])
        n_domains = len(iocs["domains"])

        if n_files + n_ips + n_domains == 0:
            continue

        est_calls = n_files * 2 + n_ips * 3 + n_domains * 3
        logger.info(
            "─── %s ─── files: %d | ips: %d | domains: %d | est_calls: %d",
            org, n_files, n_ips, n_domains, est_calls,
        )

        if args.dry_run:
            total_api += est_calls
            continue

        stats = process_org(org, iocs, dry_run=False)
        total_api += stats["api_calls"]
        total_data += stats["with_data"]
        logger.info(
            "  ✓ %s done | api_calls: %d | with_data: %d",
            org, stats["api_calls"], stats["with_data"],
        )

    logger.info("=" * 60)
    if args.dry_run:
        est_time_min = total_api * REQUEST_INTERVAL / 60
        logger.info("Dry run 完成 | 預估 API calls: %d | 預估時間: %.1f 分鐘", total_api, est_time_min)
    else:
        logger.info("完成 | 總 API calls: %d | 有資料的 IoC: %d", total_api, total_data)
    logger.info("=" * 60)

    # 寫入統計 JSON
    stats_summary = {
        "fetch_time": datetime.now().isoformat(),
        "total_orgs_processed": len(org_names),
        "total_api_calls": total_api,
        "total_with_data": total_data,
        "dry_run": args.dry_run,
    }
    stats_path = OUTPUT_DIR / "fetch_stats.json"
    with open(stats_path, "w", encoding="utf-8") as f:
        json.dump(stats_summary, f, ensure_ascii=False, indent=2)
    logger.info("統計已寫入 %s", stats_path)

    if not args.dry_run:
        logger.info("")
        logger.info("下一步：重新轉換 prototype（融合 VT + OTX 邊資料）")
        logger.info("指令：uv run python scripts/convert_vt_to_prototype.py --relationships-only --otx-dir otx_relationships/")


if __name__ == "__main__":
    main()
