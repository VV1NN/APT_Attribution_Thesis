#!/usr/bin/env python3
"""
fetch_vt_relationships.py — Batch-fetch VirusTotal Relationship data for APT IoCs.

Input:  VT_results/{org}_VT/vt_results.json  (basic VT scan results)
Output: vt_relationships/{org}/files/{sha256}.json
        vt_relationships/{org}/ips/{ip}.json
        vt_relationships/{org}/domains/{domain}.json
        vt_relationships/.cache/              ← global dedup cache (avoids re-fetching across orgs)
        vt_relationships/fetch_stats.json
        vt_relationships/progress.log

Rate limit: 4 req/min, ~500 lookups/day (academic shared group quota).
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import sys
import time
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

import requests

# ---------------------------------------------------------------------------
# Logging — console + file
# ---------------------------------------------------------------------------

def setup_logging(log_path: Path) -> logging.Logger:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    fmt = "%(asctime)s [%(levelname)s] %(message)s"
    datefmt = "%Y-%m-%dT%H:%M:%S"

    logger = logging.getLogger("vt_rel")
    logger.setLevel(logging.DEBUG)

    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(logging.Formatter(fmt, datefmt))
    ch.setLevel(logging.INFO)

    fh = logging.FileHandler(log_path, encoding="utf-8")
    fh.setFormatter(logging.Formatter(fmt, datefmt))
    fh.setLevel(logging.DEBUG)

    logger.addHandler(ch)
    logger.addHandler(fh)
    return logger


# ---------------------------------------------------------------------------
# Rate Limiter
# ---------------------------------------------------------------------------

class QuotaExhausted(Exception):
    """到達每日限額時拋出，用於 --stop-on-quota 模式。"""
    pass


class RateLimiter:
    def __init__(self, requests_per_min: float = 600, daily_limit: int = 18000,
                 stop_on_quota: bool = False):
        self.min_interval = 60.0 / requests_per_min   # 15 s at default 4 req/min
        self.daily_limit = daily_limit
        self.stop_on_quota = stop_on_quota
        self.daily_count = 0
        self.last_request_time = 0.0
        self.day_start = datetime.now(timezone.utc).date()

    def wait(self, logger: logging.Logger) -> None:
        # --- Daily quota check ---
        today = datetime.now(timezone.utc).date()
        if today != self.day_start:
            self.daily_count = 0
            self.day_start = today

        if self.daily_count >= self.daily_limit:
            if self.stop_on_quota:
                raise QuotaExhausted(
                    f"已達每日限額 {self.daily_limit} 次，進度已儲存。"
                    f"下次執行時會自動從斷點續傳。"
                )
            tomorrow = datetime.combine(
                today + timedelta(days=1), datetime.min.time()
            ).replace(tzinfo=timezone.utc)
            wait_sec = (tomorrow - datetime.now(timezone.utc)).total_seconds() + 60
            logger.info(
                f"Daily quota reached ({self.daily_count}). "
                f"Sleeping {wait_sec / 3600:.1f} h until quota resets..."
            )
            time.sleep(wait_sec)
            self.daily_count = 0
            self.day_start = datetime.now(timezone.utc).date()

        # --- Per-minute rate limit ---
        elapsed = time.monotonic() - self.last_request_time
        if elapsed < self.min_interval:
            time.sleep(self.min_interval - elapsed)

        self.last_request_time = time.monotonic()
        self.daily_count += 1


# ---------------------------------------------------------------------------
# IoC collection
# ---------------------------------------------------------------------------

_IP_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def collect_iocs(
    vt_results_dir: Path,
    org_filter: set[str] | None,
    logger: logging.Logger,
) -> dict[str, tuple[set[str], set[str], set[str]]]:
    """
    Returns {org_name: (sha256_set, ip_set, domain_set)}.

    Hash normalization: md5/sha1/sha256 all mapped to sha256 via file_info.sha256.
    Only vt_found=True records are included.
    URL IoCs: hostname extracted → IP set or domain set.
    Domain IoCs: added to domain set directly.
    """
    org_iocs: dict[str, tuple[set[str], set[str], set[str]]] = {}

    for org_dir in sorted(vt_results_dir.iterdir()):
        if not org_dir.is_dir():
            continue

        # org dir name format: {org_name}_VT
        org_name = org_dir.name
        if org_name.endswith("_VT"):
            org_name = org_name[:-3]

        if org_filter and org_name not in org_filter:
            continue

        results_file = org_dir / "vt_results.json"
        if not results_file.exists():
            logger.warning(f"Missing: {results_file}")
            continue

        try:
            with open(results_file, encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            logger.warning(f"Failed to read {results_file}: {e}")
            continue

        sha256_set: set[str] = set()
        ip_set: set[str] = set()
        domain_set: set[str] = set()

        for record in data.get("results", []):
            if not record.get("vt_found"):
                continue

            ioc = record.get("ioc", {})
            ioc_type = ioc.get("type", "")
            ioc_value = ioc.get("value", "")

            if ioc_type in ("md5", "sha1", "sha256"):
                file_info = record.get("file_info") or {}
                sha256 = file_info.get("sha256")
                if sha256:
                    sha256_set.add(sha256.lower())
                elif ioc_type == "sha256":
                    sha256_set.add(ioc_value.lower())
                # md5/sha1 without sha256 mapping → skip

            elif ioc_type == "ipv4":
                ip_set.add(ioc_value)

            elif ioc_type == "domain":
                domain_set.add(ioc_value.lower())

            elif ioc_type == "url":
                try:
                    hostname = urlparse(ioc_value).hostname or ""
                except Exception:
                    hostname = ""
                if hostname:
                    if _IP_RE.match(hostname):
                        ip_set.add(hostname)
                    else:
                        domain_set.add(hostname.lower())

            # email → skip

        org_iocs[org_name] = (sha256_set, ip_set, domain_set)

    # Summary totals (unique across orgs)
    all_sha256 = {s for sha, _, _ in org_iocs.values() for s in sha}
    all_ips    = {ip for _, ips, _ in org_iocs.values() for ip in ips}
    all_domains = {d for _, _, doms in org_iocs.values() for d in doms}
    logger.info(
        f"Scanned {len(org_iocs)} orgs | "
        f"Unique SHA256: {len(all_sha256):,} | "
        f"IPs: {len(all_ips):,} | "
        f"Domains: {len(all_domains):,}"
    )
    return org_iocs


# ---------------------------------------------------------------------------
# Cache / result path helpers
# ---------------------------------------------------------------------------

def global_cache_path(output_dir: Path, kind: str, value: str) -> Path:
    """Global dedup cache — avoids re-fetching the same IoC across orgs."""
    return output_dir / ".cache" / kind / f"{value}.json"

def org_result_path(output_dir: Path, org: str, kind: str, value: str) -> Path:
    """Per-org result path: {org}/{files|ips|domains}/{value}.json"""
    return output_dir / org / kind / f"{value}.json"


# ---------------------------------------------------------------------------
# VT API
# ---------------------------------------------------------------------------

VT_BASE = "https://www.virustotal.com/api/v3"

FILE_RELATIONSHIPS = [
    "contacted_ips",
    "contacted_domains",
    "contacted_urls",
    "dropped_files",
    "execution_parents",
    "bundled_files",
    # Enterprise-only (403 on academic plan):
    # "embedded_domains", "embedded_ips", "embedded_urls",
    # "itw_urls", "itw_domains", "itw_ips", "compressed_parents",
]

DOMAIN_RELATIONSHIPS = [
    "resolutions",
    "communicating_files",
    "referrer_files",
    "subdomains",
    "historical_ssl_certificates",
    "historical_whois",
    # Enterprise-only: "downloaded_files",
]

IP_RELATIONSHIPS = [
    "resolutions",
    "communicating_files",
    "referrer_files",
    "historical_ssl_certificates",
    "historical_whois",
    # Enterprise-only: "downloaded_files",
]


def api_call(
    session: requests.Session,
    url: str,
    rate_limiter: RateLimiter,
    logger: logging.Logger,
    max_retries: int = 3,
) -> dict | None:
    """Single GET with retry. Returns parsed JSON or None on permanent failure.

    429 handling: unlimited retries with exponential backoff (60, 120, 300, 600 s).
    429s do NOT count against max_retries — they are transient quota events.
    max_retries only counts network errors and 5xx responses.
    """
    error_attempts = 0
    rate_429_count = 0
    _429_waits = [60, 120, 300, 600]

    while error_attempts < max_retries:
        rate_limiter.wait(logger)
        try:
            resp = session.get(url, timeout=30)
        except requests.exceptions.RequestException as e:
            error_attempts += 1
            logger.warning(f"Network error (attempt {error_attempts}/{max_retries}): {e}")
            time.sleep(30)
            continue

        if resp.status_code == 200:
            return resp.json()
        elif resp.status_code == 404:
            return {"data": []}
        elif resp.status_code == 429:
            rate_429_count += 1
            wait = _429_waits[min(rate_429_count - 1, len(_429_waits) - 1)]
            logger.warning(f"429 Rate limited (#{rate_429_count}). Waiting {wait}s...")
            time.sleep(wait)
            # Do NOT increment error_attempts — just retry
        elif resp.status_code in (400, 403):
            logger.error(f"HTTP {resp.status_code} (permanent): {url}")
            return None
        else:
            error_attempts += 1
            logger.warning(f"HTTP {resp.status_code} (attempt {error_attempts}/{max_retries}): {url}")
            time.sleep(30)

    logger.error(f"All {max_retries} error retries exhausted: {url}")
    return None


def extract_items(response: dict | None, key: str = "data") -> list:
    if not response:
        return []
    val = response.get(key, [])
    return val if isinstance(val, list) else []


def fetch_file_relationships(
    sha256: str,
    session: requests.Session,
    rate_limiter: RateLimiter,
    logger: logging.Logger,
) -> dict:
    """Call 4 endpoints for a file hash. Returns combined result dict."""
    result: dict = {
        "sha256": sha256,
        "query_time": datetime.now(timezone.utc).isoformat(),
        "contacted_ips": [],
        "contacted_domains": [],
        "dropped_files": [],
        "execution_parents": [],
        "errors": [],
    }

    for rel in FILE_RELATIONSHIPS:
        url = f"{VT_BASE}/files/{sha256}/{rel}?limit=40"
        resp = api_call(session, url, rate_limiter, logger)
        if resp is None:
            result["errors"].append(rel)
        else:
            items = extract_items(resp)
            result[rel] = [
                {"id": item.get("id"), "attributes": item.get("attributes", {})}
                for item in items
            ]

    return result


def fetch_ip_relationships(
    ip: str,
    session: requests.Session,
    rate_limiter: RateLimiter,
    logger: logging.Logger,
) -> dict:
    """Call all IP relationship endpoints. Returns combined result dict."""
    result: dict = {
        "ip": ip,
        "query_time": datetime.now(timezone.utc).isoformat(),
        "errors": [],
    }
    for rel in IP_RELATIONSHIPS:
        result[rel] = []

    for rel in IP_RELATIONSHIPS:
        url = f"{VT_BASE}/ip_addresses/{ip}/{rel}?limit=40"
        resp = api_call(session, url, rate_limiter, logger)
        if resp is None:
            result["errors"].append(rel)
        else:
            items = extract_items(resp)
            if rel == "resolutions":
                result[rel] = [
                    {
                        "host_name": item.get("attributes", {}).get("host_name", ""),
                        "date": item.get("attributes", {}).get("date", 0),
                    }
                    for item in items
                ]
            else:
                result[rel] = [
                    {"id": item.get("id"), "type": item.get("type", ""),
                     "attributes": item.get("attributes", {})}
                    for item in items
                ]
    return result


def fetch_domain_relationships(
    domain: str,
    session: requests.Session,
    rate_limiter: RateLimiter,
    logger: logging.Logger,
) -> dict:
    """Call all domain relationship endpoints. Returns combined result dict."""
    result: dict = {
        "domain": domain,
        "query_time": datetime.now(timezone.utc).isoformat(),
        "errors": [],
    }
    for rel in DOMAIN_RELATIONSHIPS:
        result[rel] = []

    for rel in DOMAIN_RELATIONSHIPS:
        url = f"{VT_BASE}/domains/{domain}/{rel}?limit=40"
        resp = api_call(session, url, rate_limiter, logger)
        if resp is None:
            result["errors"].append(rel)
        else:
            items = extract_items(resp)
            if rel == "resolutions":
                result[rel] = [
                    {
                        "ip_address": item.get("attributes", {}).get("ip_address", ""),
                        "date": item.get("attributes", {}).get("date", 0),
                    }
                    for item in items
                ]
            elif rel == "subdomains":
                result[rel] = [
                    {"id": item.get("id", ""), "attributes": item.get("attributes", {})}
                    for item in items
                ]
            else:
                result[rel] = [
                    {"id": item.get("id"), "type": item.get("type", ""),
                     "attributes": item.get("attributes", {})}
                    for item in items
                ]
    return result


# ---------------------------------------------------------------------------
# Stats helpers
# ---------------------------------------------------------------------------

def make_stats(
    org_iocs: dict[str, tuple[set[str], set[str], set[str]]],
    ioc_types: set[str],
) -> dict:
    all_sha256 = {s for sha, _, _ in org_iocs.values() for s in sha}
    all_ips    = {ip for _, ips, _ in org_iocs.values() for ip in ips}
    all_domains = {d for _, _, doms in org_iocs.values() for d in doms}

    n_file = len(all_sha256) if "file" in ioc_types else 0
    n_ip   = len(all_ips)    if "ip"   in ioc_types else 0
    n_dom  = len(all_domains) if "domain" in ioc_types else 0
    total_calls = (n_file * len(FILE_RELATIONSHIPS)
                   + n_ip * len(IP_RELATIONSHIPS)
                   + n_dom * len(DOMAIN_RELATIONSHIPS))

    stats: dict = {
        "start_time": datetime.now(timezone.utc).isoformat(),
        "last_update": datetime.now(timezone.utc).isoformat(),
        "total_unique_files": n_file,
        "total_unique_ips": n_ip,
        "total_unique_domains": n_dom,
        "file_endpoints": len(FILE_RELATIONSHIPS),
        "ip_endpoints": len(IP_RELATIONSHIPS),
        "domain_endpoints": len(DOMAIN_RELATIONSHIPS),
        "total_api_calls_needed": total_calls,
        "total_api_calls_made": 0,
        "files_queried": 0,
        "files_all_empty": 0,
        "ips_queried": 0,
        "ips_with_resolutions": 0,
        "domains_queried": 0,
        "domains_with_resolutions": 0,
        "errors": 0,
        "cache_hits": 0,
        "coverage_rates": {},
    }
    # Per-relationship counters for files
    for rel in FILE_RELATIONSHIPS:
        stats[f"files_with_{rel}"] = 0
    return stats


def update_coverage(stats: dict) -> None:
    fq = stats["files_queried"]
    iq = stats["ips_queried"]
    dq = stats["domains_queried"]
    rates: dict[str, str] = {}

    if fq:
        for rel in FILE_RELATIONSHIPS:
            key = f"files_with_{rel}"
            rates[f"file_{rel}"] = f"{stats.get(key, 0)/fq*100:.1f}%"
        any_rel = fq - stats["files_all_empty"]
        rates["file_any_relationship"] = f"{any_rel/fq*100:.1f}%"
    else:
        for rel in FILE_RELATIONSHIPS:
            rates[f"file_{rel}"] = "N/A"
        rates["file_any_relationship"] = "N/A"

    rates["ip_resolutions"] = (
        f"{stats['ips_with_resolutions']/iq*100:.1f}%" if iq else "N/A"
    )
    rates["domain_resolutions"] = (
        f"{stats['domains_with_resolutions']/dq*100:.1f}%" if dq else "N/A"
    )
    stats["coverage_rates"] = rates


def save_stats(stats: dict, output_dir: Path) -> None:
    stats["last_update"] = datetime.now(timezone.utc).isoformat()
    update_coverage(stats)
    tmp = output_dir / "fetch_stats.json.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(stats, f, indent=2)
    tmp.replace(output_dir / "fetch_stats.json")


def save_result(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def load_json(path: Path) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# Main runner
# ---------------------------------------------------------------------------

def estimate_and_print(
    org_iocs: dict[str, tuple[set[str], set[str], set[str]]],
    ioc_types: set[str],
    output_dir: Path,
    logger: logging.Logger,
    daily_limit: int = 500,
) -> None:
    all_sha256  = {s  for sha, _,   _    in org_iocs.values() for s  in sha} if "file"   in ioc_types else set()
    all_ips     = {ip for _,   ips, _    in org_iocs.values() for ip in ips} if "ip"     in ioc_types else set()
    all_domains = {d  for _,   _,   doms in org_iocs.values() for d  in doms} if "domain" in ioc_types else set()

    # API calls needed = IoCs not yet in global cache
    need_files   = sum(1 for s  in all_sha256  if not global_cache_path(output_dir, "files",   s ).exists()) if "file"   in ioc_types else 0
    need_ips     = sum(1 for ip in all_ips     if not global_cache_path(output_dir, "ips",     ip).exists()) if "ip"     in ioc_types else 0
    need_domains = sum(1 for d  in all_domains if not global_cache_path(output_dir, "domains", d ).exists()) if "domain" in ioc_types else 0

    total_calls     = (len(all_sha256) * len(FILE_RELATIONSHIPS)
                       + len(all_ips) * len(IP_RELATIONSHIPS)
                       + len(all_domains) * len(DOMAIN_RELATIONSHIPS))
    remaining_calls = (need_files * len(FILE_RELATIONSHIPS)
                       + need_ips * len(IP_RELATIONSHIPS)
                       + need_domains * len(DOMAIN_RELATIONSHIPS))
    days_needed     = remaining_calls / daily_limit if daily_limit else float("inf")

    logger.info("=" * 60)
    logger.info(f"  Orgs to process     : {len(org_iocs)}")
    logger.info(f"  Unique SHA256 files : {len(all_sha256):>7,}  (global cached: {len(all_sha256)-need_files:,})")
    logger.info(f"  Unique IPs          : {len(all_ips):>7,}  (global cached: {len(all_ips)-need_ips:,})")
    logger.info(f"  Unique Domains      : {len(all_domains):>7,}  (global cached: {len(all_domains)-need_domains:,})")
    logger.info(f"  Total API calls     : {total_calls:>7,}  (remaining: {remaining_calls:,})")
    logger.info(f"  Estimated days      : {days_needed:.1f}  at {daily_limit:,}/day")
    logger.info("=" * 60)


def run(
    vt_results_dir: Path,
    output_dir: Path,
    api_key: str,
    org_filter: set[str] | None,
    ioc_types: set[str],
    dry_run: bool,
    daily_limit: int,
    logger: logging.Logger,
    stop_on_quota: bool = False,
) -> None:
    # ── Phase 1: Collect IoCs per org ───────────────────────────────────────
    logger.info("Phase 1: Scanning VT results to collect IoCs...")
    org_iocs = collect_iocs(vt_results_dir, org_filter, logger)

    # ── Phase 2: Estimate ───────────────────────────────────────────────────
    logger.info("Phase 2: Checking cache...")
    estimate_and_print(org_iocs, ioc_types, output_dir, logger, daily_limit)

    if dry_run:
        logger.info("Dry run complete. No API calls made.")
        return

    # ── Phase 3: Query per org ──────────────────────────────────────────────
    output_dir.mkdir(parents=True, exist_ok=True)
    stats = make_stats(org_iocs, ioc_types)
    save_stats(stats, output_dir)

    session = requests.Session()
    session.headers.update({"x-apikey": api_key})
    rate_limiter = RateLimiter(requests_per_min=600, daily_limit=daily_limit,
                               stop_on_quota=stop_on_quota)

    try:
      _run_queries(org_iocs, ioc_types, output_dir, session, rate_limiter, stats, logger)
    except QuotaExhausted as e:
        save_stats(stats, output_dir)
        logger.info(f"⏸ {e}")
        logger.info(f"已完成 API calls: {stats['total_api_calls_made']:,}")
        return

    save_stats(stats, output_dir)
    logger.info("All done.")
    logger.info(f"Final coverage rates: {json.dumps(stats['coverage_rates'], indent=2)}")


def _run_queries(
    org_iocs: dict[str, tuple[set[str], set[str], set[str]]],
    ioc_types: set[str],
    output_dir: Path,
    session: requests.Session,
    rate_limiter: RateLimiter,
    stats: dict,
    logger: logging.Logger,
) -> None:
    """實際查詢迴圈，QuotaExhausted 會向上拋出。"""
    progress_every = 100

    for org_name, (sha256_set, ip_set, domain_set) in sorted(org_iocs.items()):
        logger.info(f"─── Org: {org_name} ───")

        # ── 3a: Files ───────────────────────────────────────────────────────
        if "file" in ioc_types:
            todo_files = [
                s for s in sorted(sha256_set)
                if not org_result_path(output_dir, org_name, "files", s).exists()
            ]
            if todo_files:
                logger.info(f"  Phase 3a [{org_name}]: Querying {len(todo_files):,} files "
                            f"({len(FILE_RELATIONSHIPS)} endpoints each)...")

            for i, sha256 in enumerate(todo_files, 1):
                g_path = global_cache_path(output_dir, "files", sha256)
                o_path = org_result_path(output_dir, org_name, "files", sha256)

                if g_path.exists():
                    result = load_json(g_path)
                    save_result(o_path, result)
                    stats["cache_hits"] += 1
                else:
                    result = fetch_file_relationships(sha256, session, rate_limiter, logger)
                    save_result(g_path, result)
                    save_result(o_path, result)

                    stats["files_queried"] += 1
                    calls_this_file = len(FILE_RELATIONSHIPS) - len(result.get("errors", []))
                    stats["total_api_calls_made"] += calls_this_file
                    if result.get("errors"):
                        stats["errors"] += len(result["errors"])

                    has_any = False
                    for rel in FILE_RELATIONSHIPS:
                        if result.get(rel):
                            has_any = True
                            key = f"files_with_{rel}"
                            stats[key] = stats.get(key, 0) + 1
                    if not has_any:
                        stats["files_all_empty"] += 1

                if i % progress_every == 0 or i == len(todo_files):
                    save_stats(stats, output_dir)
                    logger.info(
                        f"  [files/{org_name}] {i:,}/{len(todo_files):,} done | "
                        f"calls: {stats['total_api_calls_made']:,} | "
                        f"any_rel: {stats['coverage_rates'].get('file_any_relationship','N/A')}"
                    )

        # ── 3b: IPs ─────────────────────────────────────────────────────────
        if "ip" in ioc_types:
            todo_ips = [
                ip for ip in sorted(ip_set)
                if not org_result_path(output_dir, org_name, "ips", ip).exists()
            ]
            if todo_ips:
                logger.info(f"  Phase 3b [{org_name}]: Querying {len(todo_ips):,} IPs "
                            f"({len(IP_RELATIONSHIPS)} endpoints each)...")

            for i, ip in enumerate(todo_ips, 1):
                g_path = global_cache_path(output_dir, "ips", ip)
                o_path = org_result_path(output_dir, org_name, "ips", ip)

                if g_path.exists():
                    save_result(o_path, load_json(g_path))
                    stats["cache_hits"] += 1
                else:
                    result = fetch_ip_relationships(ip, session, rate_limiter, logger)
                    save_result(g_path, result)
                    save_result(o_path, result)

                    stats["ips_queried"] += 1
                    calls_this_ip = len(IP_RELATIONSHIPS) - len(result.get("errors", []))
                    stats["total_api_calls_made"] += calls_this_ip
                    if result.get("errors"):
                        stats["errors"] += len(result["errors"])
                    if result.get("resolutions"):
                        stats["ips_with_resolutions"] += 1

                if i % progress_every == 0 or i == len(todo_ips):
                    save_stats(stats, output_dir)
                    logger.info(
                        f"  [ips/{org_name}] {i:,}/{len(todo_ips):,} done | "
                        f"with_resolutions: {stats['coverage_rates'].get('ip_resolutions','N/A')}"
                    )

        # ── 3c: Domains ─────────────────────────────────────────────────────
        if "domain" in ioc_types:
            todo_domains = [
                d for d in sorted(domain_set)
                if not org_result_path(output_dir, org_name, "domains", d).exists()
            ]
            if todo_domains:
                logger.info(f"  Phase 3c [{org_name}]: Querying {len(todo_domains):,} domains "
                            f"({len(DOMAIN_RELATIONSHIPS)} endpoints each)...")

            for i, domain in enumerate(todo_domains, 1):
                g_path = global_cache_path(output_dir, "domains", domain)
                o_path = org_result_path(output_dir, org_name, "domains", domain)

                if g_path.exists():
                    save_result(o_path, load_json(g_path))
                    stats["cache_hits"] += 1
                else:
                    result = fetch_domain_relationships(domain, session, rate_limiter, logger)
                    save_result(g_path, result)
                    save_result(o_path, result)

                    stats["domains_queried"] += 1
                    calls_this_dom = len(DOMAIN_RELATIONSHIPS) - len(result.get("errors", []))
                    stats["total_api_calls_made"] += calls_this_dom
                    if result.get("errors"):
                        stats["errors"] += len(result["errors"])
                    if result.get("resolutions"):
                        stats["domains_with_resolutions"] += 1

                if i % progress_every == 0 or i == len(todo_domains):
                    save_stats(stats, output_dir)
                    logger.info(
                        f"  [domains/{org_name}] {i:,}/{len(todo_domains):,} done | "
                        f"with_resolutions: {stats['coverage_rates'].get('domain_resolutions','N/A')}"
                    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def load_api_key(args_key: str | None, search_dirs: list[Path]) -> str:
    if args_key:
        return args_key

    import os
    env_key = os.environ.get("VT_API_KEY") or os.environ.get("virustotal_api_key")
    if env_key:
        return env_key

    # Try .env files in search dirs
    for d in search_dirs:
        env_file = d / ".env"
        if env_file.exists():
            for line in env_file.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line.startswith("#") or "=" not in line:
                    continue
                k, _, v = line.partition("=")
                k = k.strip().lower()
                v = v.strip().strip('"').strip("'")
                if k in ("vt_api_key", "virustotal_api_key"):
                    return v

    return ""


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Fetch VirusTotal Relationship data for APT IoCs.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--vt-results-dir",
        default="./VT_results",
        help="Directory containing {org}_VT/vt_results.json files (default: ./VT_results)",
    )
    parser.add_argument(
        "--output-dir",
        default="./vt_relationships",
        help="Output directory for relationship cache (default: ./vt_relationships)",
    )
    parser.add_argument(
        "--api-key",
        default=None,
        help="VT API key (or set VT_API_KEY env var / .env file)",
    )
    parser.add_argument(
        "--orgs",
        default=None,
        help="Comma-separated org names to process (e.g. APT28,APT29). Default: all.",
    )
    parser.add_argument(
        "--ioc-types",
        default="file,ip,domain",
        help="Comma-separated IoC types to query: file, ip, domain (default: all)",
    )
    parser.add_argument(
        "--daily-limit",
        type=int,
        default=500,
        help="Daily API call budget (default: 500)",
    )
    parser.add_argument(
        "--stop-on-quota",
        action="store_true",
        default=True,
        help="到達每日限額時儲存進度並退出（預設開啟）。用 --no-stop-on-quota 改為 sleep 等待。",
    )
    parser.add_argument(
        "--no-stop-on-quota",
        action="store_false",
        dest="stop_on_quota",
        help="到達每日限額時 sleep 等待隔天，而非退出。",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Collect and count IoCs, estimate API usage — no actual requests.",
    )
    args = parser.parse_args()

    vt_results_dir = Path(args.vt_results_dir).resolve()
    output_dir = Path(args.output_dir).resolve()

    if not vt_results_dir.exists():
        print(f"ERROR: --vt-results-dir not found: {vt_results_dir}", file=sys.stderr)
        sys.exit(1)

    # Search dirs for .env: project root, script dir
    script_dir = Path(__file__).parent
    project_root = script_dir.parent
    env_search = [project_root, script_dir, project_root / "archive" / "virustotal_apiTest"]
    api_key = load_api_key(args.api_key, env_search)

    if not api_key and not args.dry_run:
        print(
            "ERROR: No API key found. Pass --api-key, set VT_API_KEY env var, "
            "or put virustotal_api_key=... in virustotal_apiTest/.env",
            file=sys.stderr,
        )
        sys.exit(1)

    org_filter: set[str] | None = None
    if args.orgs:
        org_filter = {o.strip() for o in args.orgs.split(",") if o.strip()}

    ioc_types = {t.strip().lower() for t in args.ioc_types.split(",") if t.strip()}
    valid_types = {"file", "ip", "domain"}
    unknown = ioc_types - valid_types
    if unknown:
        print(f"ERROR: Unknown --ioc-types: {unknown}. Valid: file, ip, domain", file=sys.stderr)
        sys.exit(1)

    log_path = output_dir / "progress.log"
    logger = setup_logging(log_path)

    logger.info(f"vt-results-dir : {vt_results_dir}")
    logger.info(f"output-dir     : {output_dir}")
    logger.info(f"ioc-types      : {sorted(ioc_types)}")
    logger.info(f"org-filter     : {sorted(org_filter) if org_filter else 'all'}")
    logger.info(f"daily-limit    : {args.daily_limit:,}")
    logger.info(f"stop-on-quota  : {args.stop_on_quota}")
    logger.info(f"dry-run        : {args.dry_run}")

    run(
        vt_results_dir=vt_results_dir,
        output_dir=output_dir,
        api_key=api_key,
        org_filter=org_filter,
        ioc_types=ioc_types,
        dry_run=args.dry_run,
        daily_limit=args.daily_limit,
        logger=logger,
        stop_on_quota=args.stop_on_quota,
    )


if __name__ == "__main__":
    main()
