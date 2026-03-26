#!/usr/bin/env python3
"""
Batch-clean org_iocs JSON files. (v2 — improved)

Changes from v1:
  1. Cross-hash dedup: md5/sha1/sha256 pointing to the same file are merged.
  2. URL-IP dedup: URLs like "http://1.2.3.4" are collapsed into ipv4 records.
  3. Defanged IoC refanging: hxxp://, [.], [:] are normalized before processing.
  4. Expanded eTLD blacklist: security vendors, CDN, social media, etc.
  5. Expanded DDNS whitelist: common DDNS services APTs abuse.
  6. Email-type IoCs filtered: gov/vendor contact emails are noise; only
     attacker-related emails are kept.
  7. Source merging during dedup: all source URLs are preserved across duplicates.
  8. Cleaning statistics: every run produces a stats dict for reproducibility.
  9. Safe URL parsing with try/except on malformed input.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from utils.filters import (
    IOCFilter,
    extract_domain_from_url,
    get_etld_plus_one,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

# ── Allowed IoC types ────────────────────────────────────────────────
# email is excluded by default; attacker emails are rare and noisy
ALLOWED_TYPES = {"ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256"}

# ── eTLD+1 Blacklist (noise domains) ────────────────────────────────
ETLD_BLACKLIST = {
    # --- News / Media ---
    "bbc.com", "cnn.com", "nytimes.com", "scmp.com", "ejinsight.com",
    "reuters.com", "theguardian.com",
    # --- Big Tech / Social ---
    "google.com", "microsoft.com", "github.com", "twitter.com",
    "facebook.com", "linkedin.com", "youtube.com", "instagram.com",
    "apple.com", "t.me",
    # --- Security Vendors (reports, not IoCs) ---
    "fireeye.com", "mandiant.com", "virustotal.com", "kaspersky.com",
    "symantec.com", "broadcom.com", "mcafee.com", "trendmicro.com",
    "malwarebytes.com", "eset.com", "sophos.com", "paloaltonetworks.com",
    "fortinet.com", "crowdstrike.com", "proofpoint.com",
    "secureworks.com", "talosintelligence.com", "zscaler.com",
    "checkpoint.com", "sentinelone.com", "recordedfuture.com",
    "cybereason.com",
    # --- CDN / Cloud / Infra (too generic → super-node risk) ---
    "amazonaws.com", "cloudflare.com", "akamai.com",
    "azure.com", "azurewebsites.net", "cloudfront.net",
    "fastly.net", "googleusercontent.com",
    # --- Reference / Wiki ---
    "wikipedia.org", "mitre.org", "attack.mitre.org",
    # --- Government (report contacts, not C2) ---
    "us-cert.gov", "cisa.gov", "nsa.gov", "fbi.gov",
    "dhs.gov", "nist.gov", "cert.gov",
}

# ── DDNS Whitelist (known APT-abused, keep even if noisy) ───────────
DDNS_WHITELIST = {
    "serveftp.com", "no-ip.com", "no-ip.org", "no-ip.biz",
    "dyndns.org", "dyndns.com", "hopto.org", "afraid.org",
    "zapto.org", "sytes.net", "ddns.net", "myftp.biz",
    "myftp.org", "servegame.com", "servehttp.com",
    "redirectme.net", "bounceme.net", "myvnc.com",
    "webhop.me", "serveblog.net", "servepics.com",
}

# ── Email domain whitelist (only keep emails on these domains) ──────
# These are commonly used by APT actors for registration / phishing
ATTACKER_EMAIL_INDICATORS = {
    "mail.com", "protonmail.com", "tutanota.com", "yandex.com",
    "yandex.ru", "mail.ru", "outlook.com", "hotmail.com",
    "gmx.com", "gmx.net",
}

# ── Regex ────────────────────────────────────────────────────────────
_RE_IPV4 = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
_RE_IPV6 = re.compile(r"^[0-9a-fA-F:]+$")  # coarse check, ipaddress validates


# =====================================================================
#  Helper functions
# =====================================================================

def refang(value: str) -> str:
    """Restore defanged indicators to their real form."""
    value = value.replace("hxxp://", "http://").replace("hxxps://", "https://")
    value = value.replace("hXXp://", "http://").replace("hXXps://", "https://")
    value = value.replace("[.]", ".").replace("[:]", ":").replace("(.)", ".")
    value = value.replace("[at]", "@").replace("[@]", "@")
    return value


def safe_extract_domain(url: str) -> Optional[str]:
    """Extract domain from URL with error handling."""
    try:
        return extract_domain_from_url(url)
    except Exception:
        try:
            parsed = urlparse(url)
            return parsed.hostname
        except Exception:
            return None


def extract_host_from_url(url: str) -> Optional[str]:
    """Extract hostname from a URL string."""
    try:
        parsed = urlparse(url)
        return parsed.hostname
    except Exception:
        return None


def is_ip_address(value: str) -> bool:
    """Check if value is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_blacklisted_domain(domain: str) -> bool:
    """Check if a domain falls under the eTLD blacklist."""
    etld = get_etld_plus_one(domain)
    if not etld:
        return False
    if etld in DDNS_WHITELIST:
        return False
    return etld in ETLD_BLACKLIST


def is_useful_email(email: str) -> bool:
    """
    Only keep emails that look attacker-controlled.
    Gov / vendor contact addresses are noise.
    """
    parts = email.lower().split("@")
    if len(parts) != 2:
        return False
    domain = parts[1]
    # If domain is in known free-mail / attacker-used services → keep
    etld = get_etld_plus_one(domain)
    if etld and etld in ATTACKER_EMAIL_INDICATORS:
        return True
    # If domain is in our blacklist → definitely noise
    if is_blacklisted_domain(domain):
        return False
    # Unknown domain → probably attacker infra, keep it
    return True


# =====================================================================
#  Normalize
# =====================================================================

def normalize_ioc(item: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize a single IoC record in-place."""
    ioc_type = str(item.get("type", "")).lower().strip()
    value = refang(str(item.get("value", "")).strip())

    item["type"] = ioc_type
    item["value"] = value

    # Lowercase for comparisons
    if ioc_type in {"domain", "md5", "sha1", "sha256", "ipv4", "url", "email"}:
        item["value_normalized"] = value.lower()
    else:
        item["value_normalized"] = value

    # For URLs, extract and store domain
    if ioc_type == "url":
        domain = safe_extract_domain(value)
        if domain:
            item["domain"] = domain.lower()

    # Ensure sources is always a list
    sources = item.get("sources", [])
    if not isinstance(sources, list):
        sources = [sources]
    item["sources"] = [s for s in sources if s]

    return item


# =====================================================================
#  Deduplication (with source merging + cross-hash collapse)
# =====================================================================

def deduplicate_with_source_merge(
    iocs: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Deduplicate by (type, value_normalized).
    When duplicates are found, merge their sources lists.
    """
    seen: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for item in iocs:
        key = (item["type"], item["value_normalized"])
        if key in seen:
            existing_sources = set(seen[key].get("sources", []))
            new_sources = set(item.get("sources", []))
            seen[key]["sources"] = list(existing_sources | new_sources)
        else:
            seen[key] = deepcopy(item)
    return list(seen.values())


def cross_hash_merge(iocs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    If the same file appears as md5, sha1, AND sha256, merge them into
    one record (preferring sha256 as canonical).

    This relies on VT file_info which contains all three hashes.
    If file_info is absent, records stay separate.
    """
    # Build lookup: hash_value -> record
    hash_records: Dict[str, Dict[str, Any]] = {}
    non_hash_records: List[Dict[str, Any]] = []

    for item in iocs:
        if item["type"] in {"md5", "sha1", "sha256"}:
            hash_records[item["value_normalized"]] = item
        else:
            non_hash_records.append(item)

    # Group by file identity (using file_info cross-references)
    # file_group_key = sha256 if available, else original value
    groups: Dict[str, List[Dict[str, Any]]] = {}

    for val, rec in hash_records.items():
        fi = rec.get("file_info", {}) or {}
        canonical = (
            fi.get("sha256", "").lower()
            or fi.get("sha1", "").lower()
            or val
        )
        if canonical not in groups:
            groups[canonical] = []
        groups[canonical].append(rec)

    # Merge each group into one record
    merged_hashes: List[Dict[str, Any]] = []
    merge_count = 0

    for canonical_hash, group in groups.items():
        if len(group) == 1:
            merged_hashes.append(group[0])
            continue

        merge_count += len(group) - 1
        # Pick the sha256 record as base, or the one with most info
        base = None
        for rec in group:
            if rec["type"] == "sha256":
                base = rec
                break
        if base is None:
            base = max(group, key=lambda r: len(json.dumps(r.get("file_info", {}))))

        # Merge sources from all records
        all_sources = set()
        all_alt_hashes = {}
        for rec in group:
            all_sources.update(rec.get("sources", []))
            all_alt_hashes[rec["type"]] = rec["value"]

        base = deepcopy(base)
        base["type"] = "sha256"
        base["value"] = canonical_hash
        base["value_normalized"] = canonical_hash
        base["sources"] = list(all_sources)
        base["alt_hashes"] = all_alt_hashes  # preserve for reference
        merged_hashes.append(base)

    if merge_count > 0:
        logger.info(f"  Cross-hash merge: collapsed {merge_count} duplicate hash records")

    return non_hash_records + merged_hashes


def _detect_ip_type(value: str) -> str | None:
    """Return 'ipv4' or 'ipv6' if value is a valid IP, else None."""
    try:
        addr = ipaddress.ip_address(value)
        return "ipv4" if addr.version == 4 else "ipv6"
    except ValueError:
        return None


def collapse_url_ips(iocs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    URLs like 'http://1.2.3.4' or 'http://[::1]/path' where the host
    is a bare IP — merge into the corresponding ipv4/ipv6 record if it exists,
    otherwise convert to the appropriate IP type.
    """
    ip_records: Dict[str, Dict[str, Any]] = {}
    url_records: List[Dict[str, Any]] = []
    other_records: List[Dict[str, Any]] = []

    for item in iocs:
        if item["type"] in ("ipv4", "ipv6"):
            ip_records[item["value_normalized"]] = item
        elif item["type"] == "url":
            url_records.append(item)
        else:
            other_records.append(item)

    kept_urls: List[Dict[str, Any]] = []
    collapsed_count = 0

    for url_rec in url_records:
        host = extract_host_from_url(url_rec["value"])
        if host and is_ip_address(host):
            ip_norm = host.lower()
            ip_type = _detect_ip_type(host) or "ipv4"
            if ip_norm in ip_records:
                # Merge sources into existing IP record
                existing = set(ip_records[ip_norm].get("sources", []))
                new = set(url_rec.get("sources", []))
                ip_records[ip_norm]["sources"] = list(existing | new)
            else:
                # Convert URL to IP record
                converted = deepcopy(url_rec)
                converted["type"] = ip_type
                converted["value"] = host
                converted["value_normalized"] = ip_norm
                converted.pop("domain", None)
                ip_records[ip_norm] = converted
            collapsed_count += 1
        else:
            kept_urls.append(url_rec)

    if collapsed_count > 0:
        logger.info(f"  URL-IP collapse: {collapsed_count} bare-IP URLs merged into IP records")

    return other_records + list(ip_records.values()) + kept_urls


# =====================================================================
#  Main cleaning pipeline
# =====================================================================

def clean_iocs(iocs: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Full cleaning pipeline. Returns (cleaned_list, stats_dict).
    """
    stats: Dict[str, Any] = {"input_count": len(iocs)}

    # ── Step 1: Type filter ──────────────────────────────────────────
    # Include email temporarily for email filtering step
    allowed_plus_email = ALLOWED_TYPES | {"email"}
    filtered_by_type = [
        i for i in iocs
        if str(i.get("type", "")).lower().strip() in allowed_plus_email
    ]
    stats["after_type_filter"] = len(filtered_by_type)
    stats["dropped_by_type"] = stats["input_count"] - stats["after_type_filter"]

    # ── Step 2: Normalize (refang + lowercase + extract domain) ──────
    normalized = [normalize_ioc(deepcopy(i)) for i in filtered_by_type]

    # ── Step 3: Filter emails (only keep attacker-related) ───────────
    email_before = sum(1 for i in normalized if i["type"] == "email")
    normalized = [
        i for i in normalized
        if i["type"] != "email" or is_useful_email(i["value"])
    ]
    email_after = sum(1 for i in normalized if i["type"] == "email")
    stats["emails_removed"] = email_before - email_after
    stats["emails_kept"] = email_after

    # ── Step 4: Deduplicate with source merging ──────────────────────
    before_dedup = len(normalized)
    deduped = deduplicate_with_source_merge(normalized)
    stats["duplicates_removed"] = before_dedup - len(deduped)

    # ── Step 5: Cross-hash merge ─────────────────────────────────────
    before_xhash = len(deduped)
    deduped = cross_hash_merge(deduped)
    stats["cross_hash_merged"] = before_xhash - len(deduped)

    # ── Step 6: Collapse bare-IP URLs into ipv4 ─────────────────────
    before_collapse = len(deduped)
    deduped = collapse_url_ips(deduped)
    stats["url_ip_collapsed"] = before_collapse - len(deduped)

    # ── Step 7: Domain / IP filtering ────────────────────────────────
    ip_filter = IOCFilter()
    cleaned: List[Dict[str, Any]] = []
    dropped_private_ip = 0
    dropped_blacklist = 0

    for item in deduped:
        ioc_type = item.get("type", "")
        value = item.get("value", "")

        if ioc_type in ("ipv4", "ipv6"):
            if ip_filter.is_private_ip(value):
                dropped_private_ip += 1
                continue
        elif ioc_type == "domain":
            if is_blacklisted_domain(value.lower()):
                dropped_blacklist += 1
                continue
        elif ioc_type == "url":
            domain = item.get("domain") or safe_extract_domain(value)
            if domain and is_blacklisted_domain(domain.lower()):
                dropped_blacklist += 1
                continue

        # Remove internal fields
        item.pop("value_normalized", None)
        cleaned.append(item)

    stats["dropped_private_ip"] = dropped_private_ip
    stats["dropped_blacklist_domain"] = dropped_blacklist
    stats["output_count"] = len(cleaned)

    # ── Step 8: Orphan check ─────────────────────────────────────────
    orphans = [i for i in cleaned if not i.get("sources")]
    if orphans:
        logger.warning(
            f"  {len(orphans)} IoCs have no source attribution — "
            "co-occurrence edges cannot be built for these"
        )
    stats["orphan_no_source"] = len(orphans)

    # ── Final type distribution ──────────────────────────────────────
    from collections import Counter
    stats["output_type_distribution"] = dict(
        Counter(i["type"] for i in cleaned)
    )

    return cleaned, stats


# =====================================================================
#  File I/O
# =====================================================================

def process_file(input_path: Path, output_path: Path) -> Dict[str, Any]:
    """Process one org's iocs.json. Returns stats."""
    with input_path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)

    if not isinstance(data, list):
        raise ValueError(f"Unexpected JSON format (expected list): {input_path}")

    logger.info(f"Processing {input_path} ({len(data)} IoCs)")
    cleaned, stats = clean_iocs(data)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        json.dump(cleaned, handle, indent=2, ensure_ascii=False)
        handle.write("\n")

    # Also write stats alongside output
    stats_path = output_path.with_name("cleaning_stats.json")
    with stats_path.open("w", encoding="utf-8") as handle:
        json.dump(stats, handle, indent=2, ensure_ascii=False)
        handle.write("\n")

    logger.info(f"  Output: {stats['output_count']} IoCs → {output_path}")
    return stats


def main() -> None:
    project_root = Path(__file__).resolve().parent.parent
    input_root = project_root / "org_iocs"
    output_root = project_root / "org_iocs_cleaned"

    all_stats = {}
    for input_path in sorted(input_root.rglob("iocs.json")):
        rel_path = input_path.relative_to(input_root)
        output_path = output_root / rel_path
        org_name = rel_path.parts[0] if rel_path.parts else input_path.stem
        all_stats[org_name] = process_file(input_path, output_path)

    # Write aggregate stats
    agg_path = output_root / "all_cleaning_stats.json"
    with agg_path.open("w", encoding="utf-8") as handle:
        json.dump(all_stats, handle, indent=2, ensure_ascii=False)
        handle.write("\n")

    logger.info(f"Done. Cleaned files → {output_root}")
    logger.info(f"Aggregate stats   → {agg_path}")


if __name__ == "__main__":
    main()
