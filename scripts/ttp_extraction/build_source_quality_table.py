#!/usr/bin/env python3
"""
Build source reliability table for L5 TTP weighting.

Rule-based reliability scoring (0~1):
1) Government / CERT / official advisories: highest (0.90~0.95)
   - Domain endswith .gov / .mil, or includes cert/cisa/ncsc.
2) Major security vendors / primary CTI research labs: high (0.80~0.88)
   - e.g., mandiant, crowdstrike, paloalto(unit42), secureworks, microsoft, google, etc.
3) General research / vendor blogs: medium (0.68~0.78)
4) News / forum / social media / archive mirrors: lower (0.42~0.58)
5) Unknown domains: neutral default (0.62)
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path
from urllib.parse import unquote, urlparse

MAPPING_PATH = Path("scripts/ttp_extraction/ioc_ttp_mapping.json")
OUTPUT_PATH = Path("scripts/ttp_extraction/source_quality_table.json")


MONTHS = {
    "jan", "january", "feb", "february", "mar", "march", "apr", "april",
    "may", "jun", "june", "jul", "july", "aug", "august", "sep", "sept",
    "september", "oct", "october", "nov", "november", "dec", "december",
}

HIGH_CONF_DOMAINS = {
    "cisa.gov",
    "us-cert.gov",
    "ncsc.gov.uk",
    "media.defense.gov",
    "justice.gov",
    "state.gov",
    "treasury.gov",
    "fbi.gov",
    "nsa.gov",
}

VENDOR_KEYWORDS = {
    "mandiant",
    "fireeye",
    "crowdstrike",
    "secureworks",
    "paloaltonetworks",
    "researchcenter.paloaltonetworks",
    "unit42",
    "microsoft",
    "google",
    "proofpoint",
    "trendmicro",
    "welivesecurity",
    "eset",
    "sentinelone",
    "checkpoint",
    "talos",
    "volexity",
    "f-secure",
    "dragos",
    "flashpoint",
    "cybereason",
    "recordedfuture",
    "threatconnect",
}

LOW_QUALITY_KEYWORDS = {
    "forum",
    "reddit",
    "x.com",
    "twitter",
    "facebook",
    "youtube",
    "news",
    "wired",
    "cnn",
    "arstechnica",
    "zdnet",
    "web.archive.org",
    "archive.org",
}


def _normalize_host(host: str) -> str:
    host = host.lower().strip().strip(".")
    if host.startswith("www."):
        host = host[4:]
    return host


def _unwrap_archive_url(url: str) -> str:
    parsed = urlparse(url)
    host = _normalize_host(parsed.netloc or parsed.hostname or "")
    if host not in {"web.archive.org", "archive.org"}:
        return url

    m = re.search(r"/web/[^/]+/(.+)$", parsed.path or "")
    if not m:
        return url

    nested = unquote(m.group(1))
    if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:/[^/]", nested) and "://" not in nested:
        nested = nested.replace(":/", "://", 1)
    elif "://" not in nested:
        nested = "https://" + nested.lstrip("/")
    return nested


def extract_source_domain(report_url: str) -> str:
    raw = _unwrap_archive_url(report_url)
    parsed = urlparse(raw)
    host = parsed.hostname or parsed.netloc or ""
    return _normalize_host(host)


def score_domain(domain: str) -> tuple[float, str]:
    if not domain:
        return 0.62, "unknown"

    if domain in HIGH_CONF_DOMAINS or domain.endswith(".gov") or domain.endswith(".mil"):
        return 0.95, "gov_official"
    if "cert" in domain or "cisa" in domain or "ncsc" in domain:
        return 0.92, "cert_advisory"
    if any(k in domain for k in VENDOR_KEYWORDS):
        return 0.86, "major_vendor_cti"
    if domain.endswith(".edu") or domain.endswith(".ac.uk") or domain.endswith(".org"):
        return 0.74, "research_org"
    if any(k in domain for k in LOW_QUALITY_KEYWORDS):
        return 0.50, "news_forum_social"
    return 0.62, "default"


def main() -> None:
    mapping = json.loads(MAPPING_PATH.read_text())

    stats: dict[str, dict] = defaultdict(lambda: {"report_count": 0, "ioc_ids": set()})

    for nid, item in mapping.items():
        reports = item.get("reports") or []
        for url in reports:
            domain = extract_source_domain(url)
            if not domain:
                continue
            stats[domain]["report_count"] += 1
            stats[domain]["ioc_ids"].add(nid)

    table: dict[str, dict] = {}
    for domain in sorted(stats.keys()):
        score, category = score_domain(domain)
        table[domain] = {
            "reliability_score": round(float(score), 4),
            "category": category,
            "report_count": int(stats[domain]["report_count"]),
            "ioc_count": int(len(stats[domain]["ioc_ids"])),
        }

    OUTPUT_PATH.write_text(json.dumps(table, indent=2, ensure_ascii=False))

    print(f"Saved: {OUTPUT_PATH}")
    print(f"Sources: {len(table)}")
    top = sorted(table.items(), key=lambda kv: kv[1]["report_count"], reverse=True)[:10]
    print("\nTop sources by report count:")
    for domain, info in top:
        print(
            f"  {domain:<45} "
            f"score={info['reliability_score']:.2f} "
            f"reports={info['report_count']:<5d} "
            f"iocs={info['ioc_count']}"
        )


if __name__ == "__main__":
    main()
