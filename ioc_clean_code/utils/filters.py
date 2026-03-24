"""
Utility filters for IoC cleaning.

Provides:
  - IOCFilter: RFC1918 / reserved IP filtering
  - extract_domain_from_url: extract hostname from URL string
  - get_etld_plus_one: approximate eTLD+1 extraction
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse


class IOCFilter:
    """Filter for IoC values (private IPs, reserved ranges, etc.)."""

    def is_private_ip(self, value: str) -> bool:
        """Return True if the IP address is private (RFC1918) or reserved."""
        try:
            addr = ipaddress.ip_address(value)
            return addr.is_private or addr.is_reserved or addr.is_loopback
        except ValueError:
            return False


def extract_domain_from_url(url: str) -> str | None:
    """Extract the hostname (domain) from a URL string."""
    try:
        parsed = urlparse(url)
        host = parsed.hostname
        if host:
            return host.lower().rstrip(".")
        return None
    except Exception:
        return None


# Common multi-part TLDs (public suffix approximation)
_MULTI_PART_TLDS = {
    "co.uk", "co.jp", "co.kr", "co.in", "co.za", "co.nz", "co.il",
    "com.au", "com.br", "com.cn", "com.tw", "com.hk", "com.sg",
    "com.my", "com.ph", "com.ar", "com.mx", "com.tr", "com.ua",
    "org.uk", "org.au", "org.cn", "org.tw",
    "net.au", "net.cn", "net.tw",
    "ac.uk", "ac.jp", "ac.kr", "ac.in",
    "gov.uk", "gov.au", "gov.cn", "gov.tw",
    "edu.au", "edu.cn", "edu.tw",
    "ne.jp", "or.jp", "go.jp", "or.kr",
}


def get_etld_plus_one(domain: str) -> str | None:
    """
    Approximate eTLD+1 extraction without external dependencies.

    Examples:
        "mail.example.com"      -> "example.com"
        "sub.domain.co.uk"      -> "domain.co.uk"
        "example.com"           -> "example.com"
        "com"                   -> None
    """
    if not domain:
        return None

    domain = domain.lower().rstrip(".")
    parts = domain.split(".")

    if len(parts) < 2:
        return None

    # Check if the last two parts form a known multi-part TLD
    if len(parts) >= 3:
        candidate_tld = f"{parts[-2]}.{parts[-1]}"
        if candidate_tld in _MULTI_PART_TLDS:
            if len(parts) >= 3:
                return f"{parts[-3]}.{candidate_tld}"
            return None

    # Default: last two parts
    return f"{parts[-2]}.{parts[-1]}"
