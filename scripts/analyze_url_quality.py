#!/usr/bin/env python3
"""
analyze_url_quality.py — 分析所有組織的 URL IoC 品質。

統計項目：
  1. 各 org 的 URL 數量與佔比
  2. 有 path vs bare domain/IP（無 path 的 URL 跟 domain 節點完全重複）
  3. 疑似非惡意 URL（新聞、報告、資安廠商、政府、學術）
  4. Malformed URL（含 \r\n、奇怪轉義）
  5. C2 候選 URL（有 path + domain 不在非惡意白名單中）

用法：
  uv run python scripts/analyze_url_quality.py
  uv run python scripts/analyze_url_quality.py --show-c2     # 列出所有 C2 候選 URL
  uv run python scripts/analyze_url_quality.py --show-noise   # 列出所有噪音 URL
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

BASE_DIR = Path(__file__).parent.parent
CLEANED_DIR = BASE_DIR / "org_iocs_cleaned"

# 非惡意 domain 白名單（eTLD+1 層級）
# 參考 clean_iocs_v2.py ETLD_BLACKLIST，並擴充常見的 CTI 報告來源
NOISE_DOMAINS = {
    # ── 新聞 / 媒體 ──
    "bbc.com", "bbc.co.uk", "cnn.com", "nytimes.com", "reuters.com",
    "theguardian.com", "washingtonpost.com", "wsj.com", "vice.com",
    "nbcnews.com", "thehill.com", "wired.com", "arstechnica.com",
    "forbes.com", "bloomberg.com", "euronews.com", "rt.com",
    "netzpolitik.org", "scmp.com", "ejinsight.com", "spiegel.de",
    "lemonde.fr", "dw.com",
    # ── 資安廠商 / 研究 ──
    "fireeye.com", "mandiant.com", "virustotal.com", "kaspersky.com",
    "symantec.com", "broadcom.com", "mcafee.com", "trendmicro.com",
    "malwarebytes.com", "eset.com", "sophos.com", "paloaltonetworks.com",
    "fortinet.com", "crowdstrike.com", "proofpoint.com", "secureworks.com",
    "talosintelligence.com", "zscaler.com", "checkpoint.com",
    "sentinelone.com", "recordedfuture.com", "cybereason.com",
    "welivesecurity.com", "securelist.com", "threatconnect.com",
    "virusbtn.com", "virusradar.com", "securityweek.com",
    "darkreading.com", "bleepingcomputer.com", "infosecurity-magazine.com",
    "thehackernews.com", "threatpost.com", "cyberscoop.com",
    "greyhathacker.net", "digitaldefense.com",
    # ── Big Tech ──
    "google.com", "microsoft.com", "github.com", "githubusercontent.com",
    "twitter.com", "facebook.com", "linkedin.com", "youtube.com",
    "apple.com", "amazon.com", "aka.ms",
    # ── 政府 / 官方 ──
    "us-cert.gov", "cisa.gov", "nsa.gov", "fbi.gov", "dhs.gov",
    "nist.gov", "cert.gov", "cert.org", "justice.gov", "dni.gov",
    "senate.gov", "congress.gov", "state.gov", "fas.org",
    "onderzoeksraad.nl", "pst.no",
    # ── 學術 / 標準組織 ──
    "wikipedia.org", "mitre.org", "attack.mitre.org",
    "arxiv.org", "ieee.org", "acm.org",
    # ── 運動 / 國際組織（APT28 相關噪音）──
    "wada-ama.org", "olympic.org", "sfpa.sk",
    # ── CDN / Cloud（太通用）──
    "amazonaws.com", "cloudflare.com", "akamai.com",
    "azure.com", "cloudfront.net", "fastly.net",
    "googleusercontent.com",
    # ── 會議 ──
    "blackhat.com",
    "ecfr.eu",
}

# Malformed 特徵
_RE_MALFORMED = re.compile(r"[\r\n\x00]|\\r|\\n|\\\\")
_RE_IPV4 = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def extract_etld_plus_one(domain: str) -> str:
    """簡易 eTLD+1 提取（不依賴 publicsuffix2）。"""
    parts = domain.lower().strip(".").split(".")
    # 常見 ccSLD（如 co.uk, com.au）
    cc_sld = {"co.uk", "com.au", "co.jp", "co.kr", "com.br", "com.cn",
              "org.uk", "net.au", "ac.uk", "gov.uk", "com.tw", "org.tw",
              "edu.tw", "net.tw", "com.hk", "org.hk"}
    if len(parts) >= 3:
        last2 = f"{parts[-2]}.{parts[-1]}"
        if last2 in cc_sld:
            return f"{parts[-3]}.{last2}" if len(parts) >= 3 else last2
    if len(parts) >= 2:
        return f"{parts[-2]}.{parts[-1]}"
    return domain


def classify_url(url_value: str) -> str:
    """
    分類一個 URL IoC。回傳分類標籤：
      - "malformed"     : 含特殊字元、解析失敗
      - "bare_domain"   : 無 path（http://evil.com → 跟 domain 節點重複）
      - "bare_ip"       : 無 path 的 IP URL（http://1.2.3.4 → 跟 ip 節點重複）
      - "noise"         : domain 在 NOISE_DOMAINS 白名單中
      - "c2_candidate"  : 有 path + domain 不在白名單 → 真正有價值的 C2 URL
    """
    # Malformed check
    if _RE_MALFORMED.search(url_value):
        return "malformed"

    # Parse
    try:
        if "://" not in url_value:
            url_value = f"http://{url_value}"
        parsed = urlparse(url_value)
        hostname = (parsed.hostname or "").lower().strip(".")
    except Exception:
        return "malformed"

    if not hostname:
        return "malformed"

    # Path check（去掉 trailing slash 後是否還有 path）
    path = (parsed.path or "").rstrip("/")
    has_path = bool(path and path != "")
    # 也檢查 query string
    has_query = bool(parsed.query)

    is_ip = _RE_IPV4.match(hostname)

    if not has_path and not has_query:
        return "bare_ip" if is_ip else "bare_domain"

    # Noise domain check
    if not is_ip:
        etld1 = extract_etld_plus_one(hostname)
        if etld1 in NOISE_DOMAINS or hostname in NOISE_DOMAINS:
            return "noise"

    return "c2_candidate"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="分析 URL IoC 品質")
    parser.add_argument("--show-c2", action="store_true",
                        help="列出所有 C2 候選 URL")
    parser.add_argument("--show-noise", action="store_true",
                        help="列出所有噪音 URL")
    parser.add_argument("--show-malformed", action="store_true",
                        help="列出所有 malformed URL")
    args = parser.parse_args()

    # ── 收集所有 URL IoC ──
    org_stats: list[dict] = []
    all_urls: list[dict] = []  # {"org", "value", "sources", "class"}

    for org_dir in sorted(CLEANED_DIR.iterdir()):
        iocs_file = org_dir / "iocs.json"
        if not iocs_file.exists():
            continue

        data = json.loads(iocs_file.read_text(encoding="utf-8"))
        total_iocs = len(data)
        urls = [i for i in data if i.get("type", "").lower() == "url"]

        if not urls:
            continue

        counts = {"malformed": 0, "bare_domain": 0, "bare_ip": 0,
                  "noise": 0, "c2_candidate": 0}

        for u in urls:
            cls = classify_url(u["value"])
            counts[cls] += 1
            all_urls.append({
                "org": org_dir.name,
                "value": u["value"],
                "sources": u.get("sources", []),
                "class": cls,
            })

        org_stats.append({
            "org": org_dir.name,
            "total_iocs": total_iocs,
            "url_count": len(urls),
            **counts,
        })

    # ── 全域統計 ──
    total_urls = sum(s["url_count"] for s in org_stats)
    total_c2 = sum(s["c2_candidate"] for s in org_stats)
    total_noise = sum(s["noise"] for s in org_stats)
    total_bare_domain = sum(s["bare_domain"] for s in org_stats)
    total_bare_ip = sum(s["bare_ip"] for s in org_stats)
    total_malformed = sum(s["malformed"] for s in org_stats)

    print("=" * 80)
    print("URL IoC 品質分析報告")
    print("=" * 80)
    print()
    print(f"涵蓋組織數：{len(org_stats)}")
    print(f"URL IoC 總數：{total_urls}")
    print()
    print("── 全域分類統計 ──")
    print()
    print(f"  {'分類':<20} {'數量':>6} {'佔比':>8}  說明")
    print(f"  {'─' * 20} {'─' * 6} {'─' * 8}  {'─' * 40}")
    print(f"  {'c2_candidate':<20} {total_c2:>6} {total_c2/max(total_urls,1)*100:>7.1f}%"
          f"  ✅ 有 path + 非噪音 domain → 值得建 URL 節點")
    print(f"  {'bare_domain':<20} {total_bare_domain:>6} {total_bare_domain/max(total_urls,1)*100:>7.1f}%"
          f"  ⚠️  無 path → 跟 domain 節點完全重複")
    print(f"  {'bare_ip':<20} {total_bare_ip:>6} {total_bare_ip/max(total_urls,1)*100:>7.1f}%"
          f"  ⚠️  無 path 的 IP URL → 跟 ip 節點重複")
    print(f"  {'noise':<20} {total_noise:>6} {total_noise/max(total_urls,1)*100:>7.1f}%"
          f"  ❌ 新聞/報告/廠商網站（非 C2）")
    print(f"  {'malformed':<20} {total_malformed:>6} {total_malformed/max(total_urls,1)*100:>7.1f}%"
          f"  ❌ 含特殊字元或解析失敗")
    print(f"  {'─' * 20} {'─' * 6} {'─' * 8}")
    print(f"  {'合計':<20} {total_urls:>6} {100.0:>7.1f}%")
    print()

    # ── 各 Org 統計表 ──
    print("── 各組織統計（依 C2 候選數排序）──")
    print()
    print(f"  {'Org':<25} {'URLs':>5} {'C2':>5} {'Bare':>5} {'Noise':>5} "
          f"{'Bad':>5} {'C2%':>6}")
    print(f"  {'─' * 25} {'─' * 5} {'─' * 5} {'─' * 5} {'─' * 5} "
          f"{'─' * 5} {'─' * 6}")

    for s in sorted(org_stats, key=lambda x: x["c2_candidate"], reverse=True):
        bare = s["bare_domain"] + s["bare_ip"]
        c2_pct = s["c2_candidate"] / max(s["url_count"], 1) * 100
        print(f"  {s['org']:<25} {s['url_count']:>5} {s['c2_candidate']:>5} "
              f"{bare:>5} {s['noise']:>5} {s['malformed']:>5} {c2_pct:>5.0f}%")

    print()

    # ── C2 候選 URL 的 domain 統計 ──
    c2_urls = [u for u in all_urls if u["class"] == "c2_candidate"]
    c2_domains: dict[str, int] = {}
    for u in c2_urls:
        try:
            v = u["value"]
            if "://" not in v:
                v = f"http://{v}"
            hostname = (urlparse(v).hostname or "").lower()
            etld1 = extract_etld_plus_one(hostname)
            c2_domains[etld1] = c2_domains.get(etld1, 0) + 1
        except Exception:
            pass

    print(f"── C2 候選 URL 的 domain 分佈（共 {len(c2_domains)} 個不重複 eTLD+1）──")
    print()
    # 顯示出現 > 1 次的 domain（可能需要進一步檢查是否為噪音）
    repeated = [(d, c) for d, c in sorted(c2_domains.items(), key=lambda x: -x[1]) if c > 1]
    if repeated:
        print(f"  出現 > 1 次的 domain（共 {len(repeated)} 個，可能需檢查是否為噪音）：")
        for d, c in repeated[:30]:
            print(f"    {d:<40} × {c}")
        if len(repeated) > 30:
            print(f"    ... 及另外 {len(repeated) - 30} 個")
        print()

    # ── 可選：列出所有 C2 候選 ──
    if args.show_c2:
        print("── 所有 C2 候選 URL ──")
        print()
        for u in sorted(c2_urls, key=lambda x: x["org"]):
            print(f"  [{u['org']}] {u['value']}")
        print()

    # ── 可選：列出噪音 URL ──
    if args.show_noise:
        noise_urls = [u for u in all_urls if u["class"] == "noise"]
        print(f"── 所有噪音 URL（共 {len(noise_urls)} 個）──")
        print()
        for u in sorted(noise_urls, key=lambda x: x["org"]):
            print(f"  [{u['org']}] {u['value']}")
        print()

    # ── 可選：列出 malformed URL ──
    if args.show_malformed:
        bad_urls = [u for u in all_urls if u["class"] == "malformed"]
        print(f"── 所有 Malformed URL（共 {len(bad_urls)} 個）──")
        print()
        for u in sorted(bad_urls, key=lambda x: x["org"]):
            print(f"  [{u['org']}] {repr(u['value'])}")
        print()

    # ── 結論 ──
    print("=" * 80)
    print("結論")
    print("=" * 80)
    print()
    print(f"  若新增 URL 節點，有效 C2 候選數：{total_c2} / {total_urls}"
          f"（{total_c2/max(total_urls,1)*100:.1f}%）")
    print(f"  無價值（bare + noise + malformed）：{total_urls - total_c2}"
          f"（{(total_urls - total_c2)/max(total_urls,1)*100:.1f}%）")
    print()
    if total_c2 / max(total_urls, 1) > 0.3:
        print("  → C2 候選佔比 > 30%，建議新增 URL 節點類型。")
    elif total_c2 > 500:
        print("  → C2 候選數量超過 500，雖佔比不高但絕對數量足夠，建議新增 URL 節點類型。")
    else:
        print("  → C2 候選數量偏低，新增 URL 節點的投入產出比需再評估。")


if __name__ == "__main__":
    main()
