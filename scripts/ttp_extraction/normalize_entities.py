#!/usr/bin/env python3
"""
Phase 1: Entity Normalization + 白名單過濾。

兩層過濾：
  Layer 1: 表面正規化（strip 標點、lowercase、dedup）
  Layer 2: 白名單過濾（MITRE ATT&CK Software list for Tool, keyword list for Way）

輸入：scripts/ttp_extraction/{org}/*.json（NER 輸出）
輸出：同檔案，新增 entities_normalized 欄位（保留原始 entities）
"""

import argparse
import json
import re
import logging
from collections import Counter, defaultdict
from pathlib import Path

try:
    from thefuzz import fuzz
except ImportError:
    from fuzzywuzzy import fuzz

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

TTP_DIR = Path("scripts/ttp_extraction")
ATTACK_SW_LIST = TTP_DIR / "attack_software_list.txt"

# ── Layer 2: 白名單 ──

WAY_WHITELIST = [
    # Phishing variants
    "phishing", "spearphishing", "spear-phishing", "spear phishing",
    "whaling", "vishing", "smishing",
    # Initial Access
    "watering hole", "drive-by", "drive-by download", "supply chain",
    "trusted relationship", "exploit public-facing",
    # Execution
    "command-line", "powershell", "scripting", "macro", "scheduled task",
    "windows management instrumentation", "wmi", "dynamic data exchange",
    "mshta", "regsvr32", "rundll32", "cmstp", "msiexec",
    # Persistence
    "registry", "startup", "boot", "logon script", "dll hijack",
    "dll sideloading", "dll side-loading", "dll search order hijacking",
    "hooking", "bootkit", "implant",
    # Privilege Escalation
    "privilege escalation", "token manipulation", "uac bypass",
    "access token", "exploitation for privilege",
    # Defense Evasion
    "obfuscation", "obfuscated", "packing", "packed", "code signing",
    "masquerading", "process injection", "process hollowing",
    "timestomp", "rootkit", "steganography", "encryption", "encrypted",
    "deobfuscate", "decode", "virtualization", "sandbox evasion",
    # Credential Access
    "credential dump", "credential dumping", "credential harvest",
    "credential theft", "credential stealing", "brute force",
    "password spray", "password spraying", "password guessing",
    "keylogging", "keylogger", "input capture", "kerberoast",
    "pass the hash", "pass the ticket", "credential stuffing",
    # Discovery
    "network scanning", "port scanning", "reconnaissance",
    "system information discovery", "remote system discovery",
    # Lateral Movement
    "lateral movement", "remote desktop", "rdp", "remote service",
    "pass the hash", "internal spearphishing", "smb",
    # Collection
    "screen capture", "clipboard", "data staging", "keylogging",
    "audio capture", "video capture", "email collection",
    # Exfiltration
    "exfiltration", "exfiltrate", "data exfiltration",
    "exfiltration over c2", "exfiltration over alternative protocol",
    # Command and Control
    "command and control", "c2", "c&c",
    "dns tunneling", "domain fronting", "proxy",
    "multi-hop proxy", "web service", "dead drop resolver",
    "encrypted channel", "ingress tool transfer",
    "remote access trojan", "reverse shell",
    # Impact
    "data destruction", "data encrypted for impact",
    "disk wipe", "wiper", "defacement", "ransomware",
    # Delivery mechanisms
    "social engineering", "lure", "decoy",
    "malicious attachment", "malicious link",
    "dropper", "downloader", "loader",
    # Generic technique terms
    "exploit", "exploitation", "zero-day", "0-day",
    "man-in-the-middle", "man-in-the-browser",
    "sql injection", "cross-site scripting", "xss",
    "living off the land", "fileless",
]

# Tool 停用詞 — 太泛用、不是具體工具的詞
TOOL_STOPWORDS = {
    # OS/Platform
    "windows", "linux", "macos", "mac", "android", "ios",
    "unix", "ubuntu", "centos", "debian",
    # Vendors/Companies
    "microsoft", "google", "apple", "facebook", "twitter",
    "crowdstrike", "fireeye", "mandiant", "kaspersky",
    "symantec", "mcafee", "paloalto", "cisco", "fortinet",
    "sophos", "eset", "avast", "bitdefender", "norton",
    # Protocols/Formats
    "http", "https", "ftp", "smtp", "dns", "tcp", "udp",
    "ssl", "tls", "ssh", "rdp", "smb", "ldap", "snmp",
    "html", "xml", "json", "csv", "pdf", "dll", "exe",
    "bat", "vbs", "lnk", "rtf", "doc", "docx", "xls", "xlsx",
    "zip", "rar", "iso", "img", "vba", "javascript", "vbscript",
    # Generic malware categories (not specific tools)
    "backdoor", "malware", "trojan", "worm", "virus",
    "dropper", "downloader", "loader", "rat",
    "keylogger", "ransomware", "spyware", "adware",
    "rootkit", "bootkit", "exploit", "shellcode",
    "implant", "payload", "stager", "beacon",
    # Generic words NER frequently misclassifies
    "custom", "remote", "command", "tool", "tools",
    "framework", "module", "modules", "plugin", "plugins",
    "script", "scripts", "code", "binary", "file", "files",
    "server", "client", "agent", "service", "process",
    "email", "emails", "network", "internet", "web",
    "browser", "chrome", "firefox", "safari", "edge",
    "database", "registry", "memory", "disk", "system",
    "user", "admin", "administrator", "root",
    "encrypt", "encrypted", "decrypt", "compression",
    "fake", "malicious", "suspicious", "legitimate",
    "publicly", "named", "based", "hosted", "embedded",
    "downloaded", "installed", "executed", "deployed",
    "scheduled", "automated", "persistent",
    "credentials", "passwords", "tokens", "certificates",
    "nodes", "hashes", "strings", "data", "information",
    "attack", "campaign", "operation", "threat",
    "vulnerability", "vulnerabilities",
    "social media", "github", "telegram", "discord",
    "youtube", "linkedin", "instagram", "whatsapp",
    # Orgs/Brands commonly misclassified
    "dnc", "nato", "un", "eu", "fbi", "nsa", "cia",
    "solarwinds", "orion", "bitcoin", "cryptocurrency",
    # ATT&CK framework terms
    "mitre", "att&ck", "mitre att&ck",
    # Single characters / noise
    "pe", "ip", "c2", "c&c", "api", "url", "uri",
    "aes", "rc4", "rsa", "md5", "sha", "sha256",
    "base64", "xor",
}

# Way 停用詞
WAY_STOPWORDS = {
    "email", "emails", "e-mail", "e-mails",
    "gmail", "outlook", "yahoo",
    "download", "downloading", "downloaded",
    "install", "installing", "installed",
    "execute", "executing", "executed",
    "adding", "changing", "replacing", "shifting",
    "creating", "create", "using", "used",
    "running", "run", "open", "opening",
    "click", "clicking", "access", "accessing",
    "connect", "connecting", "connected",
    "send", "sending", "sent", "receive", "receiving",
    "upload", "uploading", "uploaded",
    "update", "updating", "updated",
    "delete", "deleting", "remove", "removing",
    "copy", "copying", "move", "moving",
    "read", "reading", "write", "writing",
    "network", "internet", "web", "online",
    "http", "https", "ftp", "tcp", "udp", "dns",
    "vpn", "tor", "proxy", "ssh", "ssl", "tls",
    "excel", "word", "pdf", "zip", "rar",
    "password", "passwords", "username",
    "multi-factor", "handshake", "opsec",
    "vulnerable", "combat", "dismissing",
    "contact", "employ",
}

# Area: demonym → country canonical map
AREA_CANONICAL = {
    "russian": "russia", "russians": "russia", "russia's": "russia",
    "ukrainian": "ukraine", "ukrainians": "ukraine", "ukraine's": "ukraine",
    "iranian": "iran", "iranians": "iran", "iran's": "iran",
    "chinese": "china", "china's": "china",
    "north korean": "north korea", "south korean": "south korea",
    "american": "united states", "americans": "united states",
    "israeli": "israel", "israelis": "israel",
    "pakistani": "pakistan", "pakistanis": "pakistan",
    "indian": "india", "indians": "india",
    "japanese": "japan", "saudi": "saudi arabia",
    "turkish": "turkey", "british": "united kingdom",
    "german": "germany", "french": "france",
    "european": "europe", "asian": "asia",
    "western": None,  # discard standalone "western"
    "eastern": None,
    "middle": None,   # "middle" without "east"
    "north": None,    # standalone fragments
    "south": None,
    "united": None,
    "zealand": None,
}


def load_attack_software_list() -> set[str]:
    if not ATTACK_SW_LIST.exists():
        logger.warning(f"ATT&CK software list not found: {ATTACK_SW_LIST}")
        return set()
    with open(ATTACK_SW_LIST) as f:
        return {line.strip().lower() for line in f if line.strip()}


def build_way_whitelist_set() -> set[str]:
    return {w.lower() for w in WAY_WHITELIST}


# ── Layer 1: 表面正規化 ──

def strip_punctuation(text: str) -> str:
    """Strip leading/trailing punctuation and whitespace."""
    return text.strip().strip(",.;:!?)(\"\u00ae\u2122\u00a9[]{}|/\\").strip()


def normalize_surface(text: str) -> str:
    """Basic surface normalization: strip punctuation, lowercase, filter short."""
    text = strip_punctuation(text)
    text = text.lower().strip()
    if len(text) < 2:
        return None
    # Filter pure symbols / numbers
    if not any(c.isalpha() for c in text):
        return None
    return text


CVE_PATTERN = re.compile(r"(CVE-\d{4}-\d{4,7})", re.IGNORECASE)


def normalize_exp(text: str) -> str:
    """Normalize exploit entities: extract CVE IDs or canonical forms."""
    m = CVE_PATTERN.search(text)
    if m:
        return m.group(1).upper()
    text = strip_punctuation(text).lower()
    if len(text) < 2:
        return None
    if not any(c.isalpha() for c in text):
        return None
    # Known canonical forms
    if "0-day" in text or "zero-day" in text or "zero day" in text:
        return "zero-day"
    # Filter bare fragments
    if text in ("cve", "cve-", "exploit", "vulnerability", "publicly"):
        return None
    return text


def normalize_area(text: str) -> str:
    """Normalize geographic entities: canonical country names."""
    text = strip_punctuation(text).lower()
    if len(text) < 2:
        return None
    if not any(c.isalpha() for c in text):
        return None
    # Check canonical map
    if text in AREA_CANONICAL:
        return AREA_CANONICAL[text]  # None = discard
    # Handle possessives
    if text.endswith("'s"):
        base = text[:-2]
        if base in AREA_CANONICAL:
            return AREA_CANONICAL[base]
        return base
    return text


# ── Layer 2: 白名單過濾 ──

def match_tool_whitelist(
    entity: str, attack_sw: set[str], fuzzy_threshold: int = 80
) -> str:
    """Check if a Tool entity matches the ATT&CK software list.

    Returns the matched name (from whitelist) or None if no match.
    Uses exact match first, then fuzzy match.
    """
    # Exact match
    if entity in attack_sw:
        return entity

    # Fuzzy match against whitelist
    best_score = 0
    best_match = None
    for sw in attack_sw:
        # Quick length filter
        if abs(len(entity) - len(sw)) > max(len(entity), len(sw)) * 0.5:
            continue
        score = fuzz.ratio(entity, sw)
        if score > best_score:
            best_score = score
            best_match = sw
    if best_score >= fuzzy_threshold:
        return best_match
    return None


def match_way_whitelist(entity: str, way_set: set[str]) -> str:
    """Check if a Way entity matches the Way keyword whitelist.

    Uses substring match: if any whitelist keyword is contained in the entity
    or the entity is contained in a whitelist keyword, it's a match.
    Returns the matching whitelist keyword.
    """
    # Exact match
    if entity in way_set:
        return entity

    # Substring match
    for kw in way_set:
        if kw in entity or entity in kw:
            return kw

    return None


# ── Main Processing ──

def normalize_report(
    data: dict,
    attack_sw: set[str],
    way_set: set[str],
) -> dict[str, list[str]]:
    """Normalize all entities in a single report's NER output."""
    raw = data.get("entities", {})
    normalized = {}

    for etype, entities in raw.items():
        clean = []
        for e in entities:
            if etype == "Tool":
                n = normalize_surface(e)
                if n is None:
                    continue
                if n in TOOL_STOPWORDS:
                    continue
                # Whitelist check
                matched = match_tool_whitelist(n, attack_sw)
                if matched is None:
                    continue
                clean.append(matched)

            elif etype == "Way":
                n = normalize_surface(e)
                if n is None:
                    continue
                if n in WAY_STOPWORDS:
                    continue
                # Whitelist check
                matched = match_way_whitelist(n, way_set)
                if matched is None:
                    continue
                clean.append(matched)

            elif etype == "Exp":
                n = normalize_exp(e)
                if n is not None:
                    clean.append(n)

            elif etype == "Area":
                n = normalize_area(e)
                if n is not None:
                    clean.append(n)

            else:  # Purp, Idus
                n = normalize_surface(e)
                if n is not None:
                    clean.append(n)

        # Deduplicate within report (preserve order)
        seen = set()
        deduped = []
        for c in clean:
            if c not in seen:
                seen.add(c)
                deduped.append(c)

        normalized[etype] = deduped

    return normalized


def process_all(org_filter=None):
    """Process all NER output files, add entities_normalized field."""
    attack_sw = load_attack_software_list()
    way_set = build_way_whitelist_set()
    logger.info(f"ATT&CK software whitelist: {len(attack_sw)} entries")
    logger.info(f"Way whitelist: {len(way_set)} keywords")

    files = []
    for org_dir in sorted(TTP_DIR.iterdir()):
        if not org_dir.is_dir() or org_dir.name.startswith("."):
            continue
        if org_filter and org_dir.name != org_filter:
            continue
        for f in sorted(org_dir.glob("*.json")):
            files.append(f)

    logger.info(f"Processing {len(files)} NER files...")

    stats_before = Counter()
    stats_after = Counter()
    all_entities_before = defaultdict(Counter)
    all_entities_after = defaultdict(Counter)

    for f in files:
        with open(f) as fh:
            data = json.load(fh)

        # Count before
        for etype, ents in data.get("entities", {}).items():
            stats_before[etype] += len(ents)
            for e in ents:
                all_entities_before[etype][e] += 1

        # Normalize
        normalized = normalize_report(data, attack_sw, way_set)

        # Count after
        for etype, ents in normalized.items():
            stats_after[etype] += len(ents)
            for e in ents:
                all_entities_after[etype][e] += 1

        # Write back
        data["entities_normalized"] = normalized
        data["entity_counts_normalized"] = {
            etype: len(ents) for etype, ents in normalized.items()
        }
        with open(f, "w") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)

    return stats_before, stats_after, all_entities_before, all_entities_after


def print_stats(stats_before, stats_after, all_before, all_after):
    """Print normalization statistics."""
    print(f"\n{'='*70}")
    print("Entity Normalization Statistics")
    print(f"{'='*70}")

    print(f"\n  {'Type':<8} {'Before':>8} {'After':>8} {'Δ':>8} {'Unique-B':>10} {'Unique-A':>10}")
    print(f"  {'-'*8} {'-'*8} {'-'*8} {'-'*8} {'-'*10} {'-'*10}")

    for etype in ["Tool", "Way", "Exp", "Purp", "Idus", "Area"]:
        b = stats_before.get(etype, 0)
        a = stats_after.get(etype, 0)
        ub = len(all_before.get(etype, {}))
        ua = len(all_after.get(etype, {}))
        pct = (a / b * 100) if b else 0
        print(
            f"  {etype:<8} {b:>8,} {a:>8,} {a-b:>+8,} {ub:>10,} {ua:>10,}"
        )

    total_b = sum(stats_before.values())
    total_a = sum(stats_after.values())
    print(f"  {'TOTAL':<8} {total_b:>8,} {total_a:>8,} {total_a-total_b:>+8,}")

    # Top entities per type (after normalization)
    for etype in ["Tool", "Way", "Exp"]:
        entities = all_after.get(etype, {})
        if not entities:
            continue
        print(f"\n  Top-20 {etype} (after normalization):")
        for name, count in Counter(entities).most_common(20):
            print(f"    {count:>4}x  {name}")


def main():
    parser = argparse.ArgumentParser(description="Normalize NER entities")
    parser.add_argument("--org", help="Process only this org")
    parser.add_argument(
        "--stats", action="store_true", help="Only print stats, don't write"
    )
    args = parser.parse_args()

    if args.stats:
        # Read existing normalized data
        stats_after = Counter()
        all_after = defaultdict(Counter)
        stats_before = Counter()
        all_before = defaultdict(Counter)

        for org_dir in sorted(TTP_DIR.iterdir()):
            if not org_dir.is_dir() or org_dir.name.startswith("."):
                continue
            for f in sorted(org_dir.glob("*.json")):
                with open(f) as fh:
                    data = json.load(fh)
                for etype, ents in data.get("entities", {}).items():
                    stats_before[etype] += len(ents)
                    for e in ents:
                        all_before[etype][e] += 1
                for etype, ents in data.get("entities_normalized", {}).items():
                    stats_after[etype] += len(ents)
                    for e in ents:
                        all_after[etype][e] += 1

        if stats_after:
            print_stats(stats_before, stats_after, all_before, all_after)
        else:
            logger.info("No normalized data found. Run without --stats first.")
        return

    stats_before, stats_after, all_before, all_after = process_all(args.org)
    print_stats(stats_before, stats_after, all_before, all_after)
    logger.info("Done. Normalized entities written to JSON files.")


if __name__ == "__main__":
    main()
