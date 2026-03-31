#!/usr/bin/env python3
"""
從外部公開來源擴充 21 個 org 的 IoC 資料集。
來源：RedDrip7/APT_Digital_Weapon、mandiant/iocs、eset/malware-ioc、MalwareBazaar

用法：
    uv run python scripts/fetch_external_iocs.py                  # 全部來源
    uv run python scripts/fetch_external_iocs.py --source reddrip # 單一來源
    uv run python scripts/fetch_external_iocs.py --source bazaar --bazaar-key YOUR_KEY
    uv run python scripts/fetch_external_iocs.py --dry-run        # 只統計不寫入
"""

import argparse
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Optional

import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

# ════════════════════════════════════════════════════════════
# 21 target orgs + name mapping per source
# ════════════════════════════════════════════════════════════

TARGET_ORGS = [
    "APT-C-23", "APT-C-36", "APT1", "APT12", "APT16", "APT17", "APT18",
    "APT19", "APT28", "APT29", "APT32", "FIN7", "Gamaredon_Group",
    "Kimsuky", "Lazarus_Group", "Magic_Hound", "MuddyWater", "OilRig",
    "Sandworm_Team", "Turla", "Wizard_Spider",
]

# RedDrip7 folder name → our org name
REDDRIP_MAP = {
    "APT-C-23": "APT-C-23",
    "APT-C-36": "APT-C-36",
    "APT 1": "APT1", "APT1": "APT1",
    "APT12": "APT12", "APT 12": "APT12",
    "APT16": "APT16", "APT 16": "APT16",
    "APT17": "APT17", "APT 17": "APT17",
    "APT18": "APT18", "APT 18": "APT18",
    "APT19": "APT19", "APT 19": "APT19",
    "APT28": "APT28", "APT 28": "APT28", "Fancy Bear": "APT28", "Sofacy": "APT28",
    "APT29": "APT29", "APT 29": "APT29", "Cozy Bear": "APT29",
    "APT32": "APT32", "OceanLotus": "APT32", "Ocean Lotus": "APT32",
    "FIN7": "FIN7",
    "Gamaredon Group": "Gamaredon_Group", "Gamaredon": "Gamaredon_Group",
    "Kimsuky": "Kimsuky",
    "Lazarus Group": "Lazarus_Group", "Lazarus": "Lazarus_Group",
    "Magic Hound": "Magic_Hound", "APT35": "Magic_Hound", "Charming Kitten": "Magic_Hound",
    "MuddyWater": "MuddyWater", "Muddy Water": "MuddyWater",
    "OilRig": "OilRig", "Oil Rig": "OilRig", "APT34": "OilRig",
    "Sandworm": "Sandworm_Team", "Sandworm Team": "Sandworm_Team",
    "Turla": "Turla",
    "Wizard Spider": "Wizard_Spider",
}

# ESET folder name → our org name
ESET_MAP = {
    "aridviper": "APT-C-23",
    "blindeagle": "APT-C-36",
    "sednit": "APT28",
    "dukes": "APT29",
    "oceanlotus": "APT32", "oceanlotus-macOS": "APT32",
    "gamaredon": "Gamaredon_Group",
    "kimsuky": "Kimsuky",
    "nukesped_lazarus": "Lazarus_Group", "lazarus": "Lazarus_Group",
    "muddywater": "MuddyWater",
    "oilrig": "OilRig",
    "telebots": "Sandworm_Team", "industroyer": "Sandworm_Team",
    "industroyer2": "Sandworm_Team", "greyenergy": "Sandworm_Team",
    "exaramel": "Sandworm_Team",
    "turla": "Turla",
    "fin7": "FIN7",
    "ballisticbobcat": "Magic_Hound",
    "wizard_spider": "Wizard_Spider",
}

# Mandiant folder name → our org name
MANDIANT_MAP = {
    "APT1": "APT1",
    "APT12": "APT12",
    "APT17": "APT17",
    "APT18": "APT18",
    "APT28": "APT28",
}

# MalwareBazaar: tag/signature variants to try per org
BAZAAR_QUERIES = {
    "APT-C-23": {"tags": ["APT-C-23", "AridViper"], "sigs": ["AridViper"]},
    "APT-C-36": {"tags": ["APT-C-36", "BlindEagle"], "sigs": ["BlindEagle"]},
    "APT1": {"tags": ["APT1"], "sigs": ["APT1"]},
    "APT12": {"tags": ["APT12"], "sigs": ["APT12"]},
    "APT16": {"tags": ["APT16"], "sigs": ["APT16"]},
    "APT17": {"tags": ["APT17"], "sigs": ["APT17"]},
    "APT18": {"tags": ["APT18"], "sigs": ["APT18"]},
    "APT19": {"tags": ["APT19"], "sigs": ["APT19"]},
    "APT28": {"tags": ["APT28", "apt28", "Sofacy", "FancyBear"], "sigs": ["APT28", "Sofacy"]},
    "APT29": {"tags": ["APT29", "apt29", "CozyBear"], "sigs": ["APT29", "CobaltStrike"]},
    "APT32": {"tags": ["APT32", "OceanLotus"], "sigs": ["APT32", "OceanLotus"]},
    "FIN7": {"tags": ["FIN7", "fin7"], "sigs": ["FIN7"]},
    "Gamaredon_Group": {"tags": ["Gamaredon", "gamaredon"], "sigs": ["Gamaredon"]},
    "Kimsuky": {"tags": ["Kimsuky", "kimsuky"], "sigs": ["Kimsuky"]},
    "Lazarus_Group": {"tags": ["Lazarus", "lazarus"], "sigs": ["Lazarus"]},
    "Magic_Hound": {"tags": ["APT35", "MagicHound", "CharmingKitten"], "sigs": ["APT35", "CharmingKitten"]},
    "MuddyWater": {"tags": ["MuddyWater", "muddywater"], "sigs": ["MuddyWater"]},
    "OilRig": {"tags": ["OilRig", "APT34"], "sigs": ["OilRig", "APT34"]},
    "Sandworm_Team": {"tags": ["Sandworm", "sandworm"], "sigs": ["Sandworm"]},
    "Turla": {"tags": ["Turla", "turla"], "sigs": ["Turla"]},
    "Wizard_Spider": {"tags": ["WizardSpider", "TrickBot", "Conti"], "sigs": ["TrickBot", "Conti", "BazarLoader"]},
}

ORG_IOCS_DIR = Path("org_iocs")


# ════════════════════════════════════════════════════════════
# Helpers
# ════════════════════════════════════════════════════════════

def load_existing_iocs(org: str) -> tuple[list[dict], set[str]]:
    """載入現有 IoCs，回傳 list + 已知 value set。"""
    p = ORG_IOCS_DIR / org / "iocs.json"
    if p.exists():
        with open(p) as f:
            data = json.load(f)
        # Migrate: add dataset_sources to existing entries
        for ioc in data:
            if "dataset_sources" not in ioc:
                ioc["dataset_sources"] = ["cti_reports"]
        values = set()
        for ioc in data:
            values.add(ioc["value"].lower().strip())
        return data, values
    return [], set()


def normalize_hash(h: str) -> str:
    """清理 hash 值。"""
    return h.strip().lower()


def clone_repo(url: str, dest: str) -> str:
    """Shallow clone a git repo."""
    logger.info(f"Cloning {url} ...")
    subprocess.run(
        ["git", "clone", "--depth", "1", url, dest],
        capture_output=True, text=True, check=True,
    )
    return dest


# ════════════════════════════════════════════════════════════
# Source 1: RedDrip7/APT_Digital_Weapon
# ════════════════════════════════════════════════════════════

def fetch_reddrip(tmpdir: str) -> dict[str, list[dict]]:
    """從 RedDrip7 抓取 IoCs。回傳 {org: [ioc_entries]}。"""
    repo_url = "https://github.com/RedDrip7/APT_Digital_Weapon.git"
    repo_dir = os.path.join(tmpdir, "APT_Digital_Weapon")
    clone_repo(repo_url, repo_dir)

    results = defaultdict(list)
    md5_re = re.compile(r"\[([a-fA-F0-9]{32})\]\(https://www\.virustotal\.com")

    for folder_name in os.listdir(repo_dir):
        folder_path = os.path.join(repo_dir, folder_name)
        if not os.path.isdir(folder_path):
            continue

        # Check if this folder maps to one of our orgs
        org = REDDRIP_MAP.get(folder_name)
        if org is None:
            # Try alias matching from README.md
            readme_path = os.path.join(folder_path, "README.md")
            if os.path.exists(readme_path):
                with open(readme_path, encoding="utf-8", errors="ignore") as f:
                    readme_text = f.read()
                # Check if any of our org names appear in aliases
                for alias, mapped_org in REDDRIP_MAP.items():
                    if alias.lower() in readme_text.lower():
                        org = mapped_org
                        break
        if org is None:
            continue

        # Parse hash file
        hash_files = [f for f in os.listdir(folder_path) if f.endswith("_hash.md")]
        for hf in hash_files:
            with open(os.path.join(folder_path, hf), encoding="utf-8", errors="ignore") as f:
                content = f.read()
            for match in md5_re.finditer(content):
                md5 = normalize_hash(match.group(1))
                results[org].append({
                    "type": "md5",
                    "value": md5,
                    "sources": [f"https://github.com/RedDrip7/APT_Digital_Weapon/tree/master/{folder_name}"],
                    "dataset_sources": ["reddrip7"],
                })

    for org in results:
        logger.info(f"  RedDrip7 → {org}: {len(results[org])} md5 hashes")
    return dict(results)


# ════════════════════════════════════════════════════════════
# Source 2: mandiant/iocs
# ════════════════════════════════════════════════════════════

def fetch_mandiant(tmpdir: str) -> dict[str, list[dict]]:
    """從 mandiant/iocs 抓取 IoCs。"""
    repo_url = "https://github.com/mandiant/iocs.git"
    repo_dir = os.path.join(tmpdir, "mandiant_iocs")
    clone_repo(repo_url, repo_dir)

    results = defaultdict(list)
    ns = {"ioc": "http://schemas.mandiant.com/2010/ioc",
          "iocterms": "http://schemas.mandiant.com/2010/ioc/TR/"}

    for folder_name in os.listdir(repo_dir):
        org = MANDIANT_MAP.get(folder_name)
        if org is None:
            continue

        folder_path = os.path.join(repo_dir, folder_name)
        if not os.path.isdir(folder_path):
            continue

        for fname in os.listdir(folder_path):
            if not fname.endswith(".ioc"):
                continue
            fpath = os.path.join(folder_path, fname)
            try:
                import xml.etree.ElementTree as ET
                tree = ET.parse(fpath)
                root = tree.getroot()
            except Exception as e:
                logger.warning(f"  Failed to parse {fpath}: {e}")
                continue

            source_url = f"https://github.com/mandiant/iocs/tree/master/{folder_name}/{fname}"

            for item in root.iter():
                if item.tag.endswith("IndicatorItem"):
                    ctx = item.find("{http://schemas.mandiant.com/2010/ioc}Context")
                    content = item.find("{http://schemas.mandiant.com/2010/ioc}Content")
                    if ctx is None or content is None or not content.text:
                        continue
                    search = ctx.get("search", "")
                    value = content.text.strip()

                    if "Md5sum" in search and re.match(r"^[a-fA-F0-9]{32}$", value):
                        results[org].append({
                            "type": "md5",
                            "value": normalize_hash(value),
                            "sources": [source_url],
                            "dataset_sources": ["mandiant"],
                        })
                    elif "Sha256sum" in search and re.match(r"^[a-fA-F0-9]{64}$", value):
                        results[org].append({
                            "type": "sha256",
                            "value": normalize_hash(value),
                            "sources": [source_url],
                            "dataset_sources": ["mandiant"],
                        })
                    elif ("DnsEntryItem/Host" in search or "DnsEntryItem/RecordName" in search):
                        if re.match(r"^[a-zA-Z0-9][-a-zA-Z0-9.]+\.[a-zA-Z]{2,}$", value):
                            results[org].append({
                                "type": "domain",
                                "value": value.lower(),
                                "sources": [source_url],
                                "dataset_sources": ["mandiant"],
                            })
                    elif "remoteIP" in search:
                        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", value):
                            results[org].append({
                                "type": "ipv4",
                                "value": value,
                                "sources": [source_url],
                                "dataset_sources": ["mandiant"],
                            })

    for org in results:
        logger.info(f"  Mandiant → {org}: {len(results[org])} IoCs")
    return dict(results)


# ════════════════════════════════════════════════════════════
# Source 3: eset/malware-ioc
# ════════════════════════════════════════════════════════════

def fetch_eset(tmpdir: str) -> dict[str, list[dict]]:
    """從 eset/malware-ioc 抓取 IoCs。"""
    repo_url = "https://github.com/eset/malware-ioc.git"
    repo_dir = os.path.join(tmpdir, "eset_malware_ioc")
    clone_repo(repo_url, repo_dir)

    results = defaultdict(list)

    for folder_name in os.listdir(repo_dir):
        org = ESET_MAP.get(folder_name.lower())
        if org is None:
            continue

        folder_path = os.path.join(repo_dir, folder_name)
        if not os.path.isdir(folder_path):
            continue

        source_url = f"https://github.com/eset/malware-ioc/tree/master/{folder_name}"

        # Format A: plain hash files
        for root_dir, dirs, files in os.walk(folder_path):
            for fname in files:
                fpath = os.path.join(root_dir, fname)

                if fname.endswith((".sha256", ".sha256.txt")):
                    with open(fpath, encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            h = line.strip().split()[0] if line.strip() else ""
                            if re.match(r"^[a-fA-F0-9]{64}$", h):
                                results[org].append({
                                    "type": "sha256",
                                    "value": normalize_hash(h),
                                    "sources": [source_url],
                                    "dataset_sources": ["eset"],
                                })

                elif fname.endswith((".sha1", ".sha1.txt")):
                    with open(fpath, encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            h = line.strip().split()[0] if line.strip() else ""
                            if re.match(r"^[a-fA-F0-9]{40}$", h):
                                results[org].append({
                                    "type": "sha1",
                                    "value": normalize_hash(h),
                                    "sources": [source_url],
                                    "dataset_sources": ["eset"],
                                })

                elif fname.endswith((".md5", ".md5.txt")):
                    with open(fpath, encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            h = line.strip().split()[0] if line.strip() else ""
                            if re.match(r"^[a-fA-F0-9]{32}$", h):
                                results[org].append({
                                    "type": "md5",
                                    "value": normalize_hash(h),
                                    "sources": [source_url],
                                    "dataset_sources": ["eset"],
                                })

                # Format B: MISP JSON
                elif fname.endswith(".json") and "misp" in fname.lower():
                    _parse_eset_misp(fpath, org, source_url, results)

                elif fname.endswith(".json") and fname != "package.json":
                    # Try MISP format for any JSON
                    _parse_eset_misp(fpath, org, source_url, results)

        # Format C: AsciiDoc (domain/IP extraction)
        for root_dir, dirs, files in os.walk(folder_path):
            for fname in files:
                if fname.endswith((".adoc", ".asciidoc")):
                    fpath = os.path.join(root_dir, fname)
                    _parse_eset_adoc(fpath, org, source_url, results)

    for org in results:
        logger.info(f"  ESET → {org}: {len(results[org])} IoCs")
    return dict(results)


def _parse_eset_misp(fpath: str, org: str, source_url: str, results: dict):
    """解析 ESET 的 MISP JSON 格式。"""
    try:
        with open(fpath, encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return

    events = data.get("response", [data]) if isinstance(data, dict) else data
    if not isinstance(events, list):
        events = [events]

    for evt in events:
        if isinstance(evt, dict):
            e = evt.get("Event", evt)
        else:
            continue

        attrs = e.get("Attribute", [])
        # Also grab attributes from Objects
        for obj in e.get("Object", []):
            if isinstance(obj, dict):
                attrs.extend(obj.get("Attribute", []))

        for attr in attrs:
            if not isinstance(attr, dict):
                continue
            t = attr.get("type", "")
            v = str(attr.get("value", "")).strip()
            if not v:
                continue

            entry = None
            if t in ("sha256",) and re.match(r"^[a-fA-F0-9]{64}$", v):
                entry = {"type": "sha256", "value": normalize_hash(v)}
            elif t in ("sha1",) and re.match(r"^[a-fA-F0-9]{40}$", v):
                entry = {"type": "sha1", "value": normalize_hash(v)}
            elif t in ("md5",) and re.match(r"^[a-fA-F0-9]{32}$", v):
                entry = {"type": "md5", "value": normalize_hash(v)}
            elif t in ("domain", "hostname"):
                v_clean = v.replace("[.]", ".").replace("[:]", ":")
                if re.match(r"^[a-zA-Z0-9][-a-zA-Z0-9.]+\.[a-zA-Z]{2,}$", v_clean):
                    entry = {"type": "domain", "value": v_clean.lower()}
            elif t in ("ip-dst", "ip-src"):
                v_clean = v.replace("[.]", ".")
                if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", v_clean):
                    entry = {"type": "ipv4", "value": v_clean}
            elif t in ("url",):
                v_clean = v.replace("[.]", ".").replace("[:]", ":").replace("hxxp", "http")
                entry = {"type": "url", "value": v_clean}
            elif "|" in t and "|" in v:
                # Composite like filename|sha256
                parts = v.split("|")
                hash_part = parts[-1].strip()
                if re.match(r"^[a-fA-F0-9]{64}$", hash_part):
                    entry = {"type": "sha256", "value": normalize_hash(hash_part)}
                elif re.match(r"^[a-fA-F0-9]{32}$", hash_part):
                    entry = {"type": "md5", "value": normalize_hash(hash_part)}

            if entry:
                entry["sources"] = [source_url]
                entry["dataset_sources"] = ["eset"]
                results[org].append(entry)


def _parse_eset_adoc(fpath: str, org: str, source_url: str, results: dict):
    """從 AsciiDoc 中提取 domain/IP/hash。"""
    try:
        with open(fpath, encoding="utf-8", errors="ignore") as f:
            text = f.read()
    except Exception:
        return

    # SHA-256
    for h in re.findall(r"`([0-9A-Fa-f]{64})`", text):
        results[org].append({
            "type": "sha256", "value": normalize_hash(h),
            "sources": [source_url], "dataset_sources": ["eset"],
        })

    # SHA-1
    for h in re.findall(r"`([0-9A-Fa-f]{40})`", text):
        results[org].append({
            "type": "sha1", "value": normalize_hash(h),
            "sources": [source_url], "dataset_sources": ["eset"],
        })

    # Defanged domains
    for d in re.findall(r"`([a-zA-Z0-9][-a-zA-Z0-9.]*\[\.\][a-zA-Z0-9][-a-zA-Z0-9.]*)`", text):
        clean = d.replace("[.]", ".")
        if re.match(r"^[a-zA-Z0-9][-a-zA-Z0-9.]+\.[a-zA-Z]{2,}$", clean):
            results[org].append({
                "type": "domain", "value": clean.lower(),
                "sources": [source_url], "dataset_sources": ["eset"],
            })

    # Defanged IPs
    for ip in re.findall(r"`(\d{1,3}\.\d{1,3}\.\d{1,3}\[\.\]\d{1,3})`", text):
        clean = ip.replace("[.]", ".")
        results[org].append({
            "type": "ipv4", "value": clean,
            "sources": [source_url], "dataset_sources": ["eset"],
        })

    # Plain IPs in backticks
    for ip in re.findall(r"`(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`", text):
        results[org].append({
            "type": "ipv4", "value": ip,
            "sources": [source_url], "dataset_sources": ["eset"],
        })


# ════════════════════════════════════════════════════════════
# Source 4: MalwareBazaar API
# ════════════════════════════════════════════════════════════

def fetch_bazaar(api_key: str) -> dict[str, list[dict]]:
    """從 MalwareBazaar API 抓取 IoCs（需要 API key）。"""
    base_url = "https://mb-api.abuse.ch/api/v1/"
    headers = {"Auth-Key": api_key}
    results = defaultdict(list)

    for org, queries in BAZAAR_QUERIES.items():
        seen_sha256 = set()

        # Query by tags
        for tag in queries["tags"]:
            try:
                resp = requests.post(
                    base_url, headers=headers,
                    data={"query": "get_taginfo", "tag": tag, "limit": 1000},
                    timeout=30,
                )
                data = resp.json()
                if data.get("query_status") == "ok" and data.get("data"):
                    for sample in data["data"]:
                        sha256 = sample.get("sha256_hash", "").lower()
                        if sha256 and sha256 not in seen_sha256:
                            seen_sha256.add(sha256)
                            entry = {"type": "sha256", "value": sha256,
                                     "sources": [f"https://bazaar.abuse.ch/browse/tag/{tag}/"],
                                     "dataset_sources": ["malwarebazaar"]}
                            # Also add md5/sha1 if available
                            results[org].append(entry)
                            md5 = sample.get("md5_hash", "").lower()
                            if md5:
                                results[org].append({
                                    "type": "md5", "value": md5,
                                    "sources": [f"https://bazaar.abuse.ch/browse/tag/{tag}/"],
                                    "dataset_sources": ["malwarebazaar"],
                                })
                            sha1 = sample.get("sha1_hash", "").lower()
                            if sha1:
                                results[org].append({
                                    "type": "sha1", "value": sha1,
                                    "sources": [f"https://bazaar.abuse.ch/browse/tag/{tag}/"],
                                    "dataset_sources": ["malwarebazaar"],
                                })
                time.sleep(0.5)
            except Exception as e:
                logger.warning(f"  Bazaar tag query failed ({tag}): {e}")

        # Query by signatures
        for sig in queries["sigs"]:
            try:
                resp = requests.post(
                    base_url, headers=headers,
                    data={"query": "get_siginfo", "signature": sig, "limit": 1000},
                    timeout=30,
                )
                data = resp.json()
                if data.get("query_status") == "ok" and data.get("data"):
                    for sample in data["data"]:
                        sha256 = sample.get("sha256_hash", "").lower()
                        if sha256 and sha256 not in seen_sha256:
                            seen_sha256.add(sha256)
                            results[org].append({
                                "type": "sha256", "value": sha256,
                                "sources": [f"https://bazaar.abuse.ch/browse/signature/{sig}/"],
                                "dataset_sources": ["malwarebazaar"],
                            })
                            md5 = sample.get("md5_hash", "").lower()
                            if md5:
                                results[org].append({
                                    "type": "md5", "value": md5,
                                    "sources": [f"https://bazaar.abuse.ch/browse/signature/{sig}/"],
                                    "dataset_sources": ["malwarebazaar"],
                                })
                            sha1 = sample.get("sha1_hash", "").lower()
                            if sha1:
                                results[org].append({
                                    "type": "sha1", "value": sha1,
                                    "sources": [f"https://bazaar.abuse.ch/browse/signature/{sig}/"],
                                    "dataset_sources": ["malwarebazaar"],
                                })
                time.sleep(0.5)
            except Exception as e:
                logger.warning(f"  Bazaar sig query failed ({sig}): {e}")

        if results[org]:
            logger.info(f"  Bazaar → {org}: {len(results[org])} IoCs ({len(seen_sha256)} unique samples)")

    return dict(results)


# ════════════════════════════════════════════════════════════
# Merge & Dedup
# ════════════════════════════════════════════════════════════

def merge_iocs(org: str, new_iocs: list[dict], dry_run: bool = False) -> dict:
    """合併新 IoCs 到現有 org_iocs/{org}/iocs.json，回傳統計。"""
    existing, existing_values = load_existing_iocs(org)
    stats = {"org": org, "existing": len(existing), "new_total": len(new_iocs),
             "new_unique": 0, "duplicates": 0, "by_source": Counter(), "by_type": Counter()}

    for ioc in new_iocs:
        val = ioc["value"].lower().strip()
        src = ioc["dataset_sources"][0] if ioc.get("dataset_sources") else "unknown"

        if val in existing_values:
            stats["duplicates"] += 1
            # Update dataset_sources on existing entry if from new source
            for ex in existing:
                if ex["value"].lower().strip() == val:
                    if src not in ex.get("dataset_sources", []):
                        ex.setdefault("dataset_sources", ["cti_reports"]).append(src)
                    # Merge source URLs
                    for s in ioc.get("sources", []):
                        if s not in ex.get("sources", []):
                            ex["sources"].append(s)
                    break
        else:
            existing_values.add(val)
            existing.append(ioc)
            stats["new_unique"] += 1
            stats["by_source"][src] += 1
            stats["by_type"][ioc["type"]] += 1

    stats["final_total"] = len(existing)

    if not dry_run and stats["new_unique"] > 0:
        out_path = ORG_IOCS_DIR / org / "iocs.json"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(existing, f, ensure_ascii=False, indent=2)
        logger.info(f"  ✅ {org}: wrote {stats['final_total']} IoCs (+{stats['new_unique']} new)")

    return stats


# ════════════════════════════════════════════════════════════
# Main
# ════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="擴充 21 org 的 IoC 資料集")
    parser.add_argument("--source", choices=["reddrip", "mandiant", "eset", "bazaar", "all"],
                        default="all", help="指定來源 (default: all)")
    parser.add_argument("--bazaar-key", help="MalwareBazaar API key (from https://auth.abuse.ch/)")
    parser.add_argument("--dry-run", action="store_true", help="只統計不寫入")
    args = parser.parse_args()

    sources_to_run = []
    if args.source == "all":
        sources_to_run = ["reddrip", "mandiant", "eset"]
        if args.bazaar_key:
            sources_to_run.append("bazaar")
        else:
            logger.info("跳過 MalwareBazaar（需要 --bazaar-key）")
    else:
        sources_to_run = [args.source]

    # Collect all new IoCs per org
    all_new: dict[str, list[dict]] = defaultdict(list)

    tmpdir = tempfile.mkdtemp(prefix="ioc_fetch_")
    logger.info(f"Temp dir: {tmpdir}")

    try:
        if "reddrip" in sources_to_run:
            logger.info("=" * 60)
            logger.info("Fetching from RedDrip7/APT_Digital_Weapon ...")
            for org, iocs in fetch_reddrip(tmpdir).items():
                all_new[org].extend(iocs)

        if "mandiant" in sources_to_run:
            logger.info("=" * 60)
            logger.info("Fetching from mandiant/iocs ...")
            for org, iocs in fetch_mandiant(tmpdir).items():
                all_new[org].extend(iocs)

        if "eset" in sources_to_run:
            logger.info("=" * 60)
            logger.info("Fetching from eset/malware-ioc ...")
            for org, iocs in fetch_eset(tmpdir).items():
                all_new[org].extend(iocs)

        if "bazaar" in sources_to_run:
            if not args.bazaar_key:
                logger.error("MalwareBazaar 需要 API key: --bazaar-key YOUR_KEY")
            else:
                logger.info("=" * 60)
                logger.info("Fetching from MalwareBazaar API ...")
                for org, iocs in fetch_bazaar(args.bazaar_key).items():
                    all_new[org].extend(iocs)

    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    # Merge per org
    logger.info("=" * 60)
    logger.info("Merging IoCs ...")
    all_stats = []
    for org in TARGET_ORGS:
        new_iocs = all_new.get(org, [])
        stats = merge_iocs(org, new_iocs, dry_run=args.dry_run)
        all_stats.append(stats)

    # Print summary report
    logger.info("=" * 60)
    logger.info("SUMMARY REPORT")
    logger.info("=" * 60)

    header = "{:<20} {:>6} {:>6} {:>5} {:>6} {:>8}".format(
        "Org", "Before", "New", "Dup", "After", "Sources")
    logger.info(header)
    logger.info("-" * 60)

    total_before = total_new = total_after = 0
    for s in all_stats:
        src_str = ", ".join(f"{k}:{v}" for k, v in sorted(s["by_source"].items()))
        before = s["existing"]
        logger.info("{:<20} {:>6} {:>6} {:>5} {:>6} {:>8}".format(
            s["org"], before, s["new_unique"],
            s["duplicates"], s["final_total"], src_str or "-"))
        total_before += before
        total_new += s["new_unique"]
        total_after += s["final_total"]

    logger.info("-" * 60)
    logger.info(f"Total: {total_before} → {total_after} (+{total_new} new IoCs)")

    if args.dry_run:
        logger.info("(DRY RUN — 未寫入任何檔案)")

    # Save report JSON
    report_path = Path("scripts/external_iocs_report.json")
    report = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "sources_used": sources_to_run,
        "dry_run": args.dry_run,
        "per_org": [{
            "org": s["org"],
            "before": s["existing"],
            "new_unique": s["new_unique"],
            "duplicates": s["duplicates"],
            "after": s["final_total"],
            "by_source": dict(s["by_source"]),
            "by_type": dict(s["by_type"]),
        } for s in all_stats],
        "total_before": total_before,
        "total_new": total_new,
        "total_after": total_after,
    }
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    logger.info(f"Report saved: {report_path}")


if __name__ == "__main__":
    main()
