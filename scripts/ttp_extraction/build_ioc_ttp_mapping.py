#!/usr/bin/env python3
"""
Phase 2: IoC-Report-TTP Mapping。

建立每個 IoC 的 TTP profile：
  IoC node_id → has_ioc edge 的 source_reports URLs → sha1(url)[:10] → NER JSON → entities_normalized

輸出：scripts/ttp_extraction/ioc_ttp_mapping.json
"""

import hashlib
import json
import logging
from collections import defaultdict
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

KG_JSON = Path("knowledge_graphs/master/merged_kg.json")
TTP_DIR = Path("scripts/ttp_extraction")
OUTPUT = TTP_DIR / "ioc_ttp_mapping.json"


def url_to_ner_hash(url):
    return hashlib.sha1(url.encode()).hexdigest()[:10]


def build_ner_index():
    """Build mapping: hash_suffix → NER output data (with entities_normalized)."""
    index = {}
    for org_dir in sorted(TTP_DIR.iterdir()):
        if not org_dir.is_dir() or org_dir.name.startswith("."):
            continue
        for f in sorted(org_dir.glob("*.json")):
            stem = f.stem
            # Extract hash suffix (last 10 chars after last underscore)
            parts = stem.rsplit("_", 1)
            if len(parts) == 2 and len(parts[1]) == 10:
                h = parts[1]
            else:
                continue
            with open(f) as fh:
                data = json.load(fh)
            if "entities_normalized" not in data:
                logger.warning(f"No entities_normalized in {f} — run normalize_entities.py first")
                continue
            index[h] = data
    logger.info(f"NER index: {len(index)} files")
    return index


def build_ioc_report_mapping():
    """From KG JSON, extract IoC → source_reports mapping."""
    logger.info("Loading KG JSON...")
    with open(KG_JSON) as f:
        kg = json.load(f)

    # Also get node_orgs for org labels
    node_orgs = defaultdict(set)
    for e in kg["edges"]:
        if e.get("relationship") == "has_ioc":
            org = e.get("org", "")
            tgt = e["target"]
            if org:
                node_orgs[tgt].add(org)

    # IoC → reports
    ioc_reports = {}
    for e in kg["edges"]:
        if e.get("relationship") != "has_ioc":
            continue
        tgt = e["target"]
        reports = (e.get("attributes") or {}).get("source_reports", [])
        if reports:
            if tgt in ioc_reports:
                ioc_reports[tgt] = sorted(set(ioc_reports[tgt]) | set(reports))
            else:
                ioc_reports[tgt] = sorted(reports)

    logger.info(f"IoCs with source_reports: {len(ioc_reports)}")
    return ioc_reports, node_orgs


def main():
    ner_index = build_ner_index()
    ioc_reports, node_orgs = build_ioc_report_mapping()

    mapping = {}
    n_matched = 0
    n_no_ner = 0
    n_empty_ttp = 0
    n_multi_report = 0

    for ioc_id, reports in ioc_reports.items():
        # Skip apt_ nodes and multi-org IoCs
        if ioc_id.startswith("apt_"):
            continue
        orgs = node_orgs.get(ioc_id, set())
        if len(orgs) != 1:
            continue

        org = list(orgs)[0]

        # Collect TTP from all reports
        all_entities = defaultdict(set)
        matched_reports = []

        for url in reports:
            h = url_to_ner_hash(url)
            if h in ner_index:
                ner = ner_index[h]
                for etype, ents in ner.get("entities_normalized", {}).items():
                    all_entities[etype].update(ents)
                matched_reports.append(url)

        if not matched_reports:
            n_no_ner += 1
            continue

        if len(reports) > 1:
            n_multi_report += 1

        # Convert sets to sorted lists
        entities_dict = {
            etype: sorted(ents) for etype, ents in all_entities.items() if ents
        }

        if not entities_dict:
            n_empty_ttp += 1
            continue

        n_matched += 1
        mapping[ioc_id] = {
            "reports": matched_reports,
            "entities_normalized": entities_dict,
            "entity_counts": {
                etype: len(ents) for etype, ents in entities_dict.items()
            },
            "org": org,
        }

    logger.info(f"Results:")
    logger.info(f"  Matched IoCs (with TTP): {n_matched}")
    logger.info(f"  No NER output found: {n_no_ner}")
    logger.info(f"  Empty TTP after normalization: {n_empty_ttp}")
    logger.info(f"  Multi-report IoCs: {n_multi_report}")

    # Save
    with open(OUTPUT, "w") as f:
        json.dump(mapping, f, indent=2, ensure_ascii=False)
    logger.info(f"Saved to {OUTPUT} ({len(mapping):,} IoCs)")

    # Per-org stats
    org_counts = defaultdict(int)
    for v in mapping.values():
        org_counts[v["org"]] += 1

    print(f"\n{'='*50}")
    print("IoC-TTP Mapping Per-Org Coverage")
    print(f"{'='*50}")
    print(f"  {'Org':<20} {'IoCs with TTP':>14}")
    print(f"  {'-'*20} {'-'*14}")
    for org in sorted(org_counts.keys()):
        print(f"  {org:<20} {org_counts[org]:>14,}")
    print(f"  {'TOTAL':<20} {sum(org_counts.values()):>14,}")

    # Entity type coverage
    type_counts = defaultdict(int)
    for v in mapping.values():
        for etype in v["entities_normalized"]:
            type_counts[etype] += 1

    print(f"\n  Entity type coverage (IoCs with ≥1 entity):")
    for etype in ["Tool", "Way", "Exp", "Purp", "Idus", "Area"]:
        cnt = type_counts.get(etype, 0)
        pct = cnt / len(mapping) * 100 if mapping else 0
        print(f"    {etype:<8} {cnt:>6,} / {len(mapping):,} ({pct:.1f}%)")


if __name__ == "__main__":
    main()
