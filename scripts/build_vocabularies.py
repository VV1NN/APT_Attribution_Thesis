#!/usr/bin/env python3
"""
掃描 Master KG 建立 ordinal encoding 用的 vocabulary 與頻率表。
輸出：scripts/vocabularies.json
"""

import json
import logging
from collections import Counter
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S")
logger = logging.getLogger(__name__)

KG_JSON = Path("knowledge_graphs/master/merged_kg.json")
OUTPUT = Path("scripts/vocabularies.json")
MIN_COUNT = 2  # 出現 < 2 次歸為 OTHER


def build_vocabularies():
    logger.info(f"Loading {KG_JSON}...")
    with open(KG_JSON) as f:
        data = json.load(f)

    nodes = data["nodes"]
    logger.info(f"Scanning {len(nodes)} nodes")

    # ── 收集原始值 ──
    raw = {
        "type_tag": [], "type_extension": [], "registrar": [], "tld": [],
        "country": [], "continent": [], "as_owner": [], "rir": [],
        "threat_label": [], "threat_category": [], "resource_lang": [],
    }
    freq = {"imphash": Counter(), "jarm": Counter()}

    for node in nodes:
        ntype = node.get("type")
        attrs = node.get("attributes") or {}

        if ntype == "file":
            if attrs.get("type_tag"):
                raw["type_tag"].append(attrs["type_tag"])
            if attrs.get("type_extension"):
                raw["type_extension"].append(attrs["type_extension"])

            pe = attrs.get("pe_info") or {}
            if pe.get("imphash"):
                freq["imphash"][pe["imphash"]] += 1
            rl = pe.get("resource_langs") or {}
            if isinstance(rl, dict):
                for lang in rl:
                    raw["resource_lang"].append(lang)

            tc = attrs.get("popular_threat_classification") or {}
            if tc.get("suggested_threat_label"):
                raw["threat_label"].append(tc["suggested_threat_label"])
            cats = tc.get("popular_threat_category") or []
            if cats and isinstance(cats, list):
                for cat in cats:
                    val = cat.get("value", "") if isinstance(cat, dict) else str(cat)
                    if val:
                        raw["threat_category"].append(val)

        elif ntype == "domain":
            if attrs.get("registrar"):
                raw["registrar"].append(attrs["registrar"].strip())
            if attrs.get("tld"):
                raw["tld"].append(attrs["tld"])
            jarm = attrs.get("jarm") or ""
            if jarm and jarm.replace("0", "") != "":
                freq["jarm"][jarm] += 1

        elif ntype == "ip":
            if attrs.get("country"):
                raw["country"].append(attrs["country"])
            if attrs.get("continent"):
                raw["continent"].append(attrs["continent"])
            if attrs.get("as_owner"):
                raw["as_owner"].append(attrs["as_owner"])
            if attrs.get("regional_internet_registry"):
                raw["rir"].append(attrs["regional_internet_registry"])
            jarm = attrs.get("jarm") or ""
            if jarm and jarm.replace("0", "") != "":
                freq["jarm"][jarm] += 1

    # ── 建立 ordinal mapping ──
    vocabs = {}
    value_counts = {}  # 用於 _2 特徵（頻率維度）
    for name, values in raw.items():
        counter = Counter(values)
        valid = sorted([v for v, c in counter.items() if c >= MIN_COUNT])
        mapping = {"__OTHER__": 0}
        for i, v in enumerate(valid, 1):
            mapping[v] = i
        vocabs[name] = mapping
        value_counts[name] = dict(counter)
        logger.info(f"  {name}: {len(valid)} values (+ OTHER)")

    result = {
        "vocabs": vocabs,
        "value_counts": value_counts,
        "freq": {k: dict(v) for k, v in freq.items()},
        "min_count": MIN_COUNT,
    }

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT, "w") as f:
        json.dump(result, f, ensure_ascii=False)
    logger.info(f"Saved to {OUTPUT} ({OUTPUT.stat().st_size // 1024} KB)")
    return result


if __name__ == "__main__":
    build_vocabularies()
