"""
統計所有已建立知識圖譜中，各類型 IoC 節點的 metadata 欄位分布。

輸出：
  1. 每種節點類型有哪些 attributes 欄位
  2. 每個欄位的出現次數 / 出現率
  3. 欄位值的範例（前 3 個不重複值）

Usage:
    uv run python scripts/stats_metadata_fields.py
    uv run python scripts/stats_metadata_fields.py --org APT28
"""

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path


def load_kg(path: Path) -> dict:
    with open(path) as f:
        return json.load(f)


def collect_stats(kg_dir: Path, org_filter: list[str] | None = None):
    # {node_type: {field_name: count}}
    field_counts: dict[str, Counter] = defaultdict(Counter)
    # {node_type: total_node_count}
    type_counts: Counter = Counter()
    # {node_type: {field_name: [sample_values]}}
    field_samples: dict[str, dict[str, list]] = defaultdict(lambda: defaultdict(list))
    # {node_type: {field_name: {sub_field: count}}} for nested dicts
    nested_fields: dict[str, dict[str, Counter]] = defaultdict(lambda: defaultdict(Counter))

    orgs_loaded = []

    for org_path in sorted(kg_dir.iterdir()):
        if not org_path.is_dir():
            continue
        org_name = org_path.name
        if org_filter and org_name not in org_filter:
            continue

        # Find the KG JSON (org_name.json or org_name_knowledge_graph.json)
        kg_file = org_path / f"{org_name}.json"
        if not kg_file.exists():
            kg_file = org_path / f"{org_name}_knowledge_graph.json"
        if not kg_file.exists():
            continue

        kg = load_kg(kg_file)
        orgs_loaded.append(org_name)

        for node in kg.get("nodes", []):
            ntype = node.get("type", "unknown")
            attrs = node.get("attributes", {})
            type_counts[ntype] += 1

            for key, val in attrs.items():
                field_counts[ntype][key] += 1

                # Collect sample values (up to 3 unique)
                samples = field_samples[ntype][key]
                if len(samples) < 3:
                    sample_val = _summarize_value(val)
                    if sample_val not in samples:
                        samples.append(sample_val)

                # Track sub-fields for nested dicts
                if isinstance(val, dict):
                    for sub_key in val:
                        nested_fields[ntype][key][sub_key] += 1

    return orgs_loaded, type_counts, field_counts, field_samples, nested_fields


def _summarize_value(val) -> str:
    if val is None:
        return "null"
    if isinstance(val, bool):
        return str(val).lower()
    if isinstance(val, (int, float)):
        return str(val)
    if isinstance(val, str):
        if len(val) > 60:
            return val[:57] + "..."
        return val
    if isinstance(val, list):
        return f"list[{len(val)}]"
    if isinstance(val, dict):
        return f"dict{{{', '.join(list(val.keys())[:3])}{'...' if len(val) > 3 else ''}}}"
    return str(val)[:60]


def print_report(orgs, type_counts, field_counts, field_samples, nested_fields):
    print("=" * 70)
    print(f"知識圖譜 IoC Metadata 欄位統計")
    print(f"涵蓋組織：{len(orgs)} 個 — {', '.join(orgs)}")
    total_nodes = sum(type_counts.values())
    print(f"總節點數：{total_nodes:,}")
    print("=" * 70)

    for ntype in ["apt", "file", "domain", "ip", "email"]:
        if ntype not in type_counts:
            continue
        total = type_counts[ntype]
        fields = field_counts[ntype]

        print(f"\n{'─' * 70}")
        print(f"  節點類型: {ntype}  （共 {total:,} 個）")
        print(f"{'─' * 70}")
        print(f"  {'欄位名稱':<35} {'出現次數':>8}  {'覆蓋率':>7}  {'範例值'}")
        print(f"  {'─' * 33}  {'─' * 8}  {'─' * 7}  {'─' * 30}")

        for field, count in fields.most_common():
            pct = count / total * 100
            samples = field_samples[ntype].get(field, [])
            sample_str = " | ".join(samples)
            if len(sample_str) > 50:
                sample_str = sample_str[:47] + "..."
            print(f"  {field:<35} {count:>8,}  {pct:>6.1f}%  {sample_str}")

            # Show sub-fields for nested dicts
            if ntype in nested_fields and field in nested_fields[ntype]:
                sub_counts = nested_fields[ntype][field]
                for sub_field, sub_count in sub_counts.most_common():
                    sub_pct = sub_count / total * 100
                    print(f"    └─ .{sub_field:<31} {sub_count:>8,}  {sub_pct:>6.1f}%")

    # Summary: fields with low coverage (potential gaps)
    print(f"\n{'=' * 70}")
    print("低覆蓋率欄位（< 50%）：")
    print(f"{'=' * 70}")
    for ntype in ["file", "domain", "ip"]:
        if ntype not in type_counts:
            continue
        total = type_counts[ntype]
        low = [(f, c) for f, c in field_counts[ntype].most_common() if c / total < 0.5]
        if low:
            print(f"\n  [{ntype}]")
            for field, count in low:
                pct = count / total * 100
                print(f"    {field:<35} {pct:>6.1f}%")


def main():
    parser = argparse.ArgumentParser(description="統計知識圖譜 IoC metadata 欄位分布")
    parser.add_argument("--org", type=str, help="指定單一組織（預設：全部）")
    parser.add_argument("--kg-dir", type=str, default="knowledge_graphs",
                        help="知識圖譜目錄（預設：knowledge_graphs）")
    args = parser.parse_args()

    kg_dir = Path(args.kg_dir)
    org_filter = [args.org] if args.org else None

    orgs, type_counts, field_counts, field_samples, nested_fields = collect_stats(kg_dir, org_filter)

    if not orgs:
        print("找不到任何知識圖譜 JSON 檔案。")
        return

    print_report(orgs, type_counts, field_counts, field_samples, nested_fields)


if __name__ == "__main__":
    main()
