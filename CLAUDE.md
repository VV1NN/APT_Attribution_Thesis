# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

APT (Advanced Persistent Threat) knowledge graph construction pipeline for a master's thesis. The system extracts IoCs (Indicators of Compromise) from CTI reports, enriches them via VirusTotal API, builds two-layer knowledge graphs per APT group, and merges them into a unified queryable database.

## Setup & Common Commands

**Package manager:** `uv` (Python 3.12, specified in `.python-version`)

```bash
uv sync                              # Install/update dependencies
```

**Pipeline scripts (all run via `uv run python`):**

```bash
# IoC cleaning
uv run python ioc_clean_code/clean_iocs_v2.py

# VT metadata enrichment
uv run python scripts/fetch_vt_metadata.py --org APT18

# VT relationship discovery
uv run python scripts/fetch_vt_relationships.py --org APT18

# Build knowledge graph (Phase 1 + 2)
uv run python scripts/build_knowledge_graph.py --org APT18
uv run python scripts/build_knowledge_graph.py --org APT18 --skip-query    # skip VT API calls
uv run python scripts/build_knowledge_graph.py --org APT18 --visualize     # generate PNG

# Merge all org KGs into master
uv run python scripts/merge_knowledge_graphs.py
uv run python scripts/merge_knowledge_graphs.py --orgs APT18,APT19 --visualize

# Validation
uv run python scripts/run_validation.py
```

## Data Pipeline Flow

```
org_iocs/ (raw CTI extracts)
  → org_iocs_cleaned/ (normalized, deduplicated, defanged)
  → VT_results/ (VT Details API cache)
  → vt_relationships/ (VT Relationship API cache)
  → knowledge_graphs/{org}/ (per-org KG JSON + PNG)
  → knowledge_graphs/master/ (merged KG JSON + SQLite DB + PNG)
```

## Architecture

### Two-Layer Knowledge Graph
- **Layer 1:** `apt --has_ioc--> file/domain/ip/email` (from CTI reports)
- **Layer 2:** VT-discovered relationships: `contacted_ip`, `contacted_domain`, `dropped_file`, `resolves_to`

### Key Scripts
- `scripts/build_knowledge_graph.py` — Core KG builder. Phase 1 queries VT Details API for full metadata (PE info, WHOIS, DNS, ASN). Phase 2 loads VT relationships, discovers third-layer nodes, queries their VT Details, and expands the graph. Edge attributes include: `resolution_date`, `malicious`/`undetected` counts, `last_analysis_date`, `type_tag`, `type_description`, `meaningful_name`. Uses NetworkX internally.
- `scripts/merge_knowledge_graphs.py` — Merges per-org KGs. Same-ID nodes merge (numeric fields: latest wins; lists: union). Outputs JSON + SQLite with `nodes`, `edges`, `node_orgs` tables.
- `scripts/fetch_vt_relationships.py` — Fetches VT relationship data with global dedup cache in `vt_relationships/.cache/`.
- `ioc_clean_code/clean_iocs_v2.py` — Normalization: cross-hash merging, URL-IP collapse, defang restoration, eTLD blacklist (~50 domains), DDNS whitelist.

### Node Types & IDs
- `apt` (name), `file` (`file_{sha256}`), `domain` (`domain_{name}`), `ip` (`ip_{addr}`), `email` (`email_{addr}`)

## API Constraints

- **VirusTotal academic plan:** 20,000 req/min, 20,000 lookups/day, 620,000 lookups/month
- Rate limiting: `RATE_LIMIT_SEC = 0.1` (in `build_knowledge_graph.py`), `requests_per_min = 600` (in `fetch_vt_relationships.py`)
- 429 retry with exponential backoff (max 3 attempts)
- API key loaded from `.env` (`VT_API_KEY`)

## Important Conventions

- Documentation and some comments are in Chinese (Traditional)
- Emails are stored without VT queries (preserving social engineering context)
- Private IPs (RFC1918) are filtered from Layer 2 expansion
- VT response caching is used extensively to avoid redundant API calls across runs and orgs
- `--skip-query` only rebuilds the graph from existing cache — do NOT use for initial builds where nodes need full VT metadata
- All nodes (including relationship-discovered third-layer nodes) must have full VT metadata; all edges must have complete attributes

## Current Progress (2026-03-24)

### KGs Built (with full VT metadata + edge attributes)
| Org | Nodes | Edges |
|-----|-------|-------|
| APT1 | 828 | 863 |
| APT-C-36 | 709 | 1,459 |
| Kimsuky | 1,112 | 1,451 |
| APT-C-23 | 1,686 | 2,761 |
| APT28 | 2,131 | 2,928 |
| APT29 | 2,492 | 3,515 |
| APT19 | 122 | 226 |

### KGs Needing Rebuild (built before edge attributes enhancement)
- APT12, APT16, APT17, APT18

### Remaining Work
- APT-C-23: ~30 nodes failed (DNS errors during sleep) — rerun to fill gaps
- Rebuild APT12, APT16, APT17, APT18 with edge attributes
- Fetch VT relationships for remaining ~150 orgs (~25,354 API calls)
- Build KGs for all remaining ~150 orgs after relationships fetched
