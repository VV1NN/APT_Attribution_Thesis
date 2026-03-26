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
- **Layer 2:** VT-discovered relationships (11 edge types active, 8 more defined for future API plans):
  - **File → Network:** `contacted_ip`, `contacted_domain`, `contacted_url`
  - **File → File:** `dropped_file`, `execution_parent`, `bundled_file`
  - **DNS:** `resolves_to` (domain ↔ ip), `has_subdomain` (domain → domain)
  - **Reverse (Domain/IP → File):** `communicating_file`, `referrer_file`
  - **Code-only (Enterprise API):** `embedded_domain`, `embedded_ip`, `embedded_url`, `itw_domain`, `itw_ip`, `itw_url`, `downloaded_file`, `compressed_parent`

### Key Scripts
- `scripts/build_knowledge_graph.py` — Core KG builder. Phase 1 queries VT Details API for full metadata (PE info, WHOIS, DNS, ASN). Phase 2 loads VT relationships, discovers third-layer nodes, queries their VT Details, and expands the graph. Edge attributes include: `resolution_date`, `malicious`/`undetected` counts, `last_analysis_date`, `type_tag`, `type_description`, `meaningful_name`. Uses NetworkX internally.
- `scripts/merge_knowledge_graphs.py` — Merges per-org KGs. Same-ID nodes merge (numeric fields: latest wins; lists: union). Outputs JSON + SQLite with `nodes`, `edges`, `node_orgs` tables.
- `scripts/fetch_vt_relationships.py` — Fetches VT relationship data with global dedup cache in `vt_relationships/.cache/`. File: `contacted_ips/domains/urls`, `dropped_files`, `execution_parents`, `bundled_files`. Domain: `resolutions`, `communicating_files`, `referrer_files`, `subdomains`, `historical_ssl_certificates`, `historical_whois`. IP: `resolutions`, `communicating_files`, `referrer_files`, `historical_ssl_certificates`, `historical_whois`.
- `ioc_clean_code/clean_iocs_v2.py` — Normalization: cross-hash merging, URL-IP collapse, defang restoration, eTLD blacklist (~50 domains), DDNS whitelist.

### Node Types & IDs
- `apt` (name), `file` (`file_{sha256}`), `domain` (`domain_{name}`), `ip` (`ip_{addr}`), `email` (`email_{addr}`)

## API Constraints

- **VirusTotal academic plan:** 20,000 req/min, 20,000 lookups/day, 620,000 lookups/month (group shared quota)
- Rate limiting: both scripts use ~600 req/min (`RATE_LIMIT_SEC = 0.1` / `requests_per_min = 600`)
- 429 retry: `build_knowledge_graph.py` max 3 attempts (interval = 0.1s × attempt); `fetch_vt_relationships.py` **unlimited** retries with exponential backoff (60s → 120s → 300s → 600s)
- `fetch_vt_relationships.py` daily limit: 18,000 (with buffer from 20K plan quota)
- API key loaded from `.env` (`VT_API_KEY`)

## Important Conventions

- Documentation and some comments are in Chinese (Traditional)
- Emails are stored without VT queries (preserving social engineering context)
- Private IPs (RFC1918) are filtered from Layer 2 expansion
- VT response caching is used extensively to avoid redundant API calls across runs and orgs
- `--skip-query` only rebuilds the graph from existing cache — do NOT use for initial builds where nodes need full VT metadata
- All nodes (including relationship-discovered third-layer nodes) must have full VT metadata; all edges must have complete attributes

## Current Progress (2026-03-26)

### VT Relationships Fetched (21/176 orgs)
| Org | Files | IPs | Domains | 狀態 |
|-----|-------|-----|---------|------|
| APT-C-23 | 29 | 4 | 190 | ✅ |
| APT-C-36 | 100 | 8 | 8 | ✅ |
| APT1 | 10 | 4 | 43 | ✅ |
| APT12 | 12 | 0 | 2 | ✅ |
| APT16 | 2 | 1 | 5 | ✅ |
| APT17 | 0 | 0 | 1 | ✅ |
| APT18 | 3 | 0 | 0 | ✅ |
| APT19 | 2 | 3 | 7 | ✅ |
| APT28 | 101 | 36 | 113 | ✅ |
| APT29 | 360 | 159 | 135 | ✅ |
| APT32 | 57 | 62 | 95 | ✅ |
| FIN7 | 202 | 80 | 69 | ✅ |
| Gamaredon_Group | 261 | 28 | 224 | ✅ |
| Kimsuky | 48 | 21 | 102 | ✅ |
| Lazarus_Group | 127 | 66 | 159 | ✅ |
| Magic_Hound | 45 | 103 | 706 | ✅ |
| MuddyWater | 114 | 33 | 82 | ✅ |
| OilRig | 65 | 17 | 41 | ✅ |
| Sandworm_Team | 96 | 73 | 115 | ✅ |
| Turla | 77 | 4 | 62 | ✅ |
| Wizard_Spider | 12 | 249 | 222/278 | ⚠️ 剩 ~56 domains |

Global cache: files=1,716 / ips=942 / domains=2,274

### KGs Built (13 complete, with full VT metadata + edge attributes + depth field)
| Org | Nodes | Edges | L0 | L1 | EdgeAttr% |
|-----|-------|-------|----|----|-----------|
| APT-C-23 | 3,334 | 4,857 | 252 | 3,081 | 94% |
| APT-C-36 | 1,135 | 2,063 | 118 | 1,016 | 62% |
| APT1 | 2,444 | 2,570 | 81 | 2,362 | 98% |
| APT12 | 321 | 372 | 19 | 301 | 69% |
| APT16 | 399 | 427 | 10 | 388 | 95% |
| APT18 | 126 | 146 | 6 | 119 | 69% |
| APT19 | 184 | 304 | 27 | 156 | 96% |
| APT28 | 4,888 | 6,274 | 285 | 4,602 | 91% |
| APT29 | 2,662 | 4,640 | 739 | 1,922 | 77% |
| APT32 | 1,235 | 1,724 | 283 | 951 | 82% |
| Kimsuky | 1,107 | 1,687 | 182 | 924 | 92% |
| OilRig | 3,173 | 3,964 | 193 | 2,979 | 83% |
| Turla | 3,544 | 4,383 | 198 | 3,345 | 79% |

> APT17 僅 1 個 domain IoC，KG 只有 apt 根節點，非 pipeline 問題。
> EdgeAttr% < 100% 是因為 VT 404 節點的邊無 `last_analysis_stats`，屬正常。
> `fetch_vt_metadata.py` 已被 `build_knowledge_graph.py` 取代（自行查 VT Details API），`VT_results/` 為舊版產出，僅 `fetch_vt_relationships.py` 仍讀取。

### Remaining Work
- Wizard_Spider: finish remaining ~56 domains (next run auto-resumes)
- Build KGs for 7 orgs with relationships ready (needs VT API): FIN7, Gamaredon_Group, Lazarus_Group, Magic_Hound, MuddyWater, Sandworm_Team, Wizard_Spider
- Fetch VT relationships for remaining 155 orgs
- Build KGs for all remaining orgs after relationships fetched
- Fix OilRig bad IoC: `192.121.22..46` (double dot — IoC cleaning missed it)
- URL 節點評估：2,078 個 C2 候選 URL（32.5%）值得新增為獨立節點類型（分析腳本：`scripts/analyze_url_quality.py`）
