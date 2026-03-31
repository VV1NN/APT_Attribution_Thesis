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

## Current Progress (2026-03-29)

> 完整資料狀態報告：`knowledge_graphs/data_status.md`

### VT Relationships Fetched (22/175 orgs)
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
| Wizard_Spider | 12 | 249 | 278 | ✅ |

Global cache: files=1,716 / ips=942 / domains=2,274

### KGs Built (21 orgs, with full VT metadata + edge attributes + depth field)
| Org | Nodes | Edges | L0 | L1 | EdgeAttr% |
|-----|-------|-------|----|----|-----------|
| Lazarus_Group | 11,529 | 14,424 | 434 | 11,094 | 92% |
| Gamaredon_Group | 7,515 | 15,811 | 725 | 6,789 | 91% |
| Sandworm_Team | 6,713 | 7,965 | 383 | 6,329 | 88% |
| MuddyWater | 6,725 | 8,644 | 256 | 6,468 | 85% |
| Wizard_Spider | 6,503 | 12,134 | 799 | 5,703 | 97% |
| FIN7 | 5,083 | 6,876 | 365 | 4,717 | 82% |
| APT28 | 4,888 | 6,274 | 285 | 4,602 | 92% |
| APT32 | 4,250 | 5,378 | 293 | 3,956 | 94% |
| Magic_Hound | 3,878 | 6,524 | 910 | 2,967 | — |
| Turla | 3,544 | 4,383 | 198 | 3,345 | 80% |
| APT-C-23 | 3,334 | 4,857 | 252 | 3,081 | 94% |
| OilRig | 3,173 | 3,964 | 193 | 2,979 | 84% |
| APT29 | 2,662 | 4,640 | 739 | 1,922 | 81% |
| APT1 | 2,444 | 2,570 | 81 | 2,362 | 98% |
| APT-C-36 | 1,135 | 2,063 | 118 | 1,016 | 64% |
| Kimsuky | 1,107 | 1,687 | 182 | 924 | 93% |
| APT16 | 399 | 427 | 10 | 388 | 95% |
| APT12 | 321 | 372 | 19 | 301 | 71% |
| APT19 | 184 | 304 | 27 | 156 | 97% |
| APT18 | 126 | 146 | 6 | 119 | 70% |
| APT17 | 1 | 0 | 0 | 0 | — |

> APT17 僅 1 個 domain IoC，KG 只有 apt 根節點，非 pipeline 問題。
> EdgeAttr% < 100% 是因為 VT 404 節點的邊無 `last_analysis_stats`，屬正常。
> `fetch_vt_metadata.py` 已被 `build_knowledge_graph.py` 取代（自行查 VT Details API），`VT_results/` 為舊版產出，僅 `fetch_vt_relationships.py` 仍讀取。

### Master KG (21 orgs merged, 2026-03-29)
- **66,444 nodes** / **109,443 edges**
- 節點：file=34,005 / domain=19,525 / ip=12,751 / email=142 / apt=21
- 跨 org 共享節點：4,330 個；獨有節點：62,114 個
- 輸出：`knowledge_graphs/master/merged_kg.json` + `merged_kg.db`

### 歸因可行性分析 (2026-03-29, 21 orgs)
完整報告：`scripts/feasibility_report.json` / `scripts/feasibility_report.txt`
分析腳本：`scripts/feasibility_analysis.py`

**Overlap Detection 歸因（Leave-One-Out 驗證）：**
- L0 IoC 總數：6,182
- 連通率 72.7%（L0 IoC 中有 VT relationship 鄰居的比例）
- Overlap 率 48.5%（鄰居中能找到其他 org 標記的比例）
- **Overlap 歸因準確率 95.7%**（當有 overlap 時）
- 全體歸因準確率 46.4%（含無 overlap 的 IoC）
- 過濾低惡意度（dr < 0.1）後準確率 99.2%（711 → 2003 IoCs）
- Domain 最好（61.9% overlap / 97.2% accuracy），IP 次之（60.7% / 99.7%），File 稍弱（34.8% / 90.9%）

**VT Metadata 區分力（KL divergence，僅 L0 IoC）：**
- 強區分力（KL > 1.0）：`threat_label`(5.18), `pe_imphash`(5.05), `asn`(4.53), `as_owner`(4.50), `registrar`(3.75), `jarm`(2.4-2.6), `country`(2.07), `creation_year`(1.70), `tld`(1.42), `type_tag`(1.31), `pe_resource_lang`(1.30)
- 弱區分力（KL < 0.3）：`pe_machine`(0.14)

**跨 org 共享：**
- L0 直接共享節點：62 個（domain=42, file=8, ip=8, email=4）
- L1 間接共享節點：5,306 個
- Top pair：APT28 ↔ Sandworm_Team（33 個共享節點）

### 歸因系統實驗結果 (2026-03-29)

**訓練設定：**
- 訓練集：5,961 筆 L0 IoC（depth=0，單一 org，≥100 IoCs 的 15 個 major org）
- 評估：ALL-nodes overlap dict + per-fold test IoC 移除 + 不做 exclude_org（最接近真實推論的 CV 設定）
- 分類器：XGBoost (n_estimators=500, max_depth=8, balanced sample_weight)

**正式結果（per-fold removal CV）：**

| 指標 | 無門檻 | 信心度門檻 0.3（推薦） |
|------|--------|----------------------|
| Coverage | 100% | 81.1% |
| Micro-F1 | **80.0%** | **95.7%** |
| Macro-F1 | 81.8% | 95.2% |
| Top-3 | 90.1% | — |
| Top-5 | 93.3% | — |

**Simulated Inference（額外移除 test IoC 的獨佔 L1 鄰居）：**
- Per-fold removal: Micro-F1 = 80.0%
- + 移除 exclusive L1: Micro-F1 = 72.2%
- Gap = -7.9%（輕微，來自 L1 transitive label）

**Per-class F1（無門檻）：**
- 11 個 org F1 > 70%：FIN7(96%), APT-C-36(96%), Magic_Hound(93%), APT-C-23(91%), MuddyWater(88%), APT28(87%), APT29(86%), Kimsuky(85%), Lazarus(84%), Gamaredon(82%), APT32(82%)
- 最弱：OilRig(30%)，因被當成 default class（信心度門檻 0.3 後 precision 從 18% 提升到 89%）

### Attribution Scripts

**訓練：**
- `scripts/build_vocabularies.py` — 掃描 Master KG 建立 ordinal encoding vocabulary 與頻率表
- `scripts/build_features.py` — 四層特徵提取（L1 88d + L2 35d + L3 7+Kd + L4 64d），含 IDF degree penalty
- `scripts/train_node2vec.py` — Node2Vec 嵌入訓練（64d, p=1.0, q=0.5）
- `scripts/train_classifier.py` — XGBoost/RF/MLP 5-fold CV 消融實驗
- `scripts/train_and_save_model.py` — 訓練最終模型並存檔至 `scripts/model/`

**推論：**
- `scripts/inference.py` — 單筆/批次 IoC 歸因（VT API → 四層特徵 → Top-K + 信心度 + SHAP）
  ```bash
  uv run python scripts/inference.py <hash|domain|ip>
  uv run python scripts/inference.py --file iocs.txt
  uv run python scripts/inference.py --json 185.45.67.89
  ```

**評估：**
- `scripts/run_shap_analysis.py` — SHAP TreeExplainer 分析
- `scripts/eval_confidence_threshold.py` — 信心度門檻曲線
- `scripts/eval_allnodes_correct_cv.py` — 正式 CV 評估（ALL-nodes per-fold removal）
- `scripts/eval_simulated_inference.py` — Simulated inference（移除 test IoC）

### Organization Selection (2026-03-31)

已移除 5 個不堪用組織（APT12/16/17/18/19 — IoC 不足、KG 過小）。
保留 **16 個有效 org**（考慮移除 APT-C-36，僅 141 cleaned IoCs / 1 report）。
Transparent_Tribe VT relationships 已完成，KG 建構中斷待恢復（`--skip-query` 續建）。

### TTP Context Extraction Pipeline (2026-03-31, Phase 1 進行中)

**目標：** 從 203 份 CTI 報告提取攻擊語境實體，作為 L5 特徵融入歸因系統。

**NER 模型：** [NER-BERT-CRF-for-CTI](https://github.com/stwater20/NER-BERT-CRF-for-CTI)
- 架構：BERT-base-cased → Linear → CRF（BIO 標注，13 種實體）
- Checkpoint：`NER-BERT-CRF-for-CTI/outputs/ner_bert_crf_checkpoint.pt`（433 MB）
- 採用的 6 種實體：Tool, Way, Exp, Purp, Idus, Area
- 忽略的 7 種實體：HackOrg（label leakage）, SecTeam, Org, OffAct, SamFile, Features, Time

**Pipeline scripts：**
```bash
# 批次 NER 推論（203 份報告）
uv run python scripts/ttp_extraction/run_ner_on_reports.py
uv run python scripts/ttp_extraction/run_ner_on_reports.py --org APT28  # 單一組織

# （待開發）實體正規化
uv run python scripts/ttp_extraction/normalize_entities.py

# （待開發）IoC → Report → TTP 對應
uv run python scripts/ttp_extraction/build_ioc_ttp_mapping.py

# （待開發）L5 TTP 特徵提取
uv run python scripts/build_ttp_features.py
```

**NER 輸出格式：** `scripts/ttp_extraction/{org}/{report_hash}.json`
```json
{
  "report_file": "securelist_sofacy_2017.txt",
  "org": "APT28",
  "entities": {"Tool": [...], "Way": [...], "Exp": [...], ...},
  "entity_counts": {"Tool": 5, "Way": 3, "Exp": 2, ...}
}
```

**進度：** APT-C-23（4 份）完成，其餘 199 份待跑（建議用 GPU 加速）。

### Planned: Attack Path Prediction (Phase 3)

歸因完成後，根據被歸因 APT 的歷史 TTP 序列，預測下一步攻擊技術。
- 將 NER 實體映射到 ATT&CK Kill Chain 14 階段
- 統計每個 APT 的階段轉移機率（transition model）
- 擴充 `inference.py`：歸因結果 + 當前攻擊階段 + 下一步預測 + 防禦建議

### Remaining Work
- [ ] 完成 203 份報告的 NER 推論（Phase 1A，建議用 GPU）
- [ ] 實體正規化 + 詞彙表建構（Phase 1C）
- [ ] IoC-Report-TTP 對應建立（Phase 1D）
- [ ] L5 TTP 特徵實作 + 消融實驗（Phase 2）
- [ ] 攻擊路徑預測框架（Phase 3）
- [ ] Transparent_Tribe KG 續建
- [ ] Fix OilRig bad IoC: `192.121.22..46`
- [ ] 完整計畫書：`PLAN_zh.md`
