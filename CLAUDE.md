# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

APT (Advanced Persistent Threat) knowledge graph construction pipeline for a master's thesis. The system extracts IoCs (Indicators of Compromise) from CTI reports, enriches them via VirusTotal API, builds two-layer knowledge graphs per APT group, and merges them into a unified queryable database.

## Setup & Common Commands

**Package manager:** `uv` (Python 3.12, specified in `.python-version`)
> PyTorch CUDA index 僅在 Linux 啟用（`marker = "sys_platform == 'linux'"`），macOS 使用預設 PyPI。

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

## Current Progress (2026-04-06)

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

### 歸因可行性分析 (2026-03-29, 21 orgs — 舊版，部分結論已被修正)
完整報告：`scripts/feasibility_report.json` / `scripts/feasibility_report.txt`
分析腳本：`scripts/feasibility_analysis.py`

> ⚠️ 以下 per-IoC LOO 數字（95.7% accuracy）含 same-campaign signal，已被 per-report LOO 修正版取代。
> 且 per-report LOO 的 66.7% accuracy 也受 tie-breaking 不確定性影響，真正可靠的數字見下方「Graph Overlap 深度分析」。

**VT Metadata 區分力（KL divergence，僅 L0 IoC）：**
- 強區分力（KL > 1.0）：`threat_label`(5.18), `pe_imphash`(5.05), `asn`(4.53), `as_owner`(4.50), `registrar`(3.75), `jarm`(2.4-2.6), `country`(2.07), `creation_year`(1.70), `tld`(1.42), `type_tag`(1.31), `pe_resource_lang`(1.30)
- 弱區分力（KL < 0.3）：`pe_machine`(0.14)

**跨 org 共享：**
- L0 直接共享節點：62 個（domain=42, file=8, ip=8, email=4）
- L1 間接共享節點：5,306 個
- Top pair：APT28 ↔ Sandworm_Team（33 個共享節點）

### Campaign Contamination 發現 (2026-03-31)

> 完整分析筆記：`notes/campaign_contamination_analysis.md`

**核心發現：StratifiedKFold（random split）的結果因 same-campaign contamination 嚴重虛高。**

同一份 CTI 報告的 IoC 來自同一 campaign，共享相同基礎設施（C2、registrar、ASN、packer）。Random split 讓同 campaign 的 IoC 同時出現在 train/test，分類器只需 memorize campaign fingerprint 即可猜對。GroupKFold（以報告為單位分組）才能測試跨 campaign 泛化能力。

**GroupKFold vs StratifiedKFold 消融實驗（XGBoost, 5-fold CV, 15 orgs, 5,961 IoCs, 127 report groups）：**

| 特徵組合 | StratifiedKFold | GroupKFold | Δ |
|---------|----------------|-----------|---|
| L1 (88d metadata) | 63.8% | 14.0% | **-49.8%** |
| L1+L2 (123d) | 69.6% | 17.3% | **-52.3%** |
| L1+L2+L3 (145d) | 69.8% | 12.8% | **-57.0%** |
| L1+L2+L3+L4 (209d) | 72.1% | 16.1% | **-56.0%** |
| L3 alone (22d) | 8.3% | 17.5% | +9.2% |

> 15-class random guess = 6.7%。GroupKFold 下所有配置接近 random level。
> Fair subset（≥5 report groups 的 12 org）差距仍為 -46.2%，排除 GroupKFold class 不平衡的解釋。

**結論：VT metadata-based 特徵（L1~L4）本質上是 campaign-specific，不是 APT-specific。**

特徵層次穩定性光譜：
```
Campaign-specific ──────────────────────── APT-specific
VT metadata    PE structure    Code reuse    TTP/ATT&CK
(現在在這裡)                               (NER pipeline 目標)
```

**Graph Connectivity（Overlap Matching）也需要 cross-campaign 驗證：**

Per-IoC leave-one-out 只移除 1 個 IoC，同報告的其他 IoC 仍在 KG → 同 campaign 基礎設施仍可 match。Per-Report leave-one-out 移除整份報告的所有 IoC + 獨佔 L1 鄰居 → 真正測試跨 campaign infrastructure reuse。

| 測試方式 | Coverage | Accuracy | Overall |
|---------|----------|----------|---------|
| Per-IoC (同 campaign 還在) | 68.2% | 93.8% | 63.9% |
| **Per-Report (跨 campaign)** | **47.5%** | **66.7%** | **31.7%** |
| ML classifier (GroupKFold) | 100% | ~14% | ~14% |

Graph connectivity 比 metadata 好得多（31.7% vs 14%），但也受 campaign contamination 影響（93.8% → 66.7%）。
原因：跨 campaign 的 shared L1 nodes 更可能是公共基礎設施（CDN/DNS），多 org 共用 → majority vote 錯誤。

**Per-Report 跨 campaign 各 org 表現差異極大：**

Infrastructure reuse 強的 APT（跨 campaign 歸因可行）：
- Lazarus_Group：match 掉 6%，accuracy 掉 7%（88.8%）→ 強 infrastructure reuse
- Sandworm_Team：accuracy 88.3% → 跨 campaign 穩定
- Gamaredon_Group：accuracy 84.3%
- Turla：accuracy 80.2%

Infrastructure reuse 弱的 APT（每次 campaign 換全新基礎設施）：
- Kimsuky：accuracy 92.2% → 25.4%（-66.9%）
- APT-C-36：accuracy 92.6% → 28.4%（-64.2%）
- APT29：accuracy 93.4% → 45.3%（-48.1%）
- Magic_Hound：match 從 76.3% → 32.5%（527 IoC 報告完全無跨 campaign 連結）

**完全無跨 campaign 連結的大型報告（排名前 5）：**
- Magic_Hound (ClearSky 2017)：527 IoCs，exclusive L1=1,776 → 移除後零 match
- Wizard_Spider (FireEye 2020)：457 IoCs，exclusive L1=5,010
- Gamaredon_Group (Symantec)：218 IoCs，exclusive L1=637
- APT29 (F-Secure Dukes)：178 IoCs，exclusive L1=1,108
- APT32 (Cybereason)：98 IoCs，exclusive L1=1,051

**歸因方法比較總結（修正版 2026-03-31）：**

| 方法 | Coverage | Det. Accuracy | Tie 率 | 備註 |
|------|----------|--------------|--------|------|
| VT metadata ML (GroupKFold) | 100% | ~14% | — | campaign fingerprint |
| Graph overlap (per-report, clear winner) | 24.8% | **100%** | — | 確定性歸因 |
| Graph overlap (per-report, 含 tie) | 47.5% | 100% (clear) | 46.4% | tie 需額外信號打破 |
| TTP features | ? | ? | — | 待驗證 |

**推論策略（修訂版）：**
```
輸入未知 IoC → VT API 查詢 → 1-hop 鄰居 match KG？
  有 match + clear winner → HIGH confidence（100% accuracy）
  有 match + tie         → MEDIUM confidence → TTP tie-breaking
  無 match               → LOW confidence → ML fallback / 無法歸因
```

**評估腳本：**
- `scripts/eval_groupkfold_l1.py` — L1-only GroupKFold vs StratifiedKFold
- `scripts/eval_groupkfold_ablation.py` — 全層消融 GroupKFold（L3 per-fold 重算）
- `scripts/eval_overlap_by_report.py` — Per-Report vs Per-IoC overlap 歸因比較
- `scripts/eval_edge_type_analysis.py` — Edge type 歸因力 + voting 策略比較
- `scripts/eval_noise_filter_sweep.py` — Noise filter + confidence-gated attribution
- `scripts/analyze_multihop.py` — Multi-hop leave-one-out overlap 模擬
- 結果：`scripts/results/eval_groupkfold_l1.json`, `eval_groupkfold_ablation.json`, `eval_overlap_by_report.json`, `eval_edge_type_analysis.json`, `eval_noise_filter_sweep.json`

### Graph Overlap 深度分析 (2026-03-31)

> 分析腳本：`scripts/eval_edge_type_analysis.py`, `scripts/eval_noise_filter_sweep.py`
> 結果：`scripts/results/eval_edge_type_analysis.json`, `scripts/results/eval_noise_filter_sweep.json`

**核心發現：Clear winner 永遠正確，所有「錯誤」都是 tie-breaking 假象。**

Per-report LOO 下 2,898 個 matched IoC 的真實分佈：
- **Clear winner（無 tie）：1,516 個 → 100% 正確**
- **Tie（true org 在候選中）：1,348 個 → tie-breaking 不確定**
- **tie_true_not = 0**（true org 永遠在 tie 候選中）

之前報的 63-70% accuracy 完全是 `Counter.most_common()` 在 tie 時的 set 遍歷順序決定，**每次跑結果不同**。

**Edge Type 歸因力排名（per-vote signal-to-noise ratio）：**

| Edge Type | Precision | SNR | 票數 |
|-----------|-----------|-----|------|
| execution_parent | 56.7% | 1.3x | 210 |
| communicating_file | 46.3% | 0.9x | 618 |
| referrer_file | 33.4% | 0.5x | 8,610 |
| bundled_file | 29.9% | 0.4x | 7,003 |
| dropped_file | 20.9% | 0.3x | 9,162 |
| resolves_to | 17.5% | 0.2x | 49,137 |
| contacted_ip | 11.1% | 0.1x | 50,945 |

> 代碼層面關係（execution_parent）比網路層面（contacted_ip）更有歸因力。

**Weighting 策略全部無效：** Uniform / EdgeType-weighted / IDF / Edge×IDF 結果完全相同。
原因：同一 shared L1 node 對所有 org 投等比例票，reweighting 不改變排名。

**Noise Filter Sweep（org count threshold）：**

| Threshold | Match | Clear Correct | Tie | Det.Acc |
|-----------|-------|---------------|-----|---------|
| ≤1 org | 810 | 810 | 0 | 100% |
| ≤2 org | 1,858 | 1,179 | 679 | 100% |
| ≤5 org | 2,174 | 1,374 | 800 | 100% |
| all | 2,864 | 1,516 | 1,348 | 100% |

> Static noise filter（127.0.0.1 等）效果極小（僅 34 cases），直接用 org count threshold 更實用。

**Coverage Gap 原因（52.5% 無 match）：**
- KG 中完全沒有鄰居（VT 無回傳）：1,677 個（52.4%）— file 類最嚴重 1,101 個
- 有鄰居但全被 LOO 移除（同報告獨佔）：1,526 個（47.6%）
- email 完全沒有 coverage（138 個）

### 歸因系統舊結果 (2026-03-29, StratifiedKFold — 已知虛高)

> 以下結果使用 StratifiedKFold，受 campaign contamination 影響，僅供參考。

**訓練設定：**
- 訓練集：5,961 筆 L0 IoC（depth=0，單一 org，≥100 IoCs 的 15 個 major org）
- 評估：ALL-nodes overlap dict + per-fold test IoC 移除 + 不做 exclude_org
- 分類器：XGBoost (n_estimators=500, max_depth=8, balanced sample_weight)

**StratifiedKFold 結果（已知虛高，不應作為論文主要結果）：**

| 指標 | 無門檻 | 信心度門檻 0.3 |
|------|--------|--------------|
| Micro-F1 | 80.0% | 95.7% |
| Macro-F1 | 81.8% | 95.2% |

### Multi-hop 展開分析 (2026-03-31)

**Leave-One-Out 模擬（移除 test IoC + 獨佔 L1 鄰居後，看 1-hop/2-hop match）：**

| 策略 | Match 率 | 準確率 | API 成本 |
|------|---------|--------|---------|
| 1-hop overlap | 68.7% | 92.7% | 1 query/IoC |
| 1+2 hop (naive vote) | 68.9% | 71.6% | avg 18.5 queries/IoC |

2-hop 展開弊大於利：子圖平均 9x 擴大，但新增 match 僅 +10 個，且公共基礎設施噪音稀釋準確率 (-21.1%)。
2-hop 新增的 10 個案例全是 `aka.ms`（Microsoft 短網址，10 個 org 共用）。

### Attribution Scripts

**訓練：**
- `scripts/build_vocabularies.py` — 掃描 Master KG 建立 ordinal encoding vocabulary 與頻率表
- `scripts/build_features.py` — 四層特徵提取（L1 88d + L2 35d + L3 7+Kd + L4 64d），含 IDF degree penalty
- `scripts/train_node2vec.py` — Node2Vec 嵌入訓練（64d, p=1.0, q=0.5）
- `scripts/train_classifier.py` — XGBoost/RF/MLP 5-fold CV 消融實驗
- `scripts/train_and_save_model.py` — 訓練最終模型並存檔至 `scripts/model/`

**推論：**
- `scripts/inference.py` — 單筆/批次 IoC 歸因（VT API → 四層特徵 → Top-K + calibration + abstention + SHAP）
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
- `scripts/eval_false_flag.py` — False-flag 偽旗攻擊韌性（3 attacks × 4 defenses）
- `scripts/evaluate_openset.py` — Open-set 未知組織偵測（actor holdout + temperature calibration）
- `scripts/evaluate_selective.py` — Selective classification coverage-risk 曲線
- 結果：`scripts/results/eval_false_flag.json`, `evaluate_openset.json`, `evaluate_selective.json`

**工具：**
- `scripts/split_utils.py` — Report-aware 分組工具（Union-Find + leak assertion）
- `scripts/ttp_extraction/build_source_quality_table.py` — 來源可信度評分表建構

### Organization Selection (2026-03-31)

已移除 5 個不堪用組織（APT12/16/17/18/19 — IoC 不足、KG 過小）。
保留 **16 個有效 org**（考慮移除 APT-C-36，僅 141 cleaned IoCs / 1 report）。
Transparent_Tribe VT relationships 已完成，KG 建構中斷待恢復（`--skip-query` 續建）。

### TTP Context Extraction Pipeline (2026-04-01, Phase 1-3 完成)

**目標：** 從 CTI 報告提取攻擊語境實體，作為 L5 TTP 特徵融入三信號歸因系統。

**NER 模型：** [NER-BERT-CRF-for-CTI](https://github.com/stwater20/NER-BERT-CRF-for-CTI)
- 架構：BERT-base-cased → Linear → CRF（BIO 標注，13 種實體）
- Checkpoint：`NER-BERT-CRF-for-CTI/outputs/ner_bert_crf_checkpoint.pt`（433 MB）
- 採用的 6 種實體：Tool, Way, Exp, Purp, Idus, Area
- 忽略的 7 種實體：HackOrg（label leakage）, SecTeam, Org, OffAct, SamFile, Features, Time

**NER 推論：** ✅ 207 份報告全部完成（17 orgs）

**Entity Normalization（Phase 1, ✅ 完成）：**
兩層過濾：表面正規化（strip 標點/lowercase/dedup）+ 白名單過濾（MITRE ATT&CK Software list for Tool, 攻擊手法 keyword list for Way）

| Type | Before | After | 保留率 | Unique Before → After |
|------|--------|-------|--------|----------------------|
| Tool | 8,858 | 753 | 8.5% | 6,700 → 345 |
| Way | 2,010 | 369 | 18.4% | 1,098 → 66 |
| Exp | 248 | 199 | 80.2% | 208 → 146 |
| Purp | 925 | 897 | 97.0% | 617 → 552 |
| Idus | 1,505 | 1,340 | 89.0% | 722 → 522 |
| Area | 2,026 | 1,520 | 75.0% | 741 → 493 |

Top-5 Tool（after）：mimikatz(18), cobalt strike(17), psexec(16), killdisk(10), trickbot(9)
白名單：`scripts/ttp_extraction/attack_software_list.txt`（1,059 個 MITRE ATT&CK 工具名）

**IoC-Report-TTP Mapping（Phase 2, ✅ 完成）：**
- 6,054 / 6,182 IoCs（97.9%）成功映射到 TTP
- 映射鏈：IoC → has_ioc edge source_reports URL → `sha1(url)[:10]` → NER JSON
- 輸出：`scripts/ttp_extraction/ioc_ttp_mapping.json`

**L5 TTP Features（Phase 3, ✅ 完成）：**
- 6 種 entity type 分別 TF-IDF → concatenate → 1,538 維 sparse features
- 不做 SVD（避免 transductive leakage，XGBoost 能處理稀疏高維）
- 5,957/5,961 IoCs（99.9%）有 TTP mapping
- 輸出：`scripts/features/features_l5_ttp_matrix.npz`（sparse）+ `features_l5_ttp.npz`（metadata）

**Pipeline scripts：**
```bash
# NER 推論（已完成）
uv run python scripts/ttp_extraction/run_ner_on_reports.py

# Phase 1: Entity Normalization + 白名單過濾（已完成）
uv run python scripts/ttp_extraction/normalize_entities.py
uv run python scripts/ttp_extraction/normalize_entities.py --stats

# Phase 2: IoC → Report → TTP Mapping（已完成）
uv run python scripts/ttp_extraction/build_ioc_ttp_mapping.py

# Phase 3: L5 TTP Features（已完成）
uv run python scripts/build_ttp_features.py
```

### 三信號歸因實驗結果 (2026-04-01, Phase 4-7 完成)

> 完整實作計畫書：`.claude/plans/velvet-gliding-wind.md`
> 系統架構圖：`figures/system_architecture.png` / `.drawio`

**Experiment 3: TTP Cross-Campaign Evaluation（Phase 4, ✅ PASSED）**

| Config | GroupKFold micro-F1 | macro-F1 |
|--------|-------------------|----------|
| L1 only (metadata) | 14.0% | 12.3% |
| **L5 only (TTP)** | **34.1%** | **40.9%** |
| L1+L5 | 36.9% | 41.6% |
| L3+L5 (graph+TTP) | 36.3% | 42.6% |
| L1+L2+L3+L5 | 38.2% | 41.7% |
| Full (L1-L5) | 38.2% | 41.7% |

> ★ TTP 跨 campaign 歸因力是 VT metadata 的 **2.4 倍**（34.1% vs 14.0%）→ checkpoint passed, 全速推進
> 腳本：`scripts/eval_groupkfold_ttp.py` → 結果：`scripts/results/eval_groupkfold_ttp.json`

**Experiment 4: TTP Tie-Breaking（Phase 5, ✅ 完成）**

| 指標 | Before TTP | After TTP |
|------|-----------|-----------|
| Decided (coverage) | 1,553 (25.5%) | 2,825 (46.3%) |
| Accuracy | 100% | 77.8% |
| Tie 打破率 | — | 94.6% (1,272/1,345) |
| Tie-breaking accuracy | — | 50.8% |

Per-org 差異極大：Sandworm_Team(96%), APT-C-23(94%), APT28(87%), Turla(83%) vs Kimsuky(8%), Wizard_Spider(16%)
> 腳本：`scripts/eval_ttp_tiebreak.py` → 結果：`scripts/results/eval_ttp_tiebreak.json`

**Experiment 5: Multi-Signal Fusion（Phase 6, ✅ 完成）**

| Stage | Decided | Stage Acc | Cum. Coverage | Cum. Acc |
|-------|---------|-----------|---------------|----------|
| S1: Graph clear winner | 1,553 | 100% | 25.5% | 100% |
| S2: TTP tie-breaking | 1,272 | 50.7% | 46.3% | 77.8% |
| S3: ML fallback (L1+L5) | 3,186 | 30.7% | 98.5% | 52.8% |

| Cascade | micro-F1 | macro-F1 | Accuracy | Coverage |
|---------|----------|----------|----------|----------|
| **A (clean, L1+L5)** | **52.8%** | **63.5%** | 52.8% | 98.5% |
| B (full, L1-L5) | 53.4% | 63.9% | 53.4% | 98.5% |
| Graph-only | — | — | 100% | 25.5% |

> Per-stage F1：S1=100%/100%, S2=50.7%/40.1%, S3=30.7%/38.0%（micro/macro）
> 腳本：`scripts/eval_multisignal_fusion.py` → 結果：`scripts/results/eval_multisignal_fusion.json`

**Experiment 6: Infrastructure Discovery（Phase 7, ✅ 完成）**

- 每個正確歸因 IoC 平均發現 **12.0 個**相關基礎設施節點
- **97.6% 是 novel**（L1 depth, VT-discovered, 原始報告未提及）
- IP: 9,554 / File: 6,232 / Domain: 2,855
- **P@5 = P@10 = P@20 = 1.000**（clear winner 的 matched nodes 全屬正確 org）
> 腳本：`scripts/eval_infra_discovery.py` → 結果：`scripts/results/eval_infra_discovery.json`

### False-Flag 偽旗攻擊韌性評估 (2026-04-06, Codex 實作)

> 腳本：`scripts/eval_false_flag.py` → 結果：`scripts/results/eval_false_flag.json`

**攻擊類型（3 種 × 3 強度 0.1/0.3/0.5）：**
- **Tool mimicry：** 替換 10-50% Tool tokens 為 donor APT 的 tokens
- **Way mimicry：** 操縱 Way/Technique tokens
- **Source poisoning：** 降低高品質來源的可信度

**防禦策略（4 種）：**
- `baseline_raw`：raw L5 TTP features, 無防禦
- `weighted_l5`：source-quality weighted TTP features
- `weighted_l5_calibrated`：+ temperature scaling (T=5.0)
- `weighted_l5_calibrated_abstain`：+ abstention（conflict/open-set/low-confidence 拒判）

**結果摘要（clean baseline micro-F1 = 13.0%，15-class）：**

| 攻擊 (strength 0.5) | baseline_raw Δ F1 | 最嚴重攻擊 |
|---------------------|-------------------|-----------|
| Tool mimicry | **-4.95%** | 最有害 |
| Way mimicry | -2.72% | 中等 |
| Source poisoning | -0.05% | 微弱（source weighting 有效抵禦） |

> Abstention thresholds: low_confidence=0.12, open_set=0.09, conflict_margin=0.08

### Open-Set 未知組織偵測 (2026-04-06, Codex 實作)

> 腳本：`scripts/evaluate_openset.py` → 結果：`scripts/results/evaluate_openset.json`

**方法：** Actor holdout — 輪流留出 1 個 APT 作為 unknown，用剩餘 14 個訓練，測試能否拒判 unknown 樣本。Temperature scaling (T=5.0) 校準。

**整體結果：**

| 指標 | 值 |
|------|-----|
| AUROC（平均） | 0.764 ± 0.038 |
| FPR@95%TPR | 0.446 ± 0.052 |
| Unknown 誤歸因率 | 77.7% ± 10.0% |

**Per-org AUROC（代表性）：** Gamaredon(0.839), APT-C-36(0.771), APT-C-23(0.740), APT29(0.707)

> 結論：Open-set 偵測仍具挑戰性。未知 APT 有 77.7% 機率被錯誤歸因到已知 APT。需結合圖 overlap 無 match 信號強化拒判。

### Selective Classification 選擇性預測 (2026-04-06, Codex 實作)

> 腳本：`scripts/evaluate_selective.py` → 結果：`scripts/results/evaluate_selective.json`

**Coverage-Risk 曲線分析（5,594 IoCs）：**

| 指標 | Raw | Calibrated |
|------|-----|-----------|
| AURC | 0.771 | 0.767 |
| Delta | — | -0.4% |

> 90% coverage 時 risk ≈ 0.25（即 75% accuracy on accepted samples）
> Temperature calibration 效果微弱（-0.4%），ECE 改善有限。

### Source Quality Weighting (2026-04-06, Codex 實作)

> 腳本：`scripts/ttp_extraction/build_source_quality_table.py` → 輸出：`scripts/ttp_extraction/source_quality_table.json`

**來源可信度評分規則（0-1 scale）：**
- Government/CERT (.gov/.mil, cert/cisa/ncsc)：0.90-0.95
- Major vendors (Mandiant, CrowdStrike, Unit42, Microsoft, Google)：0.80-0.88
- Research orgs (.edu/.ac.uk/.org)：0.74
- News/forums/social media：0.42-0.58
- Unknown/default：0.62
- Age decay：λ=5e-4 exponential decay

### Report-Aware Split Utilities (2026-04-06, Codex 實作)

> 腳本：`scripts/split_utils.py`

**功能：**
- `build_report_connected_groups()`：Union-Find 將共享報告的 IoC 分組（transitive closure）
- `assert_no_report_leak()`：斷言 train/test 零報告重疊
- 防止 campaign contamination（random split 虛高 50%+）

### inference.py 更新 (2026-04-06, Codex 實作)

**新增功能：**
- Temperature calibration（載入 `scripts/model/calibrator.pkl`）
- Abstention 拒判邏輯（三條件）：
  - `high_conflict`：margin < 0.08 或 distinct_orgs ≥ 3 且 dominant_ratio < 0.40
  - `open_set`：calibrated confidence < open_set_threshold 且 overlap_ratio < 0.05
  - `low_confidence`：calibrated confidence < low_confidence_threshold
- 輸出新增：`decision`(PREDICT/ABSTAIN)、`abstain_reason`、`confidence_raw/calibrated`、`confidence_margin`、`open_set_score`

### 論文架構：Multi-Signal APT Attribution Framework

**三信號融合（已驗證）：**
- **Signal 1 (Graph Overlap):** 1-hop neighbor match → org voting → 100% det. accuracy, 25.5% coverage
- **Signal 2 (TTP Context):** NER entities → TF-IDF → cosine similarity → 34.1% GroupKFold, tie-breaking 50.8%
- **Signal 3 (VT Metadata):** 88d features → XGBoost → 14.0% GroupKFold（fallback only）

**Confidence-Gated Cascade（已驗證）：**
```
Graph clear winner → HIGH (100% precision, 25.5% coverage)
Graph tie + TTP breaks → MEDIUM (50.8% tie-break acc, 46.3% cumulative coverage)
No match → ML fallback (L1+L5) → LOW (30.7% acc, 98.5% cumulative coverage)
```

**10 個實驗：**
1. Campaign memorization analysis（✅ 已完成）
2. Graph overlap 100% precision 性質（✅ 已完成）
3. TTP cross-campaign evaluation（✅ 34.1% >> 14.0%）
4. TTP tie-breaking（✅ 94.6% ties broken, 50.8% accuracy）
5. Multi-signal fusion（✅ 52.9% overall accuracy, 98.5% coverage）
6. Infrastructure discovery（✅ P@K=1.000, avg 12 nodes discovered）
7. Case studies（待做）
8. **False-Flag robustness（✅ tool mimicry 最有害 -4.95% F1）**
9. **Open-Set detection（✅ AUROC 0.764, 未知誤歸因 77.7%）**
10. **Selective classification（✅ AURC 0.771, 90% coverage 時 25% risk）**

**研究問題（投稿版 RQ，2026-04-06 新增）：**
- **RQ1（效能）：** 融合 VT 圖特徵與 TTP 語境能否穩定優於單一模態？
- **RQ2（可信）：** 模型輸出的機率是否可校準，能否在給定 coverage 下控制風險？
- **RQ3（韌性）：** 面對偽旗/模仿攻擊，歸因性能下降幅度為何？
- **RQ4（實務）：** 在未知組織（open-set）與時間漂移下，系統是否能合理拒判？

**Research Contributions：**
- C1: VT-enriched two-layer IoC KG（66K nodes, 109K edges, 21 APT orgs）
- C2: Graph overlap 100% deterministic precision + edge type ranking + tie 問題發現
- C3: Multi-signal fusion（graph + TTP + metadata）+ TTP 跨 campaign 歸因力驗證（2.4x metadata）
- C4: Campaign memorization 分析（StratifiedKFold vs GroupKFold 差距 -50%+）
- C5: False-flag robustness 評估 + source-quality weighting 防禦
- C6: Open-set detection + selective classification + calibration 框架

### 新增文件 (2026-04-06)

- `EXPERIMENT_RESULTS.md` — 實驗結果彙整文件
- `PLAN_zh.md` — 改版為投稿導向 v2（RQ1-4、可驗證假設 H1-4）
- `notes/related_work_survey.md` — 完整文獻回顧（137+ papers, 2020-2025）
- `scripts/ttp_extraction/source_quality_table.json` — 200+ 來源域名可信度評分
- `figures/system_architecture.drawio` / `.png` — 系統架構圖
- `figures/system_architecture_zh.drawio` / `.png` — 中文版系統架構圖

---

## 研究方向轉向：威脅基礎設施預測 (2026-04-06)

> 完整中文計畫：`PLAN_infra_prediction_zh.md`
> 實作計畫：`.claude/plans/sprightly-weaving-planet.md`

### 轉向動機

歸因實驗（Exp 1-10）的核心結論：
- VT metadata 特徵是 **campaign-specific**（GroupKFold 14%，≈ random）
- TTP 稍好（34.1%）但仍不足
- Graph overlap 100% precision 但本質是查表（25.5% coverage）
- 三信號 cascade 52.8% overall → 歸因信號本身可能不存在

**新方向：Threat Infrastructure Prediction in a VT-Enriched Heterogeneous KG**
- 主任務：異質 Link Prediction（預測 KG 中缺失的基礎設施關聯）
- 下游驗證：Prediction-Driven Attribution（用預測鄰域做 overlap 歸因）
- Temporal 降為 sensitivity analysis（`last_analysis_date` ≠ 攻擊時間）

### Dataset Freeze (2026-04-06)

> 腳本：`scripts/data_snapshot.py` → 輸出：`scripts/data_snapshot.json`

| 指標 | 值 |
|------|-----|
| Nodes | 66,444 (file=34,005 / domain=19,525 / ip=12,751 / email=142 / apt=21) |
| Edges | 109,443 |
| Organizations | 20 (edge-bearing) |
| Source Reports | 143 |
| LP Target Edges | 103,168 (excl. has_ioc) |
| Timed Edges | 89,804 (82%) |
| SHA256 prefix | 3cce0484116e1345 |

### Split Protocols

> 腳本：`scripts/build_splits.py` → 輸出：`scripts/splits/`

| Protocol | Train | Valid | Test | 用途 |
|----------|-------|-------|------|------|
| **A (random)** | 93,154 | 4,972 | 5,042 | **主要實驗** |
| B-Pragmatic | 59,391 | 15,036 | 28,741 | Temporal sensitivity |
| B-Strict | 46,027 | 15,036 | 28,741 | Temporal (有時間戳only) |
| B-DNS | 27,061 | 2,825 | 2,069 | Temporal (最嚴格，只用 resolution_date) |

Protocol B inductive 比例極高（B-Pragmatic: 89% test edges 有新節點）。

**設計要點：**
- has_ioc 在所有 protocol 中排除（防止未來資訊洩漏）
- Type-constrained candidate sets（resolves_to 只在 ip 中排名等）
- Protocol B 報告 transductive + inductive 結果
- Node features 必須 split-aware（不用全圖 frequency/TF-IDF）

### Link Prediction Baseline Results (Protocol A, 2026-04-06)

> 腳本：`scripts/baselines_link_prediction.py`
> 結果：`scripts/results/lp_baselines_protocol_A_random.json`
> 評估框架：`scripts/eval_link_prediction.py`

**Signal Verification: ✅ 信號極強**

| Model | MRR | Hits@1 | Hits@10 | Mean Rank |
|-------|-----|--------|---------|-----------|
| Random | 0.0004 | 0.000 | 0.000 | 10,947 |
| Degree | 0.0227 | 0.006 | 0.053 | 1,648 |
| **DistMult** | **0.3063** | **0.220** | **0.491** | **938** |
| **ComplEx** | **0.3352** | **0.244** | **0.531** | **789** |

ComplEx MRR = 0.335 → 正確答案平均排第 3 名（在數萬候選中），比 Random 高 838 倍。

**Per-Relation Analysis（ComplEx, 按 MRR 排序）：**

| Relation | MRR | Hits@10 | 候選池 | 解讀 |
|----------|-----|---------|--------|------|
| communicating_file | 0.535 | 58.1% | 34,005 | 最容易預測 |
| referrer_file | 0.448 | 59.3% | 34,005 | 高 |
| contacted_url | 0.430 | 73.7% | 19,525 | 高 |
| bundled_file | 0.400 | 69.1% | 34,005 | 高 |
| resolves_to | 0.357 | 60.9% | 12,751 | DNS 解析可預測 |
| dropped_file | 0.310 | 50.1% | 34,005 | 中高 |
| execution_parent | 0.253 | 34.4% | 34,005 | 中 |
| has_subdomain | 0.240 | 25.7% | 19,525 | 中 |
| contacted_domain | 0.198 | 38.0% | 19,525 | 中 |
| contacted_ip | 0.164 | 36.0% | 12,751 | 最難預測 |

**關鍵發現：**
- File-to-file 關係（communicating/referrer/bundled）最容易預測
- DNS 解析（resolves_to）高度可預測
- contacted_ip 最難（IP 變動大，重用度低）
- 與歸因 edge type SNR ranking 有趣對應：execution_parent 在歸因中最強（56.7%），但 LP 中只排第 7

### R-GCN Link Prediction (2026-04-06, 實驗完成)

> 腳本：`scripts/rgcn_link_prediction.py`
> 結果：`scripts/results/lp_rgcn_distmult_protocol_A_random.json`, `lp_rgcn_complex_protocol_A_random.json`, `lp_rgcn_distmult_protocol_B_pragmatic.json`

**目標：** 用 R-GCN encoder（利用圖拓撲 + node features）取代 ComplEx 的 shallow embedding，驗證 GNN message passing 是否提升 LP 效能。

**架構：**
```
Node Features (per-type)          R-GCN Encoder              Decoder
─────────────────────────        ──────────────          ─────────────
File:  35d → Linear → 128d  ─┐
Domain:105d → Linear → 128d  ├→ RGCNConv(128,128,20rel,4bases)
IP:   154d → Linear → 128d  ─┤   → LayerNorm → ReLU → Dropout
apt/email: Embedding(128d)  ─┘   → RGCNConv(128,128,20rel,4bases)
                                  → LayerNorm
                                       ↓
                              node_emb (66444 × 128)
                                       ↓
                              DistMult: score = h·r·t
                              (或 ComplEx decoder)
```

**Node Feature 設計（per-type projection → shared 128d）：**

| Node Type | 原始維度 | 特徵內容 |
|-----------|---------|---------|
| File (34,005) | 35d | detection_ratio, malicious/80, log(size)/25, type_tag one-hot (31 classes), creation_year |
| Domain (19,525) | 105d | detection_ratio, malicious/80, tld one-hot (51), registrar one-hot (51), creation_year |
| IP (12,751) | 154d | detection_ratio, malicious/80, country one-hot (51), asn one-hot (101) |
| apt/email (163) | 128d | Learnable embedding (fallback, 無 VT 特徵) |

Categorical 欄位：top-K + OTHER bucket。VT 未找到的節點：所有特徵為 0。

**R-GCN 關鍵設計：**
- **20 relation types** = 10 原始 + 10 reverse（雙向 message passing）
- **Basis decomposition** (n_bases=4)：所有 relation 共享 4 個 basis matrix，壓縮參數量
- **2 層 R-GCN**：每層對不同 relation type 的鄰居用不同 W_r 聚合
- **Full-graph encoding**：每個 training batch 重新做一次 full-graph forward（因為反向傳播會釋放計算圖）
- **Negative sampling**：corrupt tail, neg_ratio=10, BCE loss
- **Early stopping**：patience=15 on training loss
- 總參數量：~4.3M（dim=128）
- **訓練時間**：RTX 4070 約 3 分鐘/100 epochs；MPS 約 33 分鐘

**依賴：** PyTorch Geometric (`torch_geometric`)，已在 pyproject.toml

### Link Prediction 全實驗結果 (2026-04-06, Protocol A + B)

**Protocol A — Random Split（Transductive）：**

| Model | MRR | Hits@1 | Hits@3 | Hits@10 | 參數量 |
|-------|-----|--------|--------|---------|--------|
| Random | 0.0004 | 0.000 | — | 0.000 | — |
| Degree | 0.0227 | 0.006 | — | 0.053 | — |
| DistMult | 0.3063 | 0.220 | — | 0.491 | ~17M |
| **ComplEx** | **0.3352** | **0.244** | — | **0.531** | ~17M |
| R-GCN + DistMult | 0.295 | 0.214 | 0.313 | 0.459 | ~4.3M |
| R-GCN + ComplEx | 0.290 | 0.208 | 0.310 | 0.458 | ~4.3M |

> ComplEx 在 transductive setting 下仍是最佳（MRR=0.335），shallow embedding 對已見 node 的記憶能力優於 GNN 聚合。
> R-GCN 的 node features + message passing 未帶來額外收益。

**R-GCN Per-Relation 分析（Protocol A, DistMult decoder）：**

| Relation | MRR | 解讀 |
|----------|-----|------|
| communicating_file | 0.559 | 最強 |
| contacted_url | 0.512 | 高 |
| referrer_file | — | — |
| contacted_ip | 0.141 | 弱 |
| bundled_file | 0.162 | 弱 |

**Protocol B — Pragmatic Temporal Split（Inductive, 89% test edges 有新 node）：**

| Model | MRR | Hits@1 | Hits@10 |
|-------|-----|--------|---------|
| Random | 0.0005 | 0.000 | 0.0005 |
| DistMult | 0.0003 | 0.0001 | 0.0005 |
| ComplEx | 0.0004 | 0.0001 | 0.0005 |
| Degree heuristic | 0.003 | 0.002 | 0.004 |
| **R-GCN + DistMult** | **0.003** | **0.002** | **0.004** |

> **所有模型在 temporal split 下幾乎完全失效（MRR < 0.003）。**
> R-GCN 與 Degree heuristic 持平 → GNN 只學到 node popularity，未學到可泛化的結構模式。
> Shallow KGE（ComplEx/DistMult）對新 node 完全無能為力（≈ random）。

### Link Prediction 核心發現與論文定位

**發現 1：Transductive LP 信號極強，但 R-GCN 未超越 shallow KGE**

ComplEx MRR=0.335 代表正確答案平均排第 3 名（在數萬候選中），說明 KG 內部結構高度可預測。
但 R-GCN 的 node features（VT metadata）和 message passing 沒帶來增量，表明 transductive 下 per-node embedding 的記憶能力足以捕捉圖結構，不需要 GNN 歸納。

**發現 2：Temporal LP 全軍覆沒 — APT 基礎設施本質上是 campaign-specific**

Protocol B 89% test edges 有新 node，所有模型 MRR < 0.003。這與歸因實驗的發現完全一致：

| 實驗範式 | 同 campaign 內 | 跨 campaign / temporal |
|---------|--------------|----------------------|
| VT metadata 歸因 (ML) | StratifiedKFold 72% | GroupKFold 14% |
| Graph overlap 歸因 | Per-IoC accuracy 93.8% | Per-Report accuracy 66.7% |
| **Link Prediction** | **Protocol A MRR=0.335** | **Protocol B MRR=0.003** |

**三個獨立實驗範式統一結論：APT 基礎設施模式是 campaign-specific，不是 actor-specific。跨 campaign / temporal 泛化在 VT-enriched KG 上目前不可行。**

**發現 3：R-GCN 的 inductive 能力未能挽救 temporal 場景**

理論上 R-GCN 靠 node features 可以對新 node 產出 embedding，但實驗顯示（MRR=0.003 = Degree heuristic）：
- VT metadata features（detection_ratio, type_tag, registrar, ASN 等）不足以預測未來基礎設施連結
- APT 組織在不同 campaign 間會換用全新的 registrar、ASN、IP 範圍
- 這與歸因中 VT metadata GroupKFold 14% 的結論一致

**論文 narrative：**
> "We demonstrate through three independent experimental paradigms — metadata-based classification, graph overlap attribution, and link prediction — that APT threat infrastructure exhibits fundamentally campaign-specific patterns. Temporal link prediction (MRR=0.003) confirms that threat infrastructure connectivity is largely unpredictable from historical graph structure, validating the practitioners' observation that APT groups routinely rotate infrastructure between campaigns. Within known infrastructure (transductive setting), graph structure is highly predictable (ComplEx MRR=0.335), enabling effective infrastructure discovery for ongoing campaigns but not temporal forecasting."

### Link Prediction Scripts

```bash
# Dataset freeze
uv run python scripts/data_snapshot.py

# Build splits (Protocol A/B)
uv run python scripts/build_splits.py

# Run baselines (Protocol A)
uv run python scripts/baselines_link_prediction.py --protocol protocol_A_random --epochs 100 --dim 128

# Run baselines on temporal split (Protocol B)
uv run python scripts/baselines_link_prediction.py --protocol protocol_B_pragmatic --epochs 100 --dim 128

# R-GCN + DistMult (Protocol A)
uv run python scripts/rgcn_link_prediction.py --protocol protocol_A_random --epochs 100 --dim 128

# R-GCN + ComplEx decoder (Protocol A)
uv run python scripts/rgcn_link_prediction.py --decoder complex --protocol protocol_A_random --epochs 100 --dim 128

# R-GCN + DistMult (Protocol B temporal)
uv run python scripts/rgcn_link_prediction.py --protocol protocol_B_pragmatic --epochs 100 --dim 128
```

### Remaining Work (Updated 2026-04-06)
- [x] ~~Dataset Freeze~~ → `scripts/data_snapshot.json`
- [x] ~~Split Builder~~ → `scripts/splits/`
- [x] ~~Evaluation Harness~~ → `scripts/eval_link_prediction.py`
- [x] ~~Non-Neural Baselines~~ → ComplEx MRR=0.335 (Protocol A)
- [x] ~~R-GCN 實作 + 訓練~~ → Protocol A: MRR=0.295（未超越 ComplEx）; Protocol B: MRR=0.003（全軍覆沒）
- [x] ~~Temporal experiments~~ → Protocol B 確認所有模型失效（MRR < 0.003）
- [ ] **Prediction-Driven Attribution** → 用 Protocol A 的 ComplEx 預測鄰域做 overlap 歸因（transductive 場景仍有價值）
- [ ] **Ablation（可選）** → node features 消融 / edge type subset / 圖密度影響
- [ ] 論文撰寫（投稿目標：Computers & Security / Digital Investigation / FGCS）
- [ ] Fix OilRig bad IoC: `192.121.22..46`
