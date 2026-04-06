# APT 威脅情資知識圖譜建構與歸因系統

> 碩士論文研究專案 — 自動化建構 APT 組織知識圖譜，基於 VirusTotal 豐富化與多源 IoC 整合，並以 **honest evaluation + calibrated abstention** 實現可信歸因。

## 研究目標

1. 從公開 CTI（Cyber Threat Intelligence）報告中提取 IoC（Indicators of Compromise）
2. 透過 VirusTotal API 進行兩層式豐富化，建構完整的 APT 知識圖譜
3. 合併多組織圖譜為統一資料庫，發現跨 APT 共享基礎設施
4. 建立不洩漏的歸因流程：report-connected split、fold-aware L5、L4 honest mode
5. 建立可信決策層：multiclass calibration、selective classification、open-set abstain

## 主要成果

- **Master KG（21 orgs）**：66,444 nodes / 109,443 edges
- **切分防洩漏**：report-connected GroupKFold（92 groups）+ 每 fold leak check
- **L5 主實驗改為 fold-aware**：legacy global L5 `0.1839/0.2103` → fold-aware weighted L5 `0.1049/0.1571`（micro/macro）
- **L4 honest mode**：`l4_mode=off`（主文）vs `transductive`（附錄比較），GroupKFold micro 差 `+0.0286`
- **校準與拒判**：ECE `0.2844 → 0.0462`、Brier `1.0754 → 0.9295`、AURC 改善 `-0.004368`
- **Open-set（actor holdout）**：AUROC mean `0.7644`，FPR@95TPR mean `0.4456`
- **False-flag 韌性**：最傷攻擊 `tool_mimicry`；`abstain` 顯著降低誤歸因但有 coverage 代價

## 資料規模

- **涵蓋 APT 組織**：176 組織（org_iocs/ 內含已提取 IoC，其中 146 組織有 >0 IoCs）
- **VT Relationship 已擷取**：22 組織（全域快取：files=1,716 / ips=942 / domains=2,274）
- **已建構知識圖譜**：21 組織（含完整 VT metadata + edge attributes + depth 欄位）

| 組織 | Nodes | Edges | L0 (CTI IoC) | L1 (VT 發現) |
|------|------:|------:|-------------:|-------------:|
| Lazarus_Group | 11,529 | 14,424 | 434 | 11,094 |
| Gamaredon_Group | 7,515 | 15,811 | 725 | 6,789 |
| MuddyWater | 6,725 | 8,644 | 256 | 6,468 |
| Sandworm_Team | 6,713 | 7,965 | 383 | 6,329 |
| Wizard_Spider | 6,503 | 12,134 | 799 | 5,703 |
| FIN7 | 5,083 | 6,876 | 365 | 4,717 |
| APT28 | 4,888 | 6,274 | 285 | 4,602 |
| APT32 | 4,250 | 5,378 | 293 | 3,956 |
| Magic_Hound | 3,878 | 6,524 | 910 | 2,967 |
| Turla | 3,544 | 4,383 | 198 | 3,345 |
| APT-C-23 | 3,334 | 4,857 | 252 | 3,081 |
| OilRig | 3,173 | 3,964 | 193 | 2,979 |
| APT29 | 2,662 | 4,640 | 739 | 1,922 |
| APT1 | 2,444 | 2,570 | 81 | 2,362 |
| APT-C-36 | 1,135 | 2,063 | 118 | 1,016 |
| Kimsuky | 1,107 | 1,687 | 182 | 924 |
| APT16 | 399 | 427 | 10 | 388 |
| APT12 | 321 | 372 | 19 | 301 |
| APT19 | 184 | 304 | 27 | 156 |
| APT18 | 126 | 146 | 6 | 119 |
| APT17 | 1 | 0 | 0 | 0 |

**Master KG（21 orgs 合併）**：66,444 nodes / 109,443 edges
- 節點：file=34,005 / domain=19,525 / ip=12,751 / email=142 / apt=21
- 跨 org 共享節點：4,330 個；獨有節點：62,114 個

## 歸因系統（2026-04 更新）

### 方法架構（主線）

```text
未知 IoC
  → VT Details + Relationships
  → L1/L2/L3 + (可選 L4) + Fold-aware L5(Tool/Way/Exp)
  → XGBoost
  → Calibration (temperature scaling)
  → Decision Layer: PREDICT / ABSTAIN
```

目前主線重點是 **honest evaluation + trustworthy attribution**：
- 切分採 `report-connected GroupKFold`（避免 report/source leakage）
- L5 採 fold-aware train-only TF-IDF（避免 transductive leakage）
- L4 以 `--l4-mode off` 作主結果，`transductive` 僅做比較
- 推論輸出 calibrated confidence + abstain reason（可拒判）

### 特徵層總覽

| Layer | 名稱 | 維度 | 使用建議 | 說明 |
|---|---|---:|---|---|
| L1 | VT metadata | 88d | 主線保留 | 節點自身屬性 |
| L2 | 鄰域統計 | 35d | 主線保留 | 1-hop/2-hop 統計 |
| L3 | overlap 投票 | 22d | 主線保留 | graph overlap evidence |
| L4 | Node2Vec | 64d | 主結果關閉 | `off` 避免 transductive leakage |
| L5 | TTP 特徵 | fold-dependent | 主線保留 | Tool/Way/Exp TF-IDF + source/age weighting |

### L5（fold-aware + weighted）

L5 主實驗不再使用全域 `features_l5_ttp_matrix.npz` 作唯一設定，而是每 fold：
1. 只用 train 節點 fit `TfidfVectorizer`（Tool/Way/Exp）
2. transform train/test
3. 套用權重：

```text
weighted_tfidf = tfidf * source_reliability_score * exp(-lambda * age_days)
```

4. 加入 consistency features：
- `source_disagreement_rate`
- `ttp_conflict_entropy`
- `num_independent_sources`

同時保留 legacy global L5 做基線比較。

### L4（honest mode）

`eval_groupkfold_ablation.py` 與 `eval_groupkfold_ttp.py` 均支援：

```bash
--l4-mode off           # 主結果（推薦）
--l4-mode transductive  # 舊做法（附錄/比較）
```

在 `off` 模式下，不納入 L4 欄位。

### Decision Layer：校準 + 可拒判

推論流程新增：
- `scripts/model/calibrator.pkl`（temperature scaling）
- calibrated confidence
- `decision: PREDICT / ABSTAIN`
- `abstain_reason`：
  - `low_confidence`
  - `high_conflict`
  - `open_set`

`inference.py` 目前會同時輸出 raw 與 calibrated 機率（含 Top-K）。

---

### 最新核心結果（2026-04）

#### 1) Leakage 修補結果

- report-connected groups：**92 groups**
- `eval_groupkfold_ablation.py` / `eval_groupkfold_ttp.py` folds 全部 leak check PASS

#### 2) L5 legacy vs fold-aware

| 設定 | micro-F1 | macro-F1 |
|---|---:|---:|
| Legacy global L5 | 0.1839 | 0.2103 |
| Fold-aware weighted L5 | 0.1049 | 0.1571 |

> 分數下降代表 leakage 去除後更貼近真實難度，主文應使用 fold-aware 結果。

#### 3) L4 off vs transductive（GroupKFold, L1+L2+L3+L4）

| 模式 | micro-F1 | macro-F1 |
|---|---:|---:|
| `l4_mode=off` | 0.1219 | 0.0982 |
| `l4_mode=transductive` | 0.1505 | 0.1173 |
| 差距 | +0.0286 | +0.0191 |

#### 4) Calibration / Selective / Open-set

Calibration（temperature scaling）：
- ECE：`0.2844 -> 0.0462`（`-0.2381`）
- Brier：`1.0754 -> 0.9295`（`-0.1459`）

Selective classification：
- AURC(raw) = `0.771402`
- AURC(calibrated) = `0.767033`
- ΔAURC = `-0.004368`

Open-set（actor holdout）：
- AUROC mean = `0.7644 ± 0.0382`
- FPR@95TPR mean = `0.4456 ± 0.0518`
- Unknown 誤歸因率 mean = `0.7775 ± 0.0998`

#### 5) False-flag robustness

攻擊：`tool_mimicry`, `way_mimicry`, `source_poisoning`（`r=0.1,0.3,0.5`）

關鍵結論：
- 最傷攻擊：`tool_mimicry`
- Utility 排名（avg attacked micro-F1）：`baseline_raw > weighted_l5 ≈ weighted_l5_calibrated > weighted_l5_calibrated_abstain`
- Safety 排名（avg misattribution，越低越好）：`weighted_l5_calibrated_abstain` 最佳
- Risk-aware（限制 abstain<=0.4）：`baseline_raw > weighted_l5 ≈ weighted_l5_calibrated`

---

### 對未知 IoC 歸因（最新版）

```bash
# 先完成模型與校準（建議）
uv run python scripts/train_and_save_model.py
uv run python scripts/model/calibrate_probs.py

# 單筆推論（需 VT_API_KEY）
uv run python scripts/inference.py d54fa56f1a0b1b63c4e8fa1cc170...

# 批次推論
uv run python scripts/inference.py --file suspicious_iocs.txt

# JSON 輸出（供自動化串接）
uv run python scripts/inference.py --json 185.45.67.89
```

輸出重點欄位：
- `decision`：`PREDICT` / `ABSTAIN`
- `abstain_reason`：`low_confidence` / `high_conflict` / `open_set`
- `confidence_raw` / `confidence_calibrated`

### 評估 Pipeline（建議順序）

```bash
# 1) Leakage-aware split / ablation
uv run python scripts/eval_groupkfold_ablation.py --l4-mode off
uv run python scripts/eval_groupkfold_ablation.py --l4-mode transductive

# 2) L5 fold-aware TTP
uv run python scripts/ttp_extraction/build_source_quality_table.py
uv run python scripts/eval_groupkfold_ttp.py --l4-mode off

# 3) Calibration + selective + open-set
uv run python scripts/model/calibrate_probs.py
uv run python scripts/evaluate_selective.py
uv run python scripts/evaluate_openset.py

# 4) False-flag robustness
uv run python scripts/eval_false_flag.py
```

主要結果檔：
- `scripts/results/eval_groupkfold_ablation.json`
- `scripts/results/eval_groupkfold_ttp.json`
- `scripts/model/calibration_metrics.json`
- `scripts/results/evaluate_selective.json`
- `scripts/results/evaluate_openset.json`
- `scripts/results/eval_false_flag.json`

---

## Quick Start：對單一組織跑完整 Pipeline

以下以 `APT18` 為例，從清洗 IoC 到建構知識圖譜的完整流程：

### 前置條件

```bash
uv sync                          # 安裝依賴
echo 'VT_API_KEY=your_key' > .env  # 設定 VT API Key
```

### Step 1：IoC 清洗

```bash
uv run python ioc_clean_code/clean_iocs_v2.py
```

> 一次清洗所有 org，已清洗過的不會重複處理。輸出在 `org_iocs_cleaned/{org}/iocs.json`。

### Step 2：擷取 VT Relationships

```bash
uv run python scripts/fetch_vt_relationships.py --org APT18
```

> 從 `VT_results/` 讀取 IoC，查詢每個 file/domain/ip 的 VT 關聯資料，輸出到 `vt_relationships/`。
> 支援斷點續傳，中途中斷後重跑會自動跳過已快取的項目。

### Step 3：建構知識圖譜

```bash
uv run python scripts/build_knowledge_graph.py --org APT18
```

> Phase 1：查詢每個 L0 IoC 的 VT Details（metadata、偵測率、PE 資訊等）。
> Phase 2：載入 VT Relationships，展開 L1 節點並查詢其 VT Details。
> 輸出：`knowledge_graphs/APT18/APT18.json`

> ⚠️ 若要從現有快取重建圖譜（不呼叫 VT API）：
> ```bash
> uv run python scripts/build_knowledge_graph.py --org APT18 --skip-query
> ```

### Step 4：合併進 Master KG

```bash
uv run python scripts/merge_knowledge_graphs.py
```

> 自動偵測所有 `knowledge_graphs/{org}/{org}.json`，合併輸出至 `knowledge_graphs/master/`。

---

## 系統架構

### 完整 Pipeline

```
                        ┌──────────────────┐
                        │  CTI Reports     │
                        └────────┬─────────┘
                                 ▼
                    ┌────────────────────────┐
                    │  IoC 提取 → org_iocs/  │
                    └────────────┬───────────┘
                                 ▼
               ┌─────────────────────────────────┐
               │  IoC 清洗 (clean_iocs_v2.py)    │
               │  defang還原 / 跨hash合併 /       │
               │  URL-IP合併 / 黑名單過濾         │
               │           → org_iocs_cleaned/   │
               └─────────────────┬───────────────┘
                                 ▼
                                 │
                    ┌────────────┴────────────┐
                    ▼                         ▼
     ┌───────────────────────────┐  ┌──────────────────────────────┐
     │ VT Relationship API       │  │  build_knowledge_graph.py    │
     │ (fetch_vt_relationships)  │  │  Phase 1: IoC + VT Details   │
     │   → vt_relationships/     │  │  Phase 2: VT Relationships   │
     └─────────────┬─────────────┘  │  （自行查詢 VT Details API）   │
                   └──────────────▶ │     → knowledge_graphs/      │
                                    └──────────────┬───────────────┘
                           ▼
            ┌──────────────────────────────┐
            │  merge_knowledge_graphs.py   │
            │  跨組織合併 + SQLite 輸出      │
            │     → knowledge_graphs/      │
            │       master/                │
            └──────────────┬───────────────┘
                           ▼
            ┌──────────────────────────────┐
            │  ML Attribution              │
            │  Honest Split + Fold-aware L5│
            │  Calibration + Abstain       │
            └──────────────────────────────┘
```

### 兩層知識圖譜

- **Layer 1**：CTI 報告提取的 IoC（`apt --has_ioc--> file/domain/ip/email`）
- **Layer 2**：VT Relationship API 發現的關聯（11 種邊類型）

> `depth` 欄位區分層級：`null` / `0` = Layer 1（原始 IoC），`1` = Layer 2（relationship 發現的第三層節點）

---

### 節點類型（5 種）

#### 1. APT 節點

| 項目 | 值 |
|------|------|
| **ID 格式** | `apt_{name}`（如 `apt_APT18`） |
| **VT 查詢** | ✗ |
| **說明** | 每個圖譜有且只有 1 個 APT 根節點 |

| Attribute | 型別 | 說明 |
|-----------|------|------|
| `name` | `string` | APT 組織名稱 |

#### 2. File 節點

| 項目 | 值 |
|------|------|
| **ID 格式** | `file_{sha256}`（Canonical ID，即使原始 IoC 是 MD5/SHA-1，經 VT 查詢後正規化為 SHA-256） |
| **VT 查詢** | ✓（`/api/v3/files/{hash}`） |
| **說明** | 惡意檔案樣本，來自 CTI 報告或 VT Relationship 發現 |

| 分類 | Attribute | 型別 | 說明 |
|------|-----------|------|------|
| **雜湊** | `md5` | `string \| null` | MD5 雜湊 |
| | `sha1` | `string \| null` | SHA-1 雜湊 |
| | `sha256` | `string \| null` | SHA-256 雜湊 |
| | `vhash` | `string \| null` | VirusTotal 模糊雜湊 |
| | `ssdeep` | `string \| null` | ssdeep 模糊雜湊 |
| | `tlsh` | `string \| null` | TLSH 模糊雜湊 |
| | `authentihash` | `string \| null` | PE Authenticode 雜湊 |
| **偵測統計** | `malicious` | `int` | 判定為惡意的引擎數 |
| | `suspicious` | `int` | 判定為可疑的引擎數 |
| | `harmless` | `int` | 判定為無害的引擎數 |
| | `undetected` | `int` | 未偵測的引擎數 |
| | `total_engines` | `int` | 參與分析的引擎總數 |
| | `detection_ratio` | `float` | 偵測率（`malicious / total_engines`） |
| | `reputation` | `int \| null` | VT 社群信譽分數 |
| **檔案屬性** | `size` | `int \| null` | 檔案大小（bytes） |
| | `type_tag` | `string \| null` | 檔案類型標籤（如 `peexe`） |
| | `type_description` | `string \| null` | 檔案類型描述（如 `Win32 EXE`） |
| | `magic` | `string \| null` | Magic 字串（如 `PE32 executable ...`） |
| | `magika` | `string \| null` | Google Magika 識別結果 |
| | `packers` | `object \| null` | 封裝偵測（key = 引擎名，value = 結果） |
| | `names` | `string[]` | 檔案已知名稱列表 |
| | `meaningful_name` | `string \| null` | VT 推斷的有意義檔名 |
| | `tags` | `string[]` | VT 標籤（如 `["peexe", "long-sleeps"]`） |
| | `type_extension` | `string \| null` | 推斷副檔名 |
| | `type_tags` | `string[]` | 檔案類型標籤列表 |
| **時間戳** | `creation_time` | `string \| null` | PE 編譯時間（ISO 8601 UTC） |
| | `first_seen_itw` | `string \| null` | 首次在野外發現時間 |
| | `first_submission` | `string \| null` | 首次提交至 VT 時間 |
| | `last_submission` | `string \| null` | 最後提交至 VT 時間 |
| | `last_analysis` | `string \| null` | 最後分析時間 |
| **提交統計** | `times_submitted` | `int \| null` | 被提交次數 |
| | `unique_sources` | `int \| null` | 不重複提交來源數 |
| | `total_votes` | `object` | 社群投票（`{"harmless": n, "malicious": n}`） |
| **檔案識別** | `trid` | `array` | TrID 識別結果（`[{"file_type": "...", "probability": n}]`） |
| | `detectiteasy` | `array` | Detect It Easy 結果（`[{"type": "...", "name": "...", "version": "..."}]`） |
| **威脅分類** | `popular_threat_classification` | `object \| null` | VT 威脅分類（`suggested_threat_label`, `popular_threat_category`, `popular_threat_name`） |
| **Bundle** | `bundle_info` | `object \| null` | ZIP/Office 內部結構（`num_children`, `type`, `extensions`, `file_types`） |
| **簽章** | `signature_verified` | `string \| null` | 簽章驗證狀態（如 `"Unsigned"`） |
| | `file_version_info` | `object \| null` | 版本資訊（`copyright`, `product`, `description`, `internal_name`, `file_version`, `verified`） |
| **PE 結構** | `pe_info` | `object \| null` | PE 資訊（非 PE 檔案為 `null`），含以下子欄位 |
| | `pe_info.imphash` | `string \| null` | Import Hash |
| | `pe_info.rich_pe_header_hash` | `string \| null` | Rich PE Header Hash |
| | `pe_info.compilation_timestamp` | `string \| null` | 編譯時間（ISO 8601） |
| | `pe_info.entry_point` | `int \| null` | 進入點位址 |
| | `pe_info.machine_type` | `int \| null` | 機器類型 |
| | `pe_info.compiler_product_versions` | `string[]` | 編譯器版本列表 |
| | `pe_info.sections` | `array` | PE sections（`name`, `virtual_address`, `virtual_size`, `raw_size`, `entropy`, `md5`, `chi2`, `flags`） |
| | `pe_info.imports` | `string[]` | 匯入的 DLL 名稱列表 |
| | `pe_info.resources` | `array` | PE 資源（`type`, `lang`, `filetype`, `entropy`, `chi2`, `sha256`） |
| | `pe_info.resource_langs` | `object` | 資源語言統計 |
| | `pe_info.resource_types` | `object` | 資源類型統計 |

#### 3. Domain 節點

| 項目 | 值 |
|------|------|
| **ID 格式** | `domain_{name}`（如 `domain_it-desktop.com`） |
| **VT 查詢** | ✓（`/api/v3/domains/{domain}`） |
| **說明** | 惡意網域，來自 CTI 報告、URL 提取，或 VT Relationship 發現 |

| 分類 | Attribute | 型別 | 說明 |
|------|-----------|------|------|
| **偵測統計** | `malicious`, `suspicious`, `harmless`, `undetected` | `int` | 同 File |
| | `total_engines`, `detection_ratio`, `reputation` | `int` / `float` | 同 File |
| | `total_votes` | `object` | 同 File |
| **網域屬性** | `registrar` | `string \| null` | 註冊商（子域名可能為 null） |
| | `tld` | `string \| null` | 頂級域名 |
| | `creation_date` | `string \| null` | 網域建立日期（ISO 8601） |
| | `last_update_date` | `string \| null` | 最後更新日期 |
| | `last_analysis` | `string \| null` | 最後分析日期 |
| | `categories` | `object` | 各資安廠商分類（`{"Sophos": "spyware and malware"}`） |
| | `tags` | `string[]` | VT 標籤 |
| | `popularity_ranks` | `object` | 各排名系統的排名與時間戳 |
| **WHOIS** | `has_whois` | `bool` | 是否有 WHOIS 記錄 |
| | `whois` | `string \| null` | 完整 WHOIS 原始文字 |
| **DNS** | `last_dns_records` | `array` | DNS 記錄（`[{"type": "A", "value": "1.2.3.4", "ttl": 300}]`） |
| | `last_dns_records_date` | `string \| null` | DNS 記錄查詢日期 |
| **憑證 / TLS** | `jarm` | `string \| null` | JARM TLS 指紋 |
| | `last_https_certificate` | `object \| null` | HTTPS 憑證（`thumbprint`, `serial_number`, `issuer`, `subject`, `validity`, `subject_alternative_name`） |
| **社群情資** | `crowdsourced_context` | `array` | VT 社群情資標註 |

#### 4. IP 節點

| 項目 | 值 |
|------|------|
| **ID 格式** | `ip_{addr}`（如 `ip_20.62.24.77`） |
| **VT 查詢** | ✓（`/api/v3/ip_addresses/{ip}`） |
| **說明** | IP 位址，來自 CTI 報告或 VT Relationship 發現。RFC 1918 私有 IP 已於 Layer 2 展開時過濾 |

| 分類 | Attribute | 型別 | 說明 |
|------|-----------|------|------|
| **偵測統計** | `malicious`, `suspicious`, `harmless`, `undetected` | `int` | 同 File |
| | `total_engines`, `detection_ratio`, `reputation` | `int` / `float` | 同 File |
| | `total_votes` | `object` | 同 File |
| **網路屬性** | `country` | `string \| null` | 國家代碼（ISO 3166-1 alpha-2） |
| | `continent` | `string \| null` | 洲代碼（如 `NA`） |
| | `asn` | `int \| null` | 自治系統編號 |
| | `as_owner` | `string \| null` | AS 擁有者名稱 |
| | `network` | `string \| null` | CIDR 網段（如 `20.48.0.0/12`） |
| | `regional_internet_registry` | `string \| null` | 區域網路註冊機構（如 `ARIN`） |
| | `tags` | `string[]` | VT 標籤 |
| **WHOIS** | `whois` | `string \| null` | IP WHOIS 原始文字 |
| **憑證 / TLS** | `jarm` | `string \| null` | JARM TLS 指紋 |
| | `last_https_certificate` | `object \| null` | 同 Domain |
| **社群情資** | `crowdsourced_context` | `array` | VT 社群情資標註 |

#### 5. Email 節點

| 項目 | 值 |
|------|------|
| **ID 格式** | `email_{address}`（如 `email_attacker@example.com`） |
| **VT 查詢** | ✗ |
| **說明** | 保留社交工程脈絡，不查 VT |

| Attribute | 型別 | 說明 |
|-----------|------|------|
| `value` | `string` | Email 地址 |

---

### 邊類型（11 種 + 8 種保留）

#### Layer 1 — `has_ioc`

| 項目 | 值 |
|------|------|
| **方向** | `apt` → `file` / `domain` / `ip` / `email` |
| **說明** | CTI 報告中記載的 IoC 關聯 |
| **合併機制** | 同一 `(source, target)` pair 只產生 1 條邊，多個 IoC 合併至 attributes 的平行陣列 |

| Edge Attribute | 型別 | 說明 |
|----------------|------|------|
| `ioc_original_types` | `string[]` | 原始 IoC 類型（如 `["md5", "sha256"]`），與 `values` 為平行陣列 |
| `ioc_original_values` | `string[]` | 原始 IoC 值（URL 完整路徑保留於此） |
| `source_reports` | `string[]` | 來源報告 URL 列表（去重） |

#### Layer 2 — VT Relationship 邊（11 種活躍）

**共用 Edge Attributes**（由 `_extract_edge_attrs()` 提取，依資料來源可能為空）：

| Edge Attribute | 型別 | 適用邊類型 | 說明 |
|----------------|------|-----------|------|
| `resolution_date` | `string` (ISO 8601) | `resolves_to` | DNS 解析日期 |
| `malicious` | `int` | 所有含 `last_analysis_stats` 的邊 | 目標節點的惡意偵測引擎數 |
| `undetected` | `int` | 同上 | 目標節點的未偵測引擎數 |
| `last_analysis_date` | `string` (ISO 8601) | 同上 | 目標節點最後分析日期 |
| `type_tag` | `string` | `dropped_file` | 釋放檔案的類型標籤（如 `peexe`） |
| `type_description` | `string` | `dropped_file` | 釋放檔案的類型描述（如 `Win32 EXE`） |
| `meaningful_name` | `string` | `dropped_file` | 釋放檔案的有意義檔名 |

**File → Network（沙箱動態行為）：**

| 邊類型 | 方向 | 說明 | 資料來源 |
|--------|------|------|---------|
| `contacted_ip` | `file` → `ip` | 檔案執行時連線的 IP | VT sandbox 行為分析 |
| `contacted_domain` | `file` → `domain` | 檔案執行時連線的 Domain | VT sandbox 行為分析 |
| `contacted_url` | `file` → `domain` | 檔案執行時連線的 URL（提取 domain 建節點） | VT sandbox 行為分析 |

**File → File（衍生關係）：**

| 邊類型 | 方向 | 說明 | 資料來源 |
|--------|------|------|---------|
| `dropped_file` | `file` → `file` | 檔案執行後釋放的子檔案 | VT sandbox 行為分析 |
| `execution_parent` | `file` → `file` | 檔案的執行父檔案（誰執行了這個檔案） | VT 行為分析 |
| `bundled_file` | `file` → `file` | 封裝/壓縮檔內包含的子檔案 | VT 靜態分析 |

**DNS：**

| 邊類型 | 方向 | 說明 | 資料來源 |
|--------|------|------|---------|
| `resolves_to` | `domain` ↔ `ip` | DNS A record 解析歷史（雙向） | VT passive DNS |
| `has_subdomain` | `domain` → `domain` | 子域名關係 | VT DNS 記錄 |

**反向關聯（Domain/IP → File）：**

| 邊類型 | 方向 | 說明 | 資料來源 |
|--------|------|------|---------|
| `communicating_file` | `domain`/`ip` → `file` | 與該 domain/IP 通訊的惡意檔案 | VT 通訊記錄 |
| `referrer_file` | `domain`/`ip` → `file` | 在內容中引用該 domain/IP 的檔案 | VT 參照記錄 |

#### 保留邊類型（8 種，程式碼中已定義處理邏輯，但目前不產生資料）

> 以下邊類型在 `build_knowledge_graph.py` 中保留了處理邏輯，但 `fetch_vt_relationships.py` 因 VT academic plan 權限限制（403）而未擷取資料。未來升級 API 方案後可自動啟用。

| 邊類型 | 方向 | 說明 |
|--------|------|------|
| `embedded_domain` | `file` → `domain` | 靜態分析中嵌入的 domain 字串 |
| `embedded_ip` | `file` → `ip` | 靜態分析中嵌入的 IP 字串 |
| `embedded_url` | `file` → `domain` | 靜態分析中嵌入的 URL（提取 domain） |
| `itw_domain` | `file` → `domain` | In-the-Wild 分佈點 domain |
| `itw_ip` | `file` → `ip` | In-the-Wild 分佈點 IP |
| `itw_url` | `file` → `domain` | In-the-Wild 分佈點 URL（提取 domain） |
| `downloaded_file` | `domain`/`ip` → `file` | 從該 domain/IP 下載的檔案（Enterprise API） |
| `compressed_parent` | `file` → `file` | 壓縮檔父檔案 |

## 環境設置

**需求：** Python 3.11+, [uv](https://github.com/astral-sh/uv)

```bash
# 安裝依賴
uv sync

# 設定 VT API Key
echo 'VT_API_KEY=your_key_here' > .env
```

## 使用方式

### 1. IoC 清洗

```bash
uv run python ioc_clean_code/clean_iocs_v2.py
# 輸入: org_iocs/{org}/iocs.json
# 輸出: org_iocs_cleaned/{org}/iocs.json + cleaning_stats.json
```

清洗 Pipeline 共 8 步，依序處理：

```
Step 1: Type Filter
  ↓  僅保留 ipv4, ipv6, domain, url, md5, sha1, sha256, email 八種類型，其餘丟棄
Step 2: Normalize（Refang + 小寫 + URL domain 提取）
  ↓  還原 defanged IoC：hxxp:// → http://, [.] → ., [:] → :, [at] → @
  ↓  所有值轉小寫以利比對；URL 類型額外提取 domain 欄位
Step 3: Email Filter
  ↓  移除政府/資安廠商聯絡信箱等噪音，僅保留攻擊者相關 email
  ↓  已知攻擊者常用：mail.com, protonmail.com, tutanota.com, yandex.*, mail.ru 等
  ↓  若 domain 在黑名單中 → 移除；未知 domain → 保留（可能為攻擊者基礎設施）
Step 4: Dedup + Source Merge
  ↓  以 (type, normalized_value) 為 key 去重
  ↓  重複 IoC 的 sources 列表合併（保留所有出處報告 URL）
Step 5: Cross-Hash Merge
  ↓  同一檔案若以 MD5/SHA-1/SHA-256 三種 hash 出現，合併為一筆
  ↓  透過 VT file_info 中的交叉雜湊識別同一檔案
  ↓  以 SHA-256 為 canonical type，其餘 hash 保留於 alt_hashes
Step 6: URL-IP Collapse
  ↓  http://1.2.3.4/path 或 http://[::1]/path 形式的 URL → 轉為 ipv4/ipv6 類型
  ↓  若該 IP 已存在 → 合併 sources；否則新建 IP 紀錄
Step 7: Domain / IP Blacklist Filter
  ↓  移除私有/保留 IP：IPv4 RFC 1918（10.x, 172.16-31.x, 192.168.x）、
  ↓    IPv6 loopback（::1）、link-local（fe80::）、ULA（fd00::）等
  ↓  移除 eTLD+1 黑名單 domain（~50 個），涵蓋：
  ↓    • 新聞媒體：bbc.com, cnn.com, reuters.com 等
  ↓    • 大型平台：google.com, microsoft.com, github.com, twitter.com 等
  ↓    • 資安廠商：fireeye.com, kaspersky.com, crowdstrike.com 等（報告來源非 IoC）
  ↓    • CDN/雲端：amazonaws.com, cloudflare.com, azure.com 等（過於泛用會產生超級節點）
  ↓    • 政府機構：us-cert.gov, cisa.gov, nist.gov 等
  ↓  例外：DDNS 服務（no-ip.com, dyndns.org 等 ~20 個）即使符合黑名單也保留
  ↓        （APT 常濫用 DDNS 作為 C2）
Step 8: Orphan Check
     標記無 source 歸屬的 IoC（不影響輸出，僅記錄於 cleaning_stats.json）
```

每次執行會產出 `cleaning_stats.json`，記錄各步驟的處理數量，確保可重現性。

### 2. VT 資料擷取

```bash
# VT Relationships（file/domain/ip 的關聯發現）
uv run python scripts/fetch_vt_relationships.py --org APT18
```

> `fetch_vt_metadata.py` 已被 `build_knowledge_graph.py` 取代（Phase 1 自行查詢 VT Details API），`VT_results/` 為舊版產出。

> ⚠️ VT Academic Plan 限制：20,000 req/min，20,000 lookups/day，620,000 lookups/month。腳本內建速率控制與 429 自動重試。

### 3. 建構知識圖譜

```bash
# 完整建構（Phase 1 + Phase 2 + VT 查詢）
uv run python scripts/build_knowledge_graph.py --org APT18

# 跳過 VT 查詢，從快取重建
uv run python scripts/build_knowledge_graph.py --org APT18 --skip-query

# 含視覺化
uv run python scripts/build_knowledge_graph.py --org APT18 --visualize
```

### 4. 合併知識圖譜

```bash
# 自動偵測所有已完成的 KG 並合併
uv run python scripts/merge_knowledge_graphs.py

# 指定組織
uv run python scripts/merge_knowledge_graphs.py --orgs APT18,APT19 --visualize
```
\
輸出 JSON + SQLite 資料庫，支援 SQL 查詢：

```sql
-- 找出跨組織共用的 IoC
SELECT node_id, GROUP_CONCAT(org) FROM node_orgs
GROUP BY node_id HAVING COUNT(DISTINCT org) > 1;

-- 查看高偵測率的惡意檔案
SELECT id, json_extract(attributes, '$.malicious') as mal
FROM nodes WHERE type='file' AND json_extract(attributes, '$.malicious') > 50;

-- 特定 APT 的 C2 基礎設施
SELECT e.target, n.type, json_extract(n.attributes, '$.malicious') as mal
FROM edges e JOIN nodes n ON e.target = n.id
WHERE e.org = 'APT18' AND e.relationship = 'contacted_ip';
```

### 5. 驗證

```bash
uv run python scripts/eval_groupkfold_ablation.py --l4-mode off
uv run python scripts/eval_groupkfold_ttp.py --l4-mode off
uv run python scripts/model/calibrate_probs.py
uv run python scripts/evaluate_selective.py
uv run python scripts/evaluate_openset.py
uv run python scripts/eval_false_flag.py
```

## 目錄結構

```
├── scripts/                              # 主要腳本
│   │
│   │  # ── KG 建構 Pipeline ──
│   ├── build_knowledge_graph.py          # KG 建構（Phase 1 + 2 + VT Details）
│   ├── merge_knowledge_graphs.py         # 跨組織 KG 合併
│   ├── fetch_vt_relationships.py         # VT Relationship API 擷取
│   ├── feasibility_analysis.py           # 歸因可行性分析（7 部分）
│   │
│   │  # ── 歸因系統：訓練 ──
│   ├── build_vocabularies.py             # Vocabulary 預建構
│   ├── build_features.py                 # L1+L2+L3+L4 特徵提取（209d）
│   ├── train_node2vec.py                 # Node2Vec 嵌入訓練（64d）
│   ├── train_classifier.py               # XGBoost/RF/MLP 消融實驗
│   ├── train_and_save_model.py           # 訓練最終模型並存檔
│   ├── split_utils.py                    # report-connected split + leak check
│   │
│   │  # ── 歸因系統：推論 ──
│   ├── inference.py                      # 單筆/批次 IoC 歸因（calibrated + abstain）
│   │
│   │  # ── 歸因系統：評估 ──
│   ├── eval_groupkfold_ablation.py       # L1-L4 消融（含 --l4-mode）
│   ├── eval_groupkfold_ttp.py            # L5 fold-aware/legacy 比較（含 --l4-mode）
│   ├── evaluate_selective.py             # coverage-risk curve + AURC
│   ├── evaluate_openset.py               # actor holdout open-set 評估
│   ├── eval_false_flag.py                # 偽旗攻擊韌性評估
│   ├── eval_multisignal_fusion.py        # 多信號融合評估
│   ├── eval_ttp_tiebreak.py              # TTP tie-breaking 評估
│   ├── eval_infra_discovery.py           # 歸因後基礎設施探索評估
│   ├── eval_edge_type_analysis.py        # edge type 歸因力分析
│   ├── eval_noise_filter_sweep.py        # noise filter / confidence 分析
│   ├── eval_overlap_by_report.py         # overlap report-level 分析
│   │
│   │  # ── TTP Pipeline ──
│   ├── ttp_extraction/build_ioc_ttp_mapping.py
│   ├── ttp_extraction/build_source_quality_table.py
│   ├── build_ttp_features.py
│   │
│   │  # ── 模型與校準輸出 ──
│   ├── model/                            # 訓練好的模型
│   │   ├── xgboost_model.json           # XGBoost 模型
│   │   ├── imputer.pkl                  # SimpleImputer
│   │   ├── label_encoder.pkl            # LabelEncoder（15 orgs）
│   │   ├── config.json                  # org_list, feature_names, threshold
│   │   ├── calibrator.pkl               # temperature scaling calibrator
│   │   ├── calibration_metrics.json     # ECE/Brier 前後比較
│   │   └── calibration_data.npz         # selective/open-set 評估資料
│   ├── features/                         # 特徵矩陣
│   │   ├── features_all.npz             # 全四層特徵（5961×209）
│   │   ├── node2vec_embeddings.npz      # Node2Vec 嵌入（64736×64）
│   │   └── feature_names.json           # 特徵名稱與 org 列表
│   ├── results/                          # 實驗結果
│   │   ├── eval_groupkfold_ablation.json
│   │   ├── eval_groupkfold_ttp.json
│   │   ├── evaluate_selective.json
│   │   ├── evaluate_openset.json
│   │   ├── eval_false_flag.json
│   │   ├── eval_multisignal_fusion.json
│   │   ├── eval_ttp_tiebreak.json
│   │   └── eval_infra_discovery.json
│   │
│   ├── batch_visualize.py                # 批次產出 KG 視覺化 PNG
│   └── fetch_vt_metadata.py              # （舊版，已被 build_knowledge_graph.py 取代）
│
├── ioc_clean_code/                       # IoC 清洗腳本
│   └── clean_iocs_v2.py                  # v2 清洗（跨hash合併、URL-IP collapse 等）
│
├── org_iocs/                             # 原始 IoC 提取（150+ APT 組織）
├── org_iocs_cleaned/                     # 清洗後 IoC + 統計
├── VT_results/                           # VT Details API 回應快取（舊版）
├── vt_relationships/                     # VT Relationship API 資料
├── knowledge_graphs/                     # 產出的知識圖譜
│   ├── {org}/{org}.json                  # 單一組織 KG
│   ├── {org}/{org}_graph.png            # 單一組織 KG 視覺化
│   ├── {org}/{org}_vt_cache.json        # VT 查詢快取（斷點續傳）
│   └── master/                           # 合併資料庫
│       ├── merged_kg.json               # NetworkX node_link_graph 格式
│       └── merged_kg.db                 # SQLite（nodes, edges, node_orgs）
│
├── _碩士論文__黃廷翰_/                    # 論文 LaTeX 文件
└── 文獻/                                 # 參考文獻
```

## 核心依賴

| 套件 | 用途 |
|------|------|
| `requests` | VT API 呼叫 |
| `python-dotenv` | 環境變數（API Key） |
| `networkx` | 圖資料結構 |
| `xgboost` | 歸因分類器（主力） |
| `scikit-learn` | ML Pipeline（CV, imputer, metrics） |
| `node2vec` | 圖嵌入（Layer 4） |
| `shap` | 模型可解釋性分析 |
| `matplotlib` | 圖譜視覺化 |
| `numpy`, `scipy` | 數值運算 |

## 詳細文件

- [知識圖譜 Schema 與 SQL 查詢範例](knowledge_graphs/README.md)
- [IoC 清洗規則說明](org_iocs_cleaned/README.md)
- [clean_iocs_v2 修改說明](ioc_clean_code/clean_iocs_v2_changelog.md)
