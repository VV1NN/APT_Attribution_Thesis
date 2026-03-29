# APT 威脅情資知識圖譜建構與歸因系統

> 碩士論文研究專案 — 自動化建構 APT 組織知識圖譜，基於 VirusTotal 豐富化與多源 IoC 整合，透過四層特徵工程 + XGBoost 實現 APT 歸因。

## 研究目標

1. 從公開 CTI（Cyber Threat Intelligence）報告中提取 IoC（Indicators of Compromise）
2. 透過 VirusTotal API 進行兩層式豐富化，建構完整的 APT 知識圖譜
3. 合併多組織圖譜為統一資料庫，發現跨 APT 共享基礎設施
4. 基於四層特徵工程（VT Metadata + 鄰域統計 + Overlap Detection + Node2Vec）實現 APT 歸因

## 主要成果

- **Master KG（21 orgs）**：66,444 nodes / 109,443 edges
- **歸因模型**：Micro-F1 = **76.4%**, Top-5 = **92.6%**（15 個 major APT, 5,961 L0 IoCs, 5-fold CV）
- **Simulated Inference**：Micro-F1 = 52.1%–76.4%（下界–上界）

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

## 歸因系統

### 方法架構

```
未知 IoC → VT 查詢 → 子圖展開 → 四層特徵提取 → XGBoost → Top-K APT 預測
```

四層特徵各自捕捉不同的歸因信號：

| Layer | 名稱 | 維度 | 核心問題 |
|-------|------|------|---------|
| L1 | 節點自身特徵 | 88d | 這個 IoC 本身的技術屬性像哪個 APT？ |
| L2 | 鄰域統計 | 35d | 它的鄰居行為模式像哪個 APT？ |
| L3 | Overlap Detection | 22d | 它的鄰居有沒有已知屬於某 APT？ |
| L4 | Node2Vec | 64d | 它在拓撲空間中離哪個 APT cluster 最近？ |

### 實驗結果

評估方式：ALL-nodes overlap dict + per-fold test IoC 移除 + 不做 exclude_org（最接近真實推論的 CV 設定）。
訓練：5,961 筆 L0 IoC / 15 APT orgs / XGBoost / 5-fold Stratified CV。

| 指標 | 無門檻 | 信心度門檻 0.3 |
|------|--------|--------------|
| Coverage | 100% | 81.1% |
| Micro-F1 | **80.0%** | **95.7%** |
| Macro-F1 | 81.8% | 95.2% |
| Top-3 | 90.1% | — |
| Top-5 | 93.3% | — |

信心度門檻曲線（分析師可依需求調整）：

| 門檻 | Coverage | Micro-F1 | 適用場景 |
|------|----------|----------|---------|
| 0.15 | 90.3% | 87.2% | 寬鬆：盡量不遺漏 |
| 0.30 | 81.1% | 95.7% | 推薦：精準與覆蓋的平衡 |
| 0.50 | 78.8% | 97.7% | 保守：高信心才歸因 |
| 0.70 | 76.7% | 99.0% | 鑑識等級 |

### 對未知 IoC 歸因

```bash
# 首次使用：訓練模型（只需跑一次）
uv run python scripts/build_vocabularies.py
uv run python scripts/train_node2vec.py
uv run python scripts/train_and_save_model.py

# 歸因單一 IoC（需 VT API Key）
uv run python scripts/inference.py d54fa56f1a0b1b63c4e8fa1cc170...

# 歸因結果範例：
#   #1  APT28        72.3%  ████████████████████ ←
#   #2  Sandworm      8.1%  ██
#   #3  APT29         5.2%  █
#   ✅ 歸因結果：APT28（信心度 72.3% ≥ 門檻 30%）
#   Overlap: 75% 鄰居匹配, 2 候選 org

# 批次歸因
uv run python scripts/inference.py --file suspicious_iocs.txt

# JSON 輸出（供自動化串接）
uv run python scripts/inference.py --json 185.45.67.89
```

### 訓練 Pipeline（重新訓練或更新模型）

```bash
# Step 1: 建立 vocabulary
uv run python scripts/build_vocabularies.py

# Step 2: 訓練 Node2Vec 嵌入
uv run python scripts/train_node2vec.py

# Step 3: 提取四層特徵 + 存檔
uv run python scripts/build_features.py

# Step 4: 消融實驗（4 exp × 3 clf × 5-fold = 60 runs）
uv run python scripts/train_classifier.py

# Step 5: 存出最終模型
uv run python scripts/train_and_save_model.py

# Step 6: SHAP 可解釋性分析
uv run python scripts/run_shap_analysis.py

# Step 7: 信心度門檻分析
uv run python scripts/eval_confidence_threshold.py
```

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
            │  四層特徵 + XGBoost          │
            │  Micro-F1 = 76.4%           │
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
uv run python scripts/run_validation.py
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
│   ├── build_features.py                 # 四層特徵提取（L1+L2+L3+L4, 209d）
│   ├── train_node2vec.py                 # Node2Vec 嵌入訓練（64d）
│   ├── train_classifier.py               # XGBoost/RF/MLP 消融實驗
│   ├── train_and_save_model.py           # 訓練最終模型並存檔
│   │
│   │  # ── 歸因系統：推論 ──
│   ├── inference.py                      # 單筆/批次 IoC 歸因（VT API → 特徵 → Top-K）
│   │
│   │  # ── 歸因系統：評估 ──
│   ├── run_shap_analysis.py              # SHAP 特徵重要性分析
│   ├── eval_confidence_threshold.py      # 信心度門檻分析
│   ├── eval_simulated_inference.py       # Simulated inference 評估
│   ├── eval_correct_cv.py               # Per-fold removal CV（L0-only dict）
│   ├── eval_allnodes_correct_cv.py      # Per-fold removal CV（ALL-nodes dict）
│   │
│   │  # ── 產出檔案 ──
│   ├── model/                            # 訓練好的模型
│   │   ├── xgboost_model.json           # XGBoost 模型
│   │   ├── imputer.pkl                  # SimpleImputer
│   │   ├── label_encoder.pkl            # LabelEncoder（15 orgs）
│   │   └── config.json                  # org_list, feature_names, threshold
│   ├── features/                         # 特徵矩陣
│   │   ├── features_all.npz             # 全四層特徵（5961×209）
│   │   ├── node2vec_embeddings.npz      # Node2Vec 嵌入（64736×64）
│   │   └── feature_names.json           # 特徵名稱與 org 列表
│   ├── results/                          # 實驗結果
│   │   ├── results_ablation.json        # 消融實驗（4 exp × 3 clf）
│   │   ├── shap_analysis.json           # SHAP 全域/per-class 分析
│   │   ├── confidence_threshold.json    # 信心度門檻曲線
│   │   └── allnodes_correct_cv.json     # 正式評估結果
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
├── 文獻/                                 # 參考文獻
└── archive/                              # 舊版程式碼
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
