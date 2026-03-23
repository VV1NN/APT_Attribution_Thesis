# APT 威脅情資知識圖譜建構與歸因系統

> 碩士論文研究專案 — 自動化建構 APT 組織知識圖譜，基於 VirusTotal 豐富化與多源 IoC 整合，支援後續機器學習歸因分析。

## 研究目標

1. 從公開 CTI（Cyber Threat Intelligence）報告中提取 IoC（Indicators of Compromise）
2. 透過 VirusTotal API 進行兩層式豐富化，建構完整的 APT 知識圖譜
3. 合併多組織圖譜為統一資料庫，發現跨 APT 共享基礎設施
4. 設計機器學習方法進行 APT 歸因（attribution）

## 資料規模

- **涵蓋 APT 組織**：150+ 組織（org_iocs/ 內含已提取 IoC）
- **已建構知識圖譜**：APT12, APT16, APT17, APT18, APT19
- **已合併統一圖譜**：230 nodes, 338 edges（APT18 + APT19）
- **VT 關聯資料**：已擷取 10+ 組織的 VT Relationship 資料

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
          ┌──────────────────────┴──────────────────────┐
          ▼                                             ▼
┌──────────────────────┐                 ┌───────────────────────────┐
│ VT Details API       │                 │ VT Relationship API       │
│ (fetch_vt_metadata)  │                 │ (fetch_vt_relationships)  │
│   → VT_results/      │                 │   → vt_relationships/     │
└──────────┬───────────┘                 └─────────────┬─────────────┘
           └──────────────┬────────────────────────────┘
                          ▼
            ┌──────────────────────────────┐
            │  build_knowledge_graph.py    │
            │  Phase 1: IoC + VT Details   │
            │  Phase 2: VT Relationships   │
            │     → knowledge_graphs/      │
            └──────────────┬───────────────┘
                           ▼
            ┌──────────────────────────────┐
            │  merge_knowledge_graphs.py   │
            │  跨組織合併 + SQLite 輸出     │
            │     → knowledge_graphs/      │
            │       master/                │
            └──────────────┬───────────────┘
                           ▼
            ┌──────────────────────────────┐
            │  ML Attribution (開發中)      │
            └──────────────────────────────┘
```

### 兩層知識圖譜

| 層級 | 邊類型 | 說明 | 資料來源 |
|------|--------|------|----------|
| **Layer 1** | `has_ioc` | APT → file/domain/ip/email | CTI 報告 |
| **Layer 2** | `contacted_ip` | file → ip（沙箱行為） | VT Sandbox |
| | `contacted_domain` | file → domain（沙箱行為） | VT Sandbox |
| | `dropped_file` | file → file（釋放檔案） | VT Sandbox |
| | `resolves_to` | domain ↔ ip（DNS 解析） | VT Passive DNS |

### 節點類型

| 類型 | ID 格式 | VT 查詢 | 主要特徵 |
|------|---------|---------|----------|
| `apt` | `apt_{name}` | ✗ | 根節點 |
| `file` | `file_{sha256}` | ✓ | detection_ratio, PE info, hashes |
| `domain` | `domain_{name}` | ✓ | registrar, DNS, TLS/JARM |
| `ip` | `ip_{addr}` | ✓ | ASN, geolocation, network |
| `email` | `email_{addr}` | ✗ | 保留社交工程脈絡 |

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

清洗步驟：type filter → refang → email filter → dedup（合併 sources）→ cross-hash merge → URL-IP collapse → blacklist filter

### 2. VT 資料擷取

```bash
# VT Details（每個 IoC 的完整 metadata）
uv run python scripts/fetch_vt_metadata.py --org APT18

# VT Relationships（file/domain/ip 的關聯發現）
uv run python scripts/fetch_vt_relationships.py --org APT18
```

> ⚠️ VT Academic Plan 限制：4 req/min，約 5,800 lookups/day。腳本內建 15 秒間隔與 429 自動重試。

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
├── scripts/                      # 主要 pipeline 腳本
│   ├── build_knowledge_graph.py  # 知識圖譜建構（Phase 1 + 2）
│   ├── merge_knowledge_graphs.py # 跨組織圖譜合併
│   ├── fetch_vt_metadata.py      # VT Details API 擷取
│   ├── fetch_vt_relationships.py # VT Relationship API 擷取
│   ├── run_validation.py         # 資料驗證套件
│   ├── run_experiments.py        # 實驗執行
│   └── visualize_prototype.py    # 視覺化原型
│
├── ioc_clean_code/               # IoC 清洗腳本
│   └── clean_iocs_v2.py          # v2 清洗（跨hash合併、URL-IP collapse 等）
│
├── org_iocs/                     # 原始 IoC 提取（150+ APT 組織）
├── org_iocs_cleaned/             # 清洗後 IoC + 統計
├── VT_results/                   # VT Details API 回應快取
├── vt_relationships/             # VT Relationship API 資料
├── knowledge_graphs/             # 產出的知識圖譜
│   ├── {org}/{org}.json          # 單一組織 KG
│   ├── {org}/{org}_vt_cache.json # VT 查詢快取（斷點續傳）
│   └── master/                   # 合併資料庫（JSON + SQLite）
│
├── _碩士論文__黃廷翰_/            # 論文 LaTeX 文件
├── 文獻/                         # 參考文獻
└── archive/                      # 舊版程式碼
```

## 核心依賴

| 套件 | 用途 |
|------|------|
| `requests` | VT API 呼叫 |
| `python-dotenv` | 環境變數（API Key） |
| `networkx` | 圖資料結構 |
| `pandas` | 資料處理 |
| `scikit-learn` | ML 分析 |
| `matplotlib` | 圖譜視覺化 |

## 詳細文件

- [知識圖譜 Schema 與 SQL 查詢範例](knowledge_graphs/README.md)
- [IoC 清洗規則說明](org_iocs_cleaned/README.md)
- [clean_iocs_v2 修改說明](ioc_clean_code/clean_iocs_v2_changelog.md)
