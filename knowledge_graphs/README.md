# Knowledge Graphs — APT 威脅情資知識圖譜

本目錄存放以 VirusTotal (VT) API 豐富化的 APT 組織知識圖譜。
每個組織建構**兩層完整圖譜**：Layer 1（原始 IoC + VT Details）及 Layer 2（VT Relationship 發現的關聯節點 + VT Details）。

---

## 目錄結構

```
knowledge_graphs/
├── README.md                  ← 本文件
├── APT18/
│   ├── APT18.json             ← APT18 知識圖譜（108 nodes, 112 edges）
│   ├── APT18_vt_cache.json    ← VT API 查詢快取（斷點續傳）
│   └── APT18_graph.png        ← 視覺化
├── APT19/
│   ├── APT19.json             ← APT19 知識圖譜（122 nodes, 226 edges）
│   ├── APT19_vt_cache.json
│   └── APT19_graph.png
├── master/                    ← 合併資料庫（跨組織統一圖譜）
│   ├── merged_kg.json         ← 合併 JSON（230 nodes, 338 edges）
│   ├── merged_kg.db           ← SQLite 資料庫（可 SQL 查詢）
│   └── merged_kg.png          ← 合併視覺化
└── {org}/                     ← 其他組織（待建構）
```

---

## 已完成的圖譜

| 組織 | Nodes | Edges | Layer 1 | Layer 2 | VT Metadata | VT 404 |
|------|-------|-------|---------|---------|-------------|--------|
| APT18 | 108 | 112 | 7 (1 apt + 3 file + 3 domain) | 101 (45 file + 37 domain + 19 ip) | 84 (78%) | 23 file |
| APT19 | 122 | 226 | 28 (1 apt + 9 file + 8 domain + 3 ip + 7 email) | 94 (6 file + 19 domain + 69 ip) | 101 (83%) | 13 file |
| **合併** | **230** | **338** | — | — | **185 (80%)** | **36 file** |

> VT 404 全為 file 類型，是 VT 資料庫未收錄的樣本（dropped_files 或舊 md5 hash），屬資料源限制。

---

## 兩層圖譜架構

```
                    Phase 1                                    Phase 2
        ┌───────────────────────────┐          ┌───────────────────────────────────┐
        │   org_iocs_cleaned/       │          │   vt_relationships/{org}/         │
        │     iocs.json             │          │     files/*.json                  │
        │                           │          │     domains/*.json                │
        │   ↓ VT Details API        │          │     ips/*.json                    │
        │                           │          │                                   │
        │   Layer 1 Nodes:          │          │   ↓ 發現第二層節點                   │
        │   apt → has_ioc → IoC     │          │   ↓ VT Details API                │
        │   （每個 IoC 有 metadata）  │          │                                   │
        └───────────┬───────────────┘          │   Layer 2 Nodes:                  │
                    │                          │   IoC → relationship → IoC_2nd    │
                    │                          │   （每個也查 VT 取 metadata）       │
                    │                          └───────────────┬───────────────────┘
                    └──────────────┬────────────────────────────┘
                                  ▼
                    knowledge_graphs/{org}/{org}.json
                    knowledge_graphs/{org}/{org}_vt_cache.json
                    knowledge_graphs/{org}/{org}_graph.png (opt)
```

### Layer 1 — 原始 IoC（has_ioc 邊）

CTI 報告中記載的 IoC，經正規化後查 VT Details 取得完整 metadata。

- File hash（md5/sha1/sha256）→ canonical `file_{sha256}` 節點
- URL → 提取 domain 建 `domain_{domain}` 節點（完整 URL 保留在邊的 attributes）
- IP → `ip_{ipv4}` 節點
- Email → `email_{address}` 節點（不查 VT，保留社交工程脈絡）

### Layer 2 — VT Relationship 發現的關聯節點

從 `vt_relationships/{org}/` 讀取已擷取的 VT 關聯資料，發現 Layer 1 IoC 的鄰居節點，再查 VT Details 取 metadata。

| 邊類型 | 方向 | 說明 | 資料來源 |
|--------|------|------|---------|
| `has_ioc` | apt → file/domain/ip/email | CTI 報告中的 IoC（Layer 1） | org_iocs_cleaned |
| `contacted_ip` | file → ip | 檔案執行時連線的 IP | VT sandbox 行為分析 |
| `contacted_domain` | file → domain | 檔案執行時連線的 Domain | VT sandbox 行為分析 |
| `dropped_file` | file → file | 檔案執行後釋放的子檔案 | VT sandbox 行為分析 |
| `resolves_to` | domain ↔ ip | DNS 解析歷史紀錄（A record） | VT passive DNS |

---

## 建構腳本

### `scripts/build_knowledge_graph.py`（v2.0）

```bash
# 完整兩層建構：Phase 1（IoC Details）+ Phase 2（Relationship 節點 Details）
uv run python scripts/build_knowledge_graph.py --org APT18

# 跳過 VT 查詢，從現有 cache 重建圖譜
uv run python scripts/build_knowledge_graph.py --org APT18 --skip-query

# 含視覺化 PNG
uv run python scripts/build_knowledge_graph.py --org APT18 --visualize
```

**執行流程：**

1. **Phase 1** — 讀取 `org_iocs_cleaned/{org}/iocs.json`，對每個 IoC 查 VT Details API 取 metadata
2. **初次建圖** — 建立 Layer 1 節點 + `has_ioc` 邊
3. **Phase 2** — 從 `vt_relationships/{org}/` 發現圖譜外的第二層節點，查 VT Details API 取 metadata
4. **重建圖譜** — 包含 Layer 1 + Layer 2 所有節點與邊
5. **視覺化**（可選）

### `scripts/merge_knowledge_graphs.py`

```bash
# 自動偵測所有已完成的 KG，合併為統一資料庫
uv run python scripts/merge_knowledge_graphs.py --visualize

# 指定組織
uv run python scripts/merge_knowledge_graphs.py --orgs APT18,APT19 --visualize
```

**合併策略：**

| 項目 | 策略 |
|------|------|
| 相同 node ID | 合併為一個節點（數值取最新、清單累加去重） |
| 不同 node ID | 各自保留 |
| 邊 | 全部保留（不同 APT 指向同一節點的邊各自獨立，標記 `org` 來源） |
| 輸出 | JSON + SQLite（`master/merged_kg.json` + `master/merged_kg.db`） |

**SQLite 查詢範例：**

```sql
-- 找出跨組織共用的 IoC
SELECT node_id, GROUP_CONCAT(org) FROM node_orgs
GROUP BY node_id HAVING COUNT(DISTINCT org) > 1;

-- 統計每個組織的節點數
SELECT org, COUNT(*) FROM node_orgs GROUP BY org;

-- 查看所有 malicious > 50 的 file 節點
SELECT id, json_extract(attributes, '$.malicious') as mal
FROM nodes WHERE type='file' AND json_extract(attributes, '$.malicious') > 50;

-- 查看特定 APT 的 C2 基礎設施
SELECT e.target, n.type, json_extract(n.attributes, '$.malicious') as mal
FROM edges e JOIN nodes n ON e.target = n.id
WHERE e.org = 'APT18' AND e.relationship = 'contacted_ip';
```

### CLI 參數

| 腳本 | 參數 | 必要 | 說明 |
|------|------|------|------|
| `build_knowledge_graph.py` | `--org` | ✅ | APT 組織名稱 |
| | `--skip-query` | ❌ | 跳過 VT API 查詢 |
| | `--visualize` | ❌ | 產出視覺化 PNG |
| `merge_knowledge_graphs.py` | `--orgs` | ❌ | 指定組織（逗號分隔），預設自動偵測 |
| | `--visualize` | ❌ | 產出合併視覺化 PNG |

### 前置需求

1. **環境**：Python 3.11+，`uv sync` 安裝依賴
2. **VT API Key**：在專案根目錄 `.env` 中設定 `VT_API_KEY=your_key`
3. **IoC 資料**：`org_iocs_cleaned/{org}/iocs.json` 必須存在
4. **VT Relationship 資料**：`vt_relationships/{org}/` 必須存在（由 `fetch_vt_relationships.py` 產出）

---

## 圖譜 JSON Schema（v2.0）

### 頂層結構

```json
{
  "organization": "APT18",
  "version": "2.0",
  "created_at": "2026-03-22T...",
  "node_count": 108,
  "edge_count": 112,
  "nodes": [ ... ],
  "edges": [ ... ]
}
```

---

### 節點類型定義

#### 1. APT 節點

```json
{
  "id": "apt_APT18",
  "type": "apt",
  "attributes": { "name": "APT18" }
}
```

每個圖譜有且只有 1 個 APT 根節點。不查 VT。

#### 2. File 節點

**ID 規則**：`file_{sha256}`（Canonical ID）。即使原始 IoC 是 MD5 或 SHA-1，經 VT 查詢後正規化為 SHA-256。

```json
{
  "id": "file_9200f80c...",
  "type": "file",
  "vt_found": true,
  "depth": 1,
  "attributes": {
    "md5": "985eba...", "sha1": "0e989a...", "sha256": "9200f80c...",
    "vhash": "...", "ssdeep": "...", "tlsh": "...", "authentihash": "...",

    "malicious": 59, "suspicious": 0, "harmless": 0, "undetected": 12,
    "total_engines": 76, "detection_ratio": 0.7763, "reputation": -2,

    "size": 126976, "type_tag": "peexe", "type_description": "Win32 EXE",
    "magic": "PE32 executable ...", "magika": "PEBIN",
    "packers": {"PEiD": "Microsoft Visual C++"},
    "names": ["anti_virus_updates.exe"], "meaningful_name": "anti_virus_updates.exe",
    "tags": ["peexe", "long-sleeps"], "type_extension": "exe", "type_tags": ["peexe"],

    "creation_time": "2015-06-30T12:00:14Z",
    "first_seen_itw": "2015-06-30T17:35:06Z",
    "first_submission": "2015-06-30T14:38:12Z",
    "last_submission": "2024-05-23T06:57:37Z",
    "last_analysis": "2026-03-13T06:25:18Z",

    "times_submitted": 12, "unique_sources": 8,
    "total_votes": {"harmless": 0, "malicious": 3},
    "trid": [...], "detectiteasy": [...],
    "popular_threat_classification": { "suggested_threat_label": "trojan.agent/msil", ... },
    "bundle_info": null,
    "signature_verified": "Unsigned",
    "file_version_info": { "copyright": "...", "product": "...", ... },
    "pe_info": { "imphash": "...", "sections": [...], "imports": [...], "resources": [...] }
  }
}
```

> `depth`: `null` 或 `0` = Layer 1（原始 IoC），`1` = Layer 2（relationship 發現）

**File Attributes 欄位總覽：**

| 分類 | 欄位 | 型別 | 說明 |
|------|------|------|------|
| 雜湊 | `md5`, `sha1`, `sha256` | `string \| null` | 三種 hash |
| 雜湊 | `vhash`, `ssdeep`, `tlsh`, `authentihash` | `string \| null` | 模糊雜湊 / 驗證雜湊 |
| 偵測 | `malicious`, `suspicious`, `harmless`, `undetected` | `int` | 引擎偵測數 |
| 偵測 | `total_engines`, `detection_ratio` | `int` / `float` | 引擎總數 / 偵測率 |
| 偵測 | `reputation` | `int \| null` | VT 社群信譽分數 |
| 屬性 | `size` | `int \| null` | 檔案大小（bytes） |
| 屬性 | `type_tag`, `type_description`, `magic`, `magika` | `string \| null` | 檔案類型識別 |
| 屬性 | `packers` | `object \| null` | 封裝偵測 |
| 屬性 | `names`, `meaningful_name` | `string[] \| string` | 檔案名稱 |
| 屬性 | `tags`, `type_extension`, `type_tags` | `string[]` | 標籤 |
| 時間 | `creation_time`, `first_seen_itw`, `first_submission`, `last_submission`, `last_analysis` | `string \| null` | ISO 8601 |
| 統計 | `times_submitted`, `unique_sources`, `total_votes` | — | 提交統計 |
| 識別 | `trid`, `detectiteasy` | `array` | 檔案類型 / 編譯器識別 |
| 威脅 | `popular_threat_classification` | `object \| null` | VT 威脅分類 |
| Bundle | `bundle_info` | `object \| null` | ZIP/Office 內部結構 |
| 簽章 | `signature_verified`, `file_version_info` | — | 簽章 / 版本資訊 |
| PE | `pe_info` | `object \| null` | PE 結構（imphash, sections, imports, resources） |

#### 3. Domain 節點

```json
{
  "id": "domain_it-desktop.com",
  "type": "domain",
  "vt_found": true,
  "attributes": {
    "malicious": 10, "suspicious": 0, "harmless": 52, "undetected": 32,
    "total_engines": 94, "detection_ratio": 0.1064, "reputation": 0,
    "total_votes": {"harmless": 0, "malicious": 0},
    "registrar": "GoDaddy.com, LLC", "tld": "com",
    "creation_date": "2018-10-20T19:51:38Z",
    "last_update_date": "2025-10-19T01:24:43Z",
    "last_analysis": "2026-03-21T12:21:02Z",
    "categories": {"Sophos": "spyware and malware"},
    "tags": [], "popularity_ranks": {},
    "has_whois": true, "whois": "Creation Date: ...",
    "last_dns_records": [{"type": "A", "value": "1.2.3.4", "ttl": 300}],
    "last_dns_records_date": "2026-03-21T12:21:26Z",
    "jarm": "3fd3fd20d...",
    "last_https_certificate": { "thumbprint": "...", "issuer": {...}, ... },
    "crowdsourced_context": []
  }
}
```

| 分類 | 欄位 | 說明 |
|------|------|------|
| 偵測 | `malicious`, `reputation`, `detection_ratio` | 同 File |
| 網域 | `registrar`, `tld`, `creation_date`, `categories` | 註冊資訊（子域名可能無 registrar） |
| WHOIS | `has_whois`, `whois` | WHOIS 記錄 |
| DNS | `last_dns_records`, `last_dns_records_date` | 最後 DNS 記錄 |
| 憑證 | `jarm`, `last_https_certificate` | TLS 指紋 / HTTPS 憑證 |
| 情資 | `crowdsourced_context` | VT 社群情資 |

#### 4. IP 節點

```json
{
  "id": "ip_20.62.24.77",
  "type": "ip",
  "vt_found": true,
  "depth": 1,
  "attributes": {
    "malicious": 0, "suspicious": 0, "harmless": 59, "undetected": 35,
    "total_engines": 94, "detection_ratio": 0.0, "reputation": 1,
    "total_votes": {"harmless": 0, "malicious": 0},
    "country": "US", "continent": "NA",
    "asn": 8075, "as_owner": "Microsoft Corporation",
    "network": "20.48.0.0/12", "regional_internet_registry": "ARIN",
    "tags": [],
    "whois": "NetRange: 20.33.0.0 - 20.128.255.255...",
    "jarm": "2ad2ad000...",
    "last_https_certificate": {...},
    "crowdsourced_context": []
  }
}
```

| 分類 | 欄位 | 說明 |
|------|------|------|
| 偵測 | `malicious`, `reputation`, `detection_ratio` | 同 File |
| 網路 | `country`, `continent`, `asn`, `as_owner`, `network` | 地理 / ASN 資訊（私有 IP 如 192.168.x.x 無此資料） |
| WHOIS | `whois` | IP WHOIS |
| 憑證 | `jarm`, `last_https_certificate` | TLS 指紋 |

#### 5. Email 節點

```json
{
  "id": "email_attacker@example.com",
  "type": "email",
  "attributes": { "value": "attacker@example.com" }
}
```

不查 VT，保留社交工程脈絡。

---

### 邊定義

#### has_ioc（Layer 1）

APT 根節點 → IoC 節點。邊的 attributes 保留所有原始 IoC 記錄。

```json
{
  "source": "apt_APT18",
  "target": "file_9200f80c...",
  "relationship": "has_ioc",
  "attributes": {
    "ioc_original_types":  ["md5", "sha256"],
    "ioc_original_values": ["985eba...", "9200f80c..."],
    "source_reports":      ["https://www.anomali.com/blog/..."]
  }
}
```

**邊合併機制**：同一 `(source, target)` pair 只產生 1 條 `has_ioc` 邊。`ioc_original_types` 與 `ioc_original_values` 為**平行陣列**（`types[i]` 對應 `values[i]`），URL 完整路徑保留在 `ioc_original_values` 中。

#### contacted_ip / contacted_domain（Layer 2）

File 執行時的網路行為。

```json
{
  "source": "file_9200f80c...",
  "target": "ip_20.62.24.77",
  "relationship": "contacted_ip",
  "attributes": {}
}
```

#### dropped_file（Layer 2）

File 執行後釋放的子檔案。

```json
{
  "source": "file_1b341dab...",
  "target": "file_a701a64c...",
  "relationship": "dropped_file",
  "attributes": {}
}
```

#### resolves_to（Layer 2）

DNS 解析歷史。Domain ↔ IP 雙向。

```json
{
  "source": "domain_autodiscover.2bunny.com",
  "target": "ip_209.99.40.223",
  "relationship": "resolves_to",
  "attributes": {}
}
```

---

## 合併資料庫 Schema（master/）

### merged_kg.json

```json
{
  "version": "1.0",
  "orgs": ["APT18", "APT19"],
  "created_at": "2026-03-22T...",
  "node_count": 230,
  "edge_count": 338,
  "nodes": [
    { "id": "...", "type": "...", "vt_found": true, "attributes": {...}, "orgs": ["APT18"] }
  ],
  "edges": [
    { "source": "...", "target": "...", "relationship": "...", "attributes": {...}, "org": "APT18" }
  ],
  "merge_stats": {
    "total_orgs": 2, "total_nodes": 230, "total_edges": 338,
    "shared_nodes": 0, "unique_nodes": 230, "shared_node_ids": []
  }
}
```

與單一 KG 的差異：
- 節點多了 `orgs` 欄位（所屬組織列表）
- 邊多了 `org` 欄位（來源組織）
- 頂層有 `merge_stats` 統計共享節點

### merged_kg.db（SQLite）

| Table | 欄位 | 說明 |
|-------|------|------|
| `nodes` | id, type, vt_found, depth, attributes (JSON), orgs (JSON) | 所有節點 |
| `edges` | id, source, target, relationship, attributes (JSON), org | 所有邊（含來源組織） |
| `node_orgs` | node_id, org | 多對多表：節點 ↔ 組織 |

索引：`edges(source)`, `edges(target)`, `edges(org)`, `edges(relationship)`, `nodes(type)`, `node_orgs(org)`

---

## VT Cache Schema（`{org}_vt_cache.json`）

斷點續傳用的查詢快取，key 為 node ID：

```json
{
  "file_985eba...": {
    "nid": "file_985eba...",
    "ep_type": "files",
    "query_value": "985eba...",
    "query_time": "2026-03-20T10:30:00+00:00",
    "vt_found": true,
    "attributes": { ... },
    "canonical_nid": "file_9200f80c..."
  }
}
```

- 程式啟動時載入 cache，跳過已查詢的 IoC
- 每次 VT API 查詢後立即寫入（防中斷丟失）
- File 的 canonical alias 也寫入 cache（不同 hash 類型互相命中）

---

## 程式碼架構

```
scripts/build_knowledge_graph.py
│
├── main()
│   ├── Phase 1: _query_vt_batch()      ← 查 IoC Details
│   ├── build_graph()                    ← 初次建圖
│   ├── Phase 2: _discover_relationship_nodes()  ← 發現第二層節點
│   ├── _query_vt_batch()               ← 查第二層 Details
│   └── build_graph()                    ← 重建完整圖譜
│
├── build_graph()
│   ├── normalize_ioc() + make_node_id()  ← IoC 正規化
│   ├── 節點去重 + 邊合併                   ← Layer 1
│   ├── _load_relationships()             ← 讀取 vt_relationships/
│   ├── _ensure_node()                    ← Layer 2 節點加入
│   └── _add_rel_edge()                   ← Layer 2 邊加入
│
├── Metadata 提取器
│   ├── extract_file_metadata()
│   ├── extract_domain_metadata()
│   └── extract_ip_metadata()
│
├── vt_get()                              ← VT API（429 迴圈重試）
├── visualize()                           ← PNG 視覺化
└── _ts()                                 ← Unix → ISO 8601
```

```
scripts/merge_knowledge_graphs.py
│
├── main()                                ← 自動偵測 KG → 合併 → 輸出
├── merge_graphs()                        ← 節點合併 + 邊保留
│   └── _merge_attributes()              ← 數值取最新、清單累加去重
├── export_sqlite()                       ← SQLite 輸出
└── visualize()                           ← 合併視覺化（共享節點白色邊框）
```

---

## API 限制

| 項目 | 值 |
|------|------|
| 每分鐘請求數 | 4 req/min（academic plan） |
| 每日額度 | 5,800 lookups/day |
| 請求間隔 | 15 秒（`RATE_LIMIT_SEC`） |
| 429 重試 | 最多 3 次，間隔遞增（15s → 30s → 45s） |
| 連線方式 | `requests.Session()`（Connection Pooling） |

---

## Code Review 結果（2026-03-22）

### 節點 Metadata 完整性

| 檢查項 | APT18 | APT19 | 狀態 |
|--------|-------|-------|------|
| Domain — 全部有 metadata | 40/40 | 27/27 | ✓ |
| IP — 全部有 metadata | 19/19 | 72/72 | ✓ |
| File — vt_found 有完整 metadata | 25/25 | 2/2 | ✓ |
| File — VT 404 無 metadata | 23 個 | 13 個 | 預期（VT 未收錄） |
| Email — 不查 VT | — | 7 個 | 設計如此 |

**關鍵欄位缺失（皆為合理情況）：**
- `registrar=null`：子域名或大型企業 domain（www.microsoft.com 等）VT 不回傳 registrar
- `asn=null`, `country=null`：RFC 1918 私有 IP（192.168.x.x）

### 邊完整性

| 檢查項 | APT18 | APT19 | 狀態 |
|--------|-------|-------|------|
| 懸空邊（指向不存在的節點） | 0 | 0 | ✓ |
| 邊方向正確性 | 全部正確 | 全部正確 | ✓ |
| 孤立節點（無邊） | 0 | 0 | ✓ |
| 重複邊 | 0 | 0 | ✓ |

---

## 已知限制

1. **VT 404 的 file 節點無 metadata**：全為 dropped_files 或舊 md5 hash，VT 資料庫未收錄
2. **Email 節點無 metadata**：VT 不支援直接查詢 email entity
3. **大型組織建構時間長**：每個節點需 15 秒（rate limit），100 個節點 ≈ 25 分鐘
4. **Layer 2 只擴展一層**：不遞迴（IoC_2nd 不再往下查 relationship）
5. **合併圖譜為靜態快照**：新增/更新單一 KG 後需重跑 merge 腳本
