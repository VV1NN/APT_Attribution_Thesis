# 知識圖譜 JSON 架構說明

本文件說明 APT 知識圖譜系統所產生的 JSON 檔案結構，包含**單一組織 KG** 與**合併 KG (Master)** 兩種格式。

---

## 目錄

1. [單一組織 KG (`{ORG}.json`)](#1-單一組織-kg)
2. [合併 KG (`merged_kg.json`)](#2-合併-kg)
3. [節點 (Nodes) 詳細結構](#3-節點結構)
4. [邊 (Edges) 詳細結構](#4-邊結構)

---

## 1. 單一組織 KG

路徑：`knowledge_graphs/{ORG}/{ORG}.json`

### 頂層結構

```json
{
  "organization": "APT19",
  "version": "2.0",
  "created_at": "2026-03-24T02:31:57.341872+00:00",
  "node_count": 122,
  "edge_count": 226,
  "nodes": [ ... ],
  "edges": [ ... ]
}
```

| 欄位 | 型別 | 說明 |
|------|------|------|
| `organization` | string | APT 組織名稱 |
| `version` | string | KG 版本號 |
| `created_at` | string (ISO 8601) | 建立時間 |
| `node_count` | int | 節點總數 |
| `edge_count` | int | 邊總數 |
| `nodes` | array | 節點陣列 |
| `edges` | array | 邊陣列 |

---

## 2. 合併 KG

路徑：`knowledge_graphs/master/merged_kg.json`

### 頂層結構

```json
{
  "version": "1.0",
  "orgs": ["APT16", "APT18", "APT19"],
  "created_at": "2026-03-22T12:39:44.464479+00:00",
  "node_count": 357,
  "edge_count": 480,
  "merge_stats": {
    "total_orgs": 3,
    "total_nodes": 357,
    "total_edges": 480,
    "shared_nodes": 8,
    "unique_nodes": 349,
    "shared_node_ids": ["ip_20.99.133.109", "ip_8.8.8.8", "..."]
  },
  "nodes": [ ... ],
  "edges": [ ... ]
}
```

| 欄位 | 型別 | 說明 |
|------|------|------|
| `version` | string | 合併 KG 版本號 |
| `orgs` | array[string] | 包含的組織列表 |
| `created_at` | string (ISO 8601) | 建立時間 |
| `node_count` | int | 節點總數 |
| `edge_count` | int | 邊總數 |
| `merge_stats` | object | 合併統計資訊 |
| `merge_stats.shared_nodes` | int | 跨組織共用節點數量 |
| `merge_stats.shared_node_ids` | array[string] | 共用節點 ID 列表 |
| `nodes` | array | 節點陣列（每個節點多一個 `orgs` 欄位） |
| `edges` | array | 邊陣列（每個邊多一個 `org` 欄位） |

### 合併 KG 與單一 KG 的差異

- 節點多了 `orgs` 欄位（array），標記此節點屬於哪些組織
- 邊多了 `org` 欄位（string），標記此邊來自哪個組織
- 同 ID 節點合併規則：數值欄位取最新值，列表欄位取聯集

---

## 3. 節點結構

每個節點的基本結構：

```json
{
  "id": "...",
  "type": "...",
  "vt_found": true/false,
  "depth": null | 1,
  "attributes": { ... },
  "orgs": ["..."]          // 僅合併 KG
}
```

| 欄位 | 型別 | 說明 |
|------|------|------|
| `id` | string | 節點唯一識別碼（格式：`{type}_{value}`） |
| `type` | string | 節點類型：`apt`, `file`, `domain`, `ip`, `email` |
| `vt_found` | boolean | 是否在 VirusTotal 上找到資料（`apt` 節點無此欄位） |
| `depth` | null \| int | `null` = Layer 1（CTI 報告中的 IoC），`1` = Layer 2（VT 關係發現的節點） |
| `attributes` | object | 節點屬性（依類型不同，見下方） |

### 3.1 `apt` 節點

ID 格式：`apt_{name}`

```json
{
  "id": "apt_APT19",
  "type": "apt",
  "attributes": {
    "name": "APT19"
  }
}
```

### 3.2 `file` 節點

ID 格式：`file_{sha256}` 或 `file_{md5}`（當只有 MD5 時）

#### vt_found = false（VT 無資料）

```json
{
  "id": "file_0bef39d0e10b1edfe77617f494d733a8",
  "type": "file",
  "vt_found": false,
  "attributes": {}
}
```

#### vt_found = true（完整 VT 資料）

```json
{
  "id": "file_42ff4fa4a92fba9ec44371431997700195f22753d4ea16c0dda0a5c4116a61af",
  "type": "file",
  "vt_found": true,
  "attributes": {
    // --- 雜湊值 ---
    "md5": "3a1dca21bfe72368f2dd46eb4d9b48c4",
    "sha1": "3ddc3d2f40c64333adfafe508726344d90598c7b",
    "sha256": "42ff4fa4...a61af",
    "vhash": "5ae8ed93f0abf83d19a70dd16b7cbcf5",
    "ssdeep": "768:0Gnps5iPwh...",
    "tlsh": "T1F6D2CF2CE60...",
    "authentihash": "a4a954..." | null,

    // --- 偵測結果 ---
    "malicious": 46,
    "suspicious": 0,
    "harmless": 0,
    "undetected": 22,
    "total_engines": 76,
    "detection_ratio": 0.6053,
    "reputation": -9,

    // --- 檔案基本資訊 ---
    "size": 28898,
    "type_tag": "xlsx",
    "type_description": "Office Open XML Spreadsheet",
    "type_extension": "xlsx",
    "type_tags": ["document", "msoffice", "spreadsheet", "excel", "xlsx"],
    "magic": "Microsoft Excel 2007+",
    "magika": "XLSX",

    // --- 名稱與標籤 ---
    "names": ["3a1dca21...HPfBtLChP.xLsX"],
    "meaningful_name": "3a1dca21...HPfBtLChP.xLsX",
    "tags": ["powershell", "via-tor", "auto-open", "macros", "..."],

    // --- 時間戳記 ---
    "creation_time": "2009-10-19T23:35:39Z",
    "first_seen_itw": "2017-06-05T15:32:46Z",
    "first_submission": "2017-05-30T15:54:17Z",
    "last_submission": "2023-07-10T17:39:02Z",
    "last_analysis": "2025-09-07T16:00:53Z",

    // --- 提交統計 ---
    "times_submitted": 5,
    "unique_sources": 5,
    "total_votes": { "harmless": 0, "malicious": 3 },

    // --- 檔案分析工具 ---
    "packers": { "F-PROT": "Unicode" } | null,
    "trid": [
      { "file_type": "Excel Macro-enabled Open XML add-in", "probability": 42.4 }
    ],
    "detectiteasy": [
      { "type": "Compiler", "name": "Microsoft Visual C/C++", "version": "2008-2010" }
    ],

    // --- 威脅分類 ---
    "popular_threat_classification": {
      "suggested_threat_label": "trojan.hancitor/heur2",
      "popular_threat_category": [
        { "value": "trojan", "count": 11 }
      ],
      "popular_threat_name": [
        { "value": "hancitor", "count": 7 }
      ]
    },

    // --- 壓縮包資訊（僅壓縮類檔案） ---
    "bundle_info": {
      "num_children": 19,
      "uncompressed_size": 97682,
      "type": "XLSX",
      "extensions": { "xml": 10, "rels": 4, "bin": 4 },
      "file_types": { "XML": 15, "unknown": 3 },
      "lowest_datetime": "1980-01-01 00:00:00",
      "highest_datetime": "1980-01-01 00:00:00"
    } | null,

    // --- PE 資訊（僅 PE 執行檔） ---
    "pe_info": {
      "imphash": "...",
      "entry_point": 4096,
      "machine_type": 332,
      "timestamp": 1481148322,
      "sections": [ ... ],
      "imports": [ ... ],
      "exports": [ ... ],
      "resource_details": [ ... ],
      "rich_pe_header_hash": "...",
      "compiler_product_versions": [ ... ]
    } | null,

    // --- 數位簽章（僅已簽名檔案） ---
    "signature_verified": "Signed and verification failed" | null,
    "file_version_info": {
      "CompanyName": "...",
      "FileDescription": "...",
      "ProductVersion": "..."
    } | null
  }
}
```

### 3.3 `domain` 節點

ID 格式：`domain_{name}`

```json
{
  "id": "domain_autodiscover.2bunny.com",
  "type": "domain",
  "vt_found": true,
  "attributes": {
    // --- 偵測結果 ---
    "malicious": 7,
    "suspicious": 1,
    "harmless": 53,
    "undetected": 33,
    "total_engines": 94,
    "detection_ratio": 0.0745,
    "reputation": 0,
    "total_votes": { "harmless": 0, "malicious": 0 },

    // --- 網域註冊資訊 ---
    "registrar": "TurnCommerce, Inc. DBA NameBright.com",
    "tld": "com",
    "creation_date": "2019-04-03T02:27:36Z",
    "last_update_date": "2025-11-03T21:24:33Z",
    "last_analysis": "2026-02-06T00:19:15Z",

    // --- 分類與標籤 ---
    "categories": {},
    "tags": [],
    "popularity_ranks": {},

    // --- WHOIS ---
    "has_whois": true,
    "whois": "Admin City: Denver\nAdmin Country: US\n..."
  }
}
```

### 3.4 `ip` 節點

ID 格式：`ip_{address}`

```json
{
  "id": "ip_104.236.77.169",
  "type": "ip",
  "vt_found": true,
  "attributes": {
    // --- 偵測結果 ---
    "malicious": 2,
    "suspicious": 0,
    "harmless": 59,
    "undetected": 33,
    "total_engines": 94,
    "detection_ratio": 0.0213,
    "reputation": 0,
    "total_votes": { "harmless": 0, "malicious": 0 },

    // --- 網路資訊 ---
    "country": "US",
    "continent": "NA",
    "asn": 14061,
    "as_owner": "DigitalOcean, LLC",
    "network": "104.236.0.0/16",
    "regional_internet_registry": "ARIN",

    // --- 標籤與 WHOIS ---
    "tags": [],
    "whois": "NetRange: 104.236.0.0 - 104.236.255.255\n..."
  }
}
```

### 3.5 `email` 節點

ID 格式：`email_{address}`

> Email 節點不會查詢 VT API，僅保留社交工程的脈絡資訊。

```json
{
  "id": "email_angela.suh@cloudsend.net",
  "type": "email",
  "vt_found": false,
  "attributes": {
    "value": "angela.suh@cloudsend.net"
  }
}
```

---

## 4. 邊結構

每條邊的基本結構：

```json
{
  "source": "...",
  "target": "...",
  "relationship": "...",
  "attributes": { ... },
  "org": "..."          // 僅合併 KG
}
```

| 欄位 | 型別 | 說明 |
|------|------|------|
| `source` | string | 起點節點 ID |
| `target` | string | 終點節點 ID |
| `relationship` | string | 關係類型（見下方） |
| `attributes` | object | 邊屬性（依關係類型不同） |

### 4.1 `has_ioc`（Layer 1：CTI 報告來源）

方向：`apt` → `file` / `domain` / `ip` / `email`

```json
{
  "source": "apt_APT19",
  "target": "email_angela.suh@cloudsend.net",
  "relationship": "has_ioc",
  "attributes": {
    "ioc_original_types": ["email"],
    "ioc_original_values": ["angela.suh@cloudsend.net"],
    "source_reports": [
      "https://www.fireeye.com/blog/threat-research/2017/06/phished-at-the-request-of-counsel.html"
    ]
  }
}
```

| 屬性 | 型別 | 說明 |
|------|------|------|
| `ioc_original_types` | array[string] | 原始 IoC 類型（如 `email`, `md5`, `sha256`, `domain`, `ip`） |
| `ioc_original_values` | array[string] | 原始 IoC 值（合併前的值，可能包含多個 hash） |
| `source_reports` | array[string] | CTI 報告來源 URL |

### 4.2 `contacted_ip`（Layer 2：VT 關係）

方向：`file` → `ip`

```json
{
  "source": "file_e3494fd2cc7e9e...4d7be9",
  "target": "ip_3.223.115.185",
  "relationship": "contacted_ip",
  "attributes": {
    "malicious": 0,
    "undetected": 34,
    "last_analysis_date": "2026-02-24T20:14:53Z"
  }
}
```

### 4.3 `contacted_domain`（Layer 2：VT 關係）

方向：`file` → `domain`

```json
{
  "source": "file_e3494fd2cc7e9e...4d7be9",
  "target": "domain_2bunny.com",
  "relationship": "contacted_domain",
  "attributes": {
    "malicious": 11,
    "undetected": 33,
    "last_analysis_date": "2026-03-05T21:58:21Z"
  }
}
```

### 4.4 `dropped_file`（Layer 2：VT 關係）

方向：`file` → `file`

```json
{
  "source": "file_e3494fd2cc7e9e...4d7be9",
  "target": "file_140ca749f6a39...3ef1",
  "relationship": "dropped_file",
  "attributes": {}
}
```

### 4.5 `resolves_to`（Layer 2：DNS 解析）

方向：`domain` → `ip`

```json
{
  "source": "domain_sfo02s01-in-f2.cloudsend.net",
  "target": "ip_13.223.25.84",
  "relationship": "resolves_to",
  "attributes": {
    "resolution_date": "2025-08-17T16:18:41Z"
  }
}
```

### VT 關係邊屬性摘要

| 關係類型 | 可能的屬性 | 說明 |
|----------|-----------|------|
| `contacted_ip` | `malicious`, `undetected`, `last_analysis_date` | VT 偵測計數與最後分析日期 |
| `contacted_domain` | `malicious`, `undetected`, `last_analysis_date` | 同上 |
| `dropped_file` | （可能為空） | 部分邊有 `type_tag`, `type_description`, `meaningful_name` |
| `resolves_to` | `resolution_date` | DNS 解析紀錄日期 |

---

## 圖結構概覽

```
                    Layer 1 (CTI Reports)              Layer 2 (VT Relationships)
                    ─────────────────────              ──────────────────────────

                         has_ioc
                    APT ──────────→ File ──contacted_ip────→ IP (depth=1)
                     │                │
                     │  has_ioc       ├──contacted_domain──→ Domain (depth=1)
                     ├──────────→ Domain                        │
                     │                │                    resolves_to
                     │  has_ioc       └──dropped_file──→ File (depth=1)
                     ├──────────→ IP                            ↓
                     │                                     IP (depth=1)
                     │  has_ioc
                     └──────────→ Email


    depth=null (Layer 1 原始 IoC)     depth=1 (Layer 2 VT 發現的節點)
```

### 節點 ID 命名規則

| 類型 | 格式 | 範例 |
|------|------|------|
| `apt` | `apt_{name}` | `apt_APT19` |
| `file` | `file_{sha256}` 或 `file_{md5}` | `file_42ff4fa4a92f...a61af` |
| `domain` | `domain_{name}` | `domain_2bunny.com` |
| `ip` | `ip_{address}` | `ip_104.236.77.169` |
| `email` | `email_{address}` | `email_angela.suh@cloudsend.net` |
