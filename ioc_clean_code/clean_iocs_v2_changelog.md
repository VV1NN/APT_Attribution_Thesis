# IoC 清洗腳本 v2 — 修改說明文件

## 概述

本文件說明 `clean_iocs_v2.py` 相較於原始版本 (v1) 的所有修改與設計理由。
修改圍繞一個核心目標：**產出乾淨、去重、可直接建圖的 IoC 資料集**，為後續的子圖相似度比對與 APT 歸因做準備。

---

## 修改總覽

| # | 問題 | 修改內容 | 影響層面 |
|---|------|---------|---------|
| 1 | Hash 跨類型重複 | 新增 `cross_hash_merge()` | 去重 / 建圖 |
| 2 | URL-IP 重複 | 新增 `collapse_url_ips()` | 去重 / 建圖 |
| 3 | Defanged IoC 未處理 | 新增 `refang()` | 正規化 |
| 4 | eTLD 黑名單不完整 | 擴充至 ~50 個 domain | 噪音過濾 |
| 5 | DDNS 白名單不完整 | 擴充至 ~20 個 domain | 保留真正 C2 |
| 6 | Email 噪音未過濾 | 新增 `is_useful_email()` | 噪音過濾 |
| 7 | 去重時 sources 未合併 | 重寫 `deduplicate_with_source_merge()` | co-occurrence 邊 |
| 8 | 無清洗統計 | 每步產出 stats dict | 論文可重現性 |
| 9 | URL parse 無容錯 | 新增 `safe_extract_domain()` | 穩定性 |

---

## 修改詳解

### 1. Cross-Hash 合併 (`cross_hash_merge`)

**問題：**
同一個惡意檔案可能在不同報告中以 md5、sha1、sha256 三種形式出現。
v1 用 `(type, value)` 去重，會把同一檔案視為三筆獨立 IoC。
在圖上這會造成三個孤立節點，無法正確計算子圖相似度。

**解法：**
利用 VT 回傳的 `file_info` 中包含完整三種 hash 的特性：

```
file_info: {
    "md5": "02b79c...",
    "sha1": "57d7f3...",
    "sha256": "8646a5..."
}
```

演算法步驟：
1. 把所有 hash 類型的 IoC 取出
2. 對每一筆，用 `file_info.sha256` 作為 canonical key 來分組
3. 同一組的多筆記錄合併為一筆（以 sha256 為主）
4. 合併所有 sources，並在 `alt_hashes` 欄位保留其他 hash 值

**你的實際資料狀況：**
APT28 資料中 md5 與 sha256 之間目前沒有發現交叉重複（可能是 VT 回傳的 `file_info` 不完整），但這個邏輯在多 APT 組織資料混合後會非常重要。

```python
# 合併前：三個孤立節點
# md5:02b79c...  sha1:57d7f3...  sha256:8646a5...

# 合併後：一個節點，alt_hashes 保留所有值
# sha256:8646a5... (alt_hashes: {md5: "02b79c...", sha1: "57d7f3..."})
```

---

### 2. URL-IP 去重 (`collapse_url_ips`)

**問題：**
你的 APT28 資料中有 **36 筆 URL 實際上就是裸 IP**（如 `http://185.25.50.93`），
而且這 36 筆 **全部** 同時存在對應的 ipv4 記錄。
這意味著圖上會有 36 對重複節點。

**解法：**
```
處理邏輯：
  URL: http://1.2.3.4     →  提取 host = 1.2.3.4
                           →  是 IP? YES
                           →  ipv4:1.2.3.4 已存在? 
                              YES → 合併 sources 到 ipv4 記錄，刪除 URL
                              NO  → 將此 URL 轉型為 ipv4 記錄
```

注意：帶路徑的 URL（如 `http://1.2.3.4/malware/payload.exe`）也會被合併。
這是故意的設計——在圖層級，我們關心的是 IP 節點的連接性，路徑資訊可以作為邊的屬性保留在後續步驟。

---

### 3. Defanged IoC 還原 (`refang`)

**問題：**
CTI 報告中 IoC 常被 defang 處理以避免意外點擊：
- `hxxp://` → `http://`
- `evil[.]com` → `evil.com`
- `192.168.1[.]1` → `192.168.1.1`

v1 沒有處理這種情況，會導致：
- URL parse 失敗（`hxxp://` 不是合法 scheme）
- Domain 比對失敗（`evil[.]com` 不會匹配黑名單中的 `evil.com`）
- 同一 IoC 的 defanged 和 refanged 版本被視為不同記錄

**解法：**
在 normalize 的最開始加上 `refang()` 函數，統一還原：

```python
def refang(value: str) -> str:
    value = value.replace("hxxp://", "http://").replace("hxxps://", "https://")
    value = value.replace("[.]", ".").replace("[:]", ":")
    value = value.replace("(.)", ".").replace("[at]", "@")
    return value
```

**你的實際資料狀況：**
APT28 資料中沒有 defanged IoC（你在提取時可能已經處理過了），但這是防禦性措施，其他 APT 組織的資料很可能會有。

---

### 4. 擴充 eTLD 黑名單

**問題：**
v1 只有 10 個黑名單 domain，遺漏了大量噪音來源。
在圖中，這些 domain 會變成 **super-node**（超級節點），把不相關的 event subgraph 全部連在一起，嚴重干擾相似度計算。

**擴充內容（按類別）：**

```
安全廠商 (報告來源，非 C2):
  fireeye.com, mandiant.com, virustotal.com, kaspersky.com,
  symantec.com, broadcom.com, mcafee.com, trendmicro.com,
  malwarebytes.com, eset.com, sophos.com, paloaltonetworks.com,
  fortinet.com, crowdstrike.com, proofpoint.com, secureworks.com,
  talosintelligence.com, zscaler.com, checkpoint.com,
  sentinelone.com, recordedfuture.com, cybereason.com

CDN / 雲端 (太泛用，不適合作 IoC):
  amazonaws.com, cloudflare.com, akamai.com, azure.com,
  azurewebsites.net, cloudfront.net, fastly.net,
  googleusercontent.com

政府機構 (報告聯絡資訊):
  us-cert.gov, cisa.gov, nsa.gov, fbi.gov,
  dhs.gov, nist.gov, cert.gov
```

**為什麼 CDN domain 要擋：**
像 `amazonaws.com` 這種 domain，幾乎所有 APT 和正常軟體都會用到。
如果保留，它會跟圖中幾乎所有子圖產生連接，讓相似度計算失去區分力。

---

### 5. 擴充 DDNS 白名單

**問題：**
APT28 (以及許多其他 APT 組織) 大量使用 DDNS 服務做 C2。
v1 只列了 `serveftp.com`，其他 DDNS domain 可能會被未來擴充的黑名單誤殺。

**擴充內容：**
```
no-ip.com, no-ip.org, no-ip.biz,     ← No-IP 家族
dyndns.org, dyndns.com,               ← DynDNS
hopto.org, afraid.org, zapto.org,     ← Free DNS services
sytes.net, ddns.net, myftp.biz,       ← 常見 DDNS
webhop.me, bounceme.net, myvnc.com    ← 其他
```

白名單的邏輯是：即使未來黑名單擴充，這些 domain 永遠不會被過濾掉，因為它們對 APT 歸因非常有價值。

---

### 6. Email 噪音過濾 (`is_useful_email`)

**問題：**
你的 APT28 資料中有 15 筆 email，其中大部分是政府機構聯絡信箱：

```
ciscp@us-cert.gov          ← CISA 通報信箱，噪音
cybersecurity_requests@nsa.gov  ← NSA 聯絡，噪音
cywatch@ic.fbi.gov         ← FBI 聯絡，噪音
threatintel@eset.com       ← ESET 情報分享，噪音
dirbinsaabol@mail.com      ← 可能是攻擊者註冊，保留
openai@chatgpt4beta.com    ← 可能是攻擊者釣魚，保留
```

**解法：**
三層判斷邏輯：

```
1. Email domain 在已知免費信箱服務（mail.com, protonmail.com...）？
   → YES → 保留（攻擊者常用）

2. Email domain 在黑名單中（us-cert.gov, eset.com...）？
   → YES → 丟棄（報告聯絡人）

3. 都不是？
   → 保留（未知 domain 可能是攻擊者基礎設施）
```

---

### 7. 去重時合併 Sources (`deduplicate_with_source_merge`)

**問題：**
v1 的 `deduplicate_iocs()` 在遇到重複時只保留其中一筆，丟掉另一筆的 sources。
但 **sources 是建立 co-occurrence 邊的唯一依據**——同一 source report 中出現的 IoC 應該被連接。
丟掉 sources 等於丟掉圖的邊。

**解法：**
重寫去重函數，用 dict 以 `(type, value_normalized)` 為 key：

```python
# 遇到重複時：
existing_sources = set(seen[key]["sources"])
new_sources = set(item["sources"])
seen[key]["sources"] = list(existing_sources | new_sources)
```

**你的資料實際影響：**
APT28 有 7 筆 IoC 出現在多個 source report 中。
這些 IoC 是跨報告的樞紐節點，對子圖連接性特別重要。

---

### 8. 清洗統計輸出

**問題：**
v1 沒有任何統計輸出，無法重現清洗過程，論文中也無法引用具體數據。

**解法：**
`clean_iocs()` 現在回傳 `(cleaned_list, stats_dict)`，stats 包含：

```json
{
    "input_count": 379,
    "after_type_filter": 379,
    "dropped_by_type": 0,
    "emails_removed": 12,
    "emails_kept": 3,
    "duplicates_removed": 5,
    "cross_hash_merged": 0,
    "url_ip_collapsed": 36,
    "dropped_private_ip": 0,
    "dropped_blacklist_domain": 8,
    "output_count": 318,
    "orphan_no_source": 0,
    "output_type_distribution": {
        "ipv4": 36,
        "sha256": 44,
        "md5": 68,
        "url": 157,
        "domain": 10,
        "email": 3
    }
}
```

每個 org 的清洗結果會生成 `cleaning_stats.json`，
所有 org 的彙總則寫入 `all_cleaning_stats.json`。
這些數據可以直接用在論文的 Experiment Setup 章節。

---

### 9. 安全的 URL 解析 (`safe_extract_domain`)

**問題：**
v1 直接呼叫 `extract_domain_from_url()` 沒有 try-except。
遇到格式異常的 URL 會直接 crash，導致整個 org 的清洗失敗。

**解法：**
包一層 fallback：

```python
def safe_extract_domain(url: str) -> Optional[str]:
    try:
        return extract_domain_from_url(url)     # 用你的 utils
    except Exception:
        try:
            parsed = urlparse(url)              # 退回標準庫
            return parsed.hostname
        except Exception:
            return None                         # 真的解析不了就跳過
```

---

## Pipeline 執行順序

完整清洗流程如下圖：

```
原始 IoC (379)
    │
    ▼
[Step 1] Type Filter ─── 過濾非 ALLOWED_TYPES 的記錄
    │
    ▼
[Step 2] Normalize ────── refang + lowercase + 提取 domain
    │
    ▼
[Step 3] Email Filter ─── 保留攻擊者 email，丟棄政府/廠商聯絡
    │
    ▼
[Step 4] Dedup ────────── (type, value) 去重，合併 sources
    │
    ▼
[Step 5] Cross-Hash ───── md5/sha1/sha256 同檔案合併為一筆
    │
    ▼
[Step 6] URL-IP ───────── 裸 IP 的 URL 併入 ipv4 記錄
    │
    ▼
[Step 7] Blacklist ────── 過濾私有 IP、黑名單 domain
    │
    ▼
[Step 8] Orphan Check ─── 警告沒有 source 的 IoC
    │
    ▼
清洗完成的 IoC + stats.json
```

---

## 使用方式

```bash
# 與 v1 相同，直接執行
python scripts/clean_iocs.py

# 輸入: project_root/org_iocs/{group}/iocs.json
# 輸出: project_root/org_iocs_cleaned/{group}/iocs.json
#        project_root/org_iocs_cleaned/{group}/cleaning_stats.json
#        project_root/org_iocs_cleaned/all_cleaning_stats.json
```

---

## 對後續建圖的影響

| 清洗步驟 | 對圖的影響 |
|---------|-----------|
| Cross-hash 合併 | 避免同一檔案產生多個孤立節點 |
| URL-IP 合併 | 避免 IP 節點重複，保持 degree 準確 |
| Sources 合併 | 確保 co-occurrence 邊完整，不遺漏跨報告連接 |
| 黑名單擴充 | 避免 super-node 把不相關子圖黏在一起 |
| DDNS 白名單 | 保留 APT 常用 C2 基礎設施 |
| 統計輸出 | 論文 Experiment Setup 可直接引用 |

---

## 注意事項

1. **`utils.filters` 依賴**：本腳本仍然依賴你原有的 `IOCFilter`、`extract_domain_from_url`、`get_etld_plus_one`。如果這些函數有 bug，建議加上單元測試。

2. **黑名單需要持續維護**：不同 APT 組織可能涉及不同的噪音 domain。建議把黑名單抽成外部 JSON 檔案，方便按需調整。

3. **Email 保留策略偏保守**：目前未知 domain 的 email 一律保留。如果發現太多噪音，可以改為只保留 `ATTACKER_EMAIL_INDICATORS` 中的 domain。

4. **CDN domain 封鎖的例外**：如果某個 APT 確實以特定 AWS/Cloudflare 子網域作為 C2，你需要在更細粒度上處理（例如保留完整 FQDN 而非 eTLD+1）。這在 v2 中尚未實作，但可以在後續版本加入。
