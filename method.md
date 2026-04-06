# Methodology

> 本文件描述 APT 歸因系統的完整方法論，涵蓋知識圖譜建構、多層特徵工程、三信號 Cascade 歸因架構、以及評估方法論。

---

## 1. 系統總覽

本系統的核心目標是：給定一個未知來源的 IoC（Indicator of Compromise），判斷其所屬的 APT 組織，並輸出信心度與證據鏈。

系統由四個主要階段組成：

```
Stage A: 知識圖譜建構（離線，一次性）
  CTI 報告 → IoC 清洗 → VT API 擴充 → 雙層 KG → Master KG 合併

Stage B: 特徵工程（離線，一次性）
  Master KG → L1~L4 結構特徵 + NER → L5 TTP 特徵

Stage C: 三信號 Cascade 歸因（線上推論）
  Query IoC → VT API → S1 Graph Overlap → S2 TTP Tie-Breaking → S3 ML Fallback

Stage D: 可信度評估（離線實驗）
  Campaign-Aware CV + False-Flag + Open-Set + Selective Classification
```

---

## 2. Stage A：知識圖譜建構

### 2.1 IoC 清洗（`clean_iocs_v2.py`）

從 CTI 報告提取的原始 IoC 經過以下清洗步驟：

1. **Defang 還原**：`hxxp://` → `http://`、`[.]` → `.` 等常見防護格式還原
2. **類型正規化**：統一為 ipv4, ipv6, domain, url, md5, sha1, sha256, email
3. **跨 Hash 合併**：同一檔案的 md5/sha1/sha256 透過 VT file_info 合併為單一 sha256 記錄，保留 `alt_hashes` 欄位
4. **URL-IP 折疊**：裸 IP URL（如 `http://1.2.3.4/path`）轉為 ipv4 記錄
5. **黑名單過濾**：
   - Private IP（RFC 1918, loopback）移除
   - eTLD+1 黑名單（~50 個新聞/社群/廠商/CDN/政府域名）移除
   - DDNS 白名單例外：保留已知 APT 濫用的 DDNS 服務
6. **去重**：以 (type, normalized_value) 為 key，合併 source_reports
7. **Email 過濾**：僅保留攻擊者相關域名（protonmail, yandex, mail.ru 等）

### 2.2 VT 元資料擴充（Phase 1）

每個清洗後的 IoC 透過 VirusTotal Details API 查詢完整屬性：

| IoC Type | 主要查詢欄位 |
|----------|-------------|
| **File** | md5/sha1/sha256, detection stats (malicious/suspicious/harmless/undetected), reputation, size, type_tag, PE info (sections, imports, resources, imphash, compilation_timestamp), packers, bundle_info, threat classification, timestamps |
| **Domain** | detection stats, registrar, TLD, creation/update dates, categories, DNS records (A/AAAA/MX), WHOIS, HTTPS certificate, JARM |
| **IP** | detection stats, country/continent/ASN/AS owner, network CIDR, WHOIS, HTTPS certificate, JARM, tags |
| **Email** | 不查 VT（保留社交工程語境） |

**API 限制**：學術方案 20,000 req/day，rate limit 0.1s/req（~600 req/min），429 重試最多 3 次。

### 2.3 VT 關係發現（`fetch_vt_relationships.py`）

對每個 L0 IoC 查詢其 VT 關係，發現 L1 鄰居節點。啟用的 11 種邊類型：

| 來源類型 | 關係類型 | 目標類型 |
|---------|---------|---------|
| File | contacted_ip, contacted_domain, contacted_url | IP, Domain |
| File | dropped_file, execution_parent, bundled_file | File |
| Domain | resolves_to | IP |
| Domain | has_subdomain | Domain |
| Domain/IP | communicating_file, referrer_file | File |

**全域快取**：`vt_relationships/.cache/` 避免跨組織重複查詢。每日上限 18,000 次（留 buffer）。429 錯誤使用 unlimited retries + exponential backoff（60s → 120s → 300s → 600s）。

### 2.4 雙層知識圖譜建構（`build_knowledge_graph.py` Phase 2）

```
Layer 0 (L0): CTI 報告直接提到的 IoC
  apt --has_ioc--> file/domain/ip/email

Layer 1 (L1): VT 關係發現的鄰居節點
  file --contacted_ip--> ip (L1)
  domain --resolves_to--> ip (L1)
  ...
```

L1 節點同樣查詢 VT Details API 取得完整屬性。每個節點標記 `depth` 欄位（0=L0 來自報告, 1=L1 來自 VT）。每條邊攜帶屬性：`resolution_date`, `malicious`/`undetected` counts, `last_analysis_date`, `type_tag`, `meaningful_name`。

**輸出**：每個 APT 組織一個 JSON 格式 KG（NetworkX 序列化）。

### 2.5 Master KG 合併（`merge_knowledge_graphs.py`）

將所有組織的 KG 合併為統一的 Master KG：

**節點合併規則**（相同 ID 的節點）：
- `vt_found`: OR（任一組織找到即 True）
- `depth`: MIN（優先保留 L0 身份）
- 數值欄位（malicious, reputation, size）：取較新的值（依 query_time）
- 列表欄位（names, tags, source_reports）：聯集去重

**輸出格式**：
- JSON：`merged_kg.json`
- SQLite：`merged_kg.db`，含 `nodes`, `edges`, `node_orgs` 三張表

**規模**：66,444 nodes / 109,443 edges / 21 APT orgs / 跨組織共享節點 4,330 個。

---

## 3. Stage B：多層特徵工程

### 3.1 L1：節點自身屬性特徵（88 維）

從 VT 元資料提取的屬性特徵，依 IoC 類型分支：

**共用特徵（6d）：** detection_ratio, malicious, suspicious, harmless, undetected, reputation

**類型指示（4d）：** is_file, is_domain, is_ip, is_email（one-hot）

**File 特徵（37d）：**
- 基本：log(size), type_tag（ordinal + frequency）, PE 有無
- PE 結構：section count, section entropy stats, entry_point, machine_type, imphash frequency, resource_lang_count, import_dll_count
- 時序：days_since creation/first_seen/first_submission/last_submission, submission gap
- 提交：log(times_submitted), log(unique_sources), vote counts
- 威脅：signature, packer, threat_label（ordinal + frequency）, threat_category, tag count, anti-analysis tags, overlay, bundle, compiler_count

**Domain 特徵（20d）：**
- Registrar/TLD（ordinal + frequency）, creation/update age
- 分類標記：malware/phishing/C2/botnet binary flags
- DNS：has_A/AAAA/MX, record count, WHOIS, JARM

**IP 特徵（15d）：**
- Country/continent（ordinal + frequency）, log(ASN), AS owner
- RIR, CIDR prefix, JARM, HTTPS certificate, tags

**Email 特徵（6d）：** protonmail/tutanota/yandex/mail.ru/mainstream/custom domain indicators

**Ordinal encoding**：使用 `build_vocabularies.py` 預建詞彙表，出現次數 < 2 的值映射為 `__OTHER__`（index 0）。共 11 個分類欄位。

### 3.2 L2：鄰居統計特徵（35 維）

描述 IoC 在 KG 中的局部拓撲結構：

**邊類型分布（12d）：** 10 種 VT 關係類型 + "other" 的 log-count, log(total_degree)

**1-hop 鄰居統計（10d）：**
- Detection ratio: mean, max, std
- 類型組成：ratio_file, ratio_domain, ratio_ip, ratio_email
- 多樣性：IP country entropy, IP ASN entropy, domain TLD entropy

**2-hop 統計（5d）：** log(2-hop count), mean detection ratio, 類型比例

**邊屬性（8d）：**
- Malicious count: mean, max; undetected count: mean
- Resolution date count, dropped_file type_tag 多樣性
- Depth 分布：ratio_depth0, ratio_depth1
- log(total_source_reports)

### 3.3 L3：圖重疊偵測特徵（7 + K 維，K = 組織數）

衡量 IoC 的鄰居與各組織 KG 的重疊程度：

**直接重疊（3d）：**
- 擁有此 IoC 的組織數
- is_unique_org（僅屬一個組織）
- is_shared（> 1 個組織）

**鄰居重疊（4d）：**
- 鄰居中有重疊的比例
- 鄰居重疊涉及的 distinct org 數
- 最大組織的 normalized vote share
- 組織投票的 entropy

**Per-org 投票（K 維）：** 每個組織的加權票數，權重由三因素決定：
- Detection ratio weight：< 0.1 → 0.1（低偵測率懲罰）, 0.1~0.3 → 0.5, ≥ 0.3 → 1.0
- Node-IDF：1 / log₂(1 + 共享此節點的組織數)（懲罰公共基礎設施）
- Org-size normalization：weight / log₂(1 + org_size)（防止大組織主導）

### 3.4 L4：Node2Vec 圖嵌入（64 維）

使用 Node2Vec 在 Master KG 上訓練節點嵌入：

| 參數 | 值 | 說明 |
|------|-----|------|
| dimensions | 64 | 嵌入維度 |
| walk_length | 30 | 隨機遊走長度 |
| num_walks | 20 | 每節點遊走次數 |
| p | 1.0 | 返回參數（無懲罰） |
| q | 0.5 | 外向參數（偏好 BFS，捕捉局部社群結構） |
| window | 10 | Word2Vec 窗口大小 |

建圖時排除 `apt` 節點和 `has_ioc` 邊（聚焦基礎設施拓撲）。無嵌入的節點使用最佳鄰居（依 detection_ratio）的嵌入作為 fallback。

### 3.5 L5：TTP 攻擊語境特徵（~1,538 維稀疏）

#### 3.5.1 NER 實體提取

使用 [NER-BERT-CRF-for-CTI](https://github.com/stwater20/NER-BERT-CRF-for-CTI) 從 207 份 CTI 報告提取攻擊語境實體：

- **模型架構**：BERT-base-cased (768d) → Linear → CRF（BIO 標注，33 tags）
- **推論**：逐句處理，MAX_SEQ_LENGTH=512，Viterbi 解碼
- **採用 6 種實體**：Tool, Way（攻擊手法）, Exp（漏洞利用）, Purp（目的）, Idus（產業）, Area（地理）
- **忽略 7 種實體**：HackOrg（label leakage）, SecTeam, Org, OffAct, SamFile, Features, Time

#### 3.5.2 Entity Normalization（兩層過濾）

**Layer 1：表面正規化** — Strip 標點、lowercase、去重、過濾 < 2 字元

**Layer 2：白名單過濾**（依實體類型）：
- **Tool**：比對 MITRE ATT&CK Software list（1,059 個工具名），fuzzy matching threshold=80
- **Way**：攻擊手法 keyword 白名單（ATT&CK tactics/techniques），substring matching
- **Exp**：CVE ID regex 提取 + "zero-day" 標準形式
- **Area**：Demonym → 國家名映射（如 "Russian" → "Russia"）
- **Purp, Idus**：僅表面正規化

過濾效果：Tool 從 6,700 unique → 345（保留率 8.5%），Way 從 1,098 → 66（18.4%）。

#### 3.5.3 IoC-Report-TTP 映射

映射鏈：IoC → `has_ioc` edge 的 `source_reports` URL → SHA1(URL)[:10] → NER JSON

對每個 IoC 聚合其所有來源報告的 normalized entities（set union per type）。覆蓋率：6,054 / 6,182 IoCs（97.9%）。

#### 3.5.4 TF-IDF 向量化

每種實體類型獨立做 TF-IDF，再水平拼接：

| 參數 | 值 |
|------|-----|
| min_df | 2 |
| max_df | 0.8 |
| token_pattern | `r"[^\s]+"` |
| lowercase | False（已正規化） |
| Multi-word 處理 | 空格替換為底線（視為單一 token） |

**輸出**：scipy sparse matrix（~1,538 維），不做 SVD（避免 transductive leakage，XGBoost 能處理稀疏高維）。

#### 3.5.5 Fold-Aware TF-IDF（防止洩漏）

在 GroupKFold 評估中，每個 fold 獨立 fit TF-IDF vectorizer：
- 僅用訓練集報告 fit vocabulary
- Transform 所有報告（訓練 + 測試），確保測試集不引入新詞彙
- Vocabulary size 隨 fold 變動（通常 50–300 terms）

**Source-Quality Weighting**（可選）：
- 每個 IoC 的 TTP 權重 = mean(reliability_score × age_factor) across reports
- Reliability score：政府 0.90-0.95、主要廠商 0.80-0.88、研究機構 0.74、新聞 0.42-0.58、預設 0.62
- Age decay：exp(−5×10⁻⁴ × age_days)

---

## 4. Stage C：三信號 Cascade 歸因架構

### 4.1 架構總覽

```
輸入：未知 IoC
  │
  ├─ VT Details API 查詢 → 節點屬性
  ├─ VT Relationships API 查詢 → 1-hop 鄰居
  │
  ▼
┌─────────────────────────────────────┐
│  Signal 1: Graph Overlap            │
│  查詢 IoC 的 VT 鄰居是否存在於     │
│  Master KG 中任何組織的子圖         │
│                                     │
│  有 match + clear winner            │
│  → HIGH confidence (100% precision) │─── 歸因結果 + evidence trail
│                                     │
│  有 match + tie（多組織票數相同）    │
│  → 進入 Signal 2                    │
│                                     │
│  無 match                           │
│  → 進入 Signal 3                    │
└─────────────────────────────────────┘
  │
  ▼
┌─────────────────────────────────────┐
│  Signal 2: TTP Tie-Breaking         │
│  對 tie 的候選組織，比較 IoC 的     │
│  TTP 向量與各候選組織 profile 的    │
│  cosine similarity                  │
│                                     │
│  最高相似度組織勝出                 │
│  → MEDIUM confidence                │─── 歸因結果
│                                     │
│  無法打破 tie                       │
│  → 進入 Signal 3                    │
└─────────────────────────────────────┘
  │
  ▼
┌─────────────────────────────────────┐
│  Signal 3: ML Fallback              │
│  XGBoost 分類器                     │
│  特徵：L1(88d) + L5 TTP            │
│  輸出：calibrated probability       │
│  + abstention 拒判邏輯              │
│                                     │
│  PREDICT / ABSTAIN                  │─── 歸因結果 or 拒判
└─────────────────────────────────────┘
```

### 4.2 Signal 1：Graph Overlap（確定性歸因）

**演算法**：

1. 對 query IoC 的每個 VT 1-hop 鄰居 $n$，檢查 $n$ 是否存在於 Master KG
2. 若存在，查詢 $n$ 所屬的所有組織 $\{org_1, org_2, ...\}$
3. 對每個組織累計投票（一個 matched neighbor = 一票）
4. **Clear winner**：唯一最高票組織 → 歸因結果，confidence = HIGH
5. **Tie**：多個組織同票 → 轉入 Signal 2

**關鍵性質**（Per-Report LOO 驗證）：
- Clear winner 案例：1,516 個，**100% 正確**（零錯誤）
- Tie 案例：1,348 個（true org 永遠在候選中，tie_true_not = 0）
- 無 match：3,203 個（52.5%）

### 4.3 Signal 2：TTP Tie-Breaking

**演算法**：

1. 對 Signal 1 中 tie 的候選組織集合 $\{org_a, org_b, ...\}$
2. 建構各候選組織的 TTP profile：
   - 收集該組織所有報告的 normalized entities
   - 排除當前 IoC 所屬報告（防止洩漏）
   - 合併為單一 entity set per type
3. 建構 query IoC 的 TTP 向量：
   - 從 IoC 的 source_reports 收集 normalized entities
4. 對每個候選組織，計算 TTP profile 與 IoC 向量的 cosine similarity
5. 選擇最高 similarity 的組織

**結果**：94.6% 的 tie 成功打破（1,272 / 1,345），打破後 accuracy 50.8%。

### 4.4 Signal 3：ML Fallback（含 Calibration 與 Abstention）

**分類器**：XGBoost

| 參數 | 值 |
|------|-----|
| n_estimators | 500 |
| max_depth | 8 |
| learning_rate | 0.05 |
| subsample | 0.8 |
| colsample_bytree | 0.8 |
| min_child_weight | 3 |
| eval_metric | mlogloss |
| sample_weight | balanced（n / k × count_c） |

**特徵組合**：L1(88d) + L5 fold-aware TTP（Cascade A，clean 版本）

**Temperature Calibration**：
- 載入 `calibrator.pkl`，若 method = temperature_scaling：
  - $\text{logits} = \log(\text{proba})$
  - $\text{calibrated} = \text{softmax}(\text{logits} / T)$

**三條件 Abstention 拒判**：

| 條件 | 觸發規則 | abstain_reason |
|------|---------|----------------|
| High conflict | margin < 0.08 **或** (distinct_orgs ≥ 3 **且** dominant_ratio < 0.40) | `high_conflict` |
| Open-set suspicion | calibrated confidence < open_set_threshold **且** overlap_ratio < 0.05 | `open_set` |
| Low confidence | calibrated confidence < low_confidence_threshold | `low_confidence` |

若任一條件觸發 → `decision = ABSTAIN`，否則 → `decision = PREDICT`。

---

## 5. Stage D：評估方法論

### 5.1 Campaign-Aware 評估：為何 Random Split 不可靠

**問題**：同一份 CTI 報告的 IoC 來自同一 campaign，共享相同基礎設施（C2、registrar、ASN）。StratifiedKFold 讓同 campaign 的 IoC 同時出現在 train/test，分類器只需 memorize campaign fingerprint 即可猜對。

**解方**：GroupKFold 以報告為單位分組。

**Report-Connected Groups（Union-Find）**：
1. 每個報告 URL 映射到其第一個 IoC
2. 後續共享同一報告的 IoC 通過 Union-Find 合併
3. Transitive closure：共享任何報告的 IoC 屬於同一 group
4. `assert_no_report_leak()`：斷言 train/test 零報告重疊

**實證差距**：

| 特徵組合 | StratifiedKFold | GroupKFold | Δ |
|---------|----------------|-----------|---|
| L1 (88d) | 63.8% | 14.0% | **−49.8%** |
| L1+L2+L3+L4 (209d) | 72.1% | 16.1% | **−56.0%** |
| L5 only (TTP) | — | 34.1% | — |

### 5.2 Per-Report Leave-One-Out（Graph Overlap 驗證）

**演算法**：

1. 對每份報告 $r$，移除 $r$ 的所有 IoC 及其 **exclusive L1 鄰居**
   - Exclusive L1 node：其所有 L0 鄰居都屬於被移除的報告
2. 對每個被移除的 IoC，用 Signal 1 在剩餘 KG 上做歸因
3. 統計 match rate, clear winner accuracy, tie rate

### 5.3 False-Flag 偽旗攻擊韌性

**3 種攻擊**（各 3 個強度 r ∈ {0.1, 0.3, 0.5}）：

| 攻擊 | 操作 |
|------|------|
| Tool mimicry | 替換 r 比例的 Tool tokens 為 donor APT 的 top-60 Tool tokens |
| Way mimicry | 替換 r 比例的 Way tokens 為 donor APT 的 top-60 Way tokens |
| Source poisoning | 將高信任來源（reliability ≥ 0.8）的可信度乘以 (1 − r) |

**4 種防禦策略**：

1. `baseline_raw`：raw TF-IDF，無防禦
2. `weighted_l5`：source-quality weighted TF-IDF
3. `weighted_l5_calibrated`：+ temperature scaling (T=5.0)
4. `weighted_l5_calibrated_abstain`：+ abstention

評估均使用 GroupKFold（5-fold），每 fold 獨立 fit TF-IDF。

### 5.4 Open-Set 未知組織偵測

**Actor Holdout**：輪流留出 1 個 APT 作為 unknown，用剩餘組織訓練。

- Unknown detection score = 1 − max(calibrated_proba)
- Threshold：open_set_conf_threshold
- 指標：AUROC, FPR@95%TPR, unknown misattribution rate

### 5.5 Selective Classification

**Coverage-Risk Curve**：

1. 按 calibrated confidence 排序（降序）
2. 對每個 coverage level c：選擇 top-k 樣本（k = ⌈c × n⌉），計算 risk = 1 − accuracy
3. AURC = ∫ risk(c) dc

---

## 6. 訓練資料篩選

| 條件 | 說明 |
|------|------|
| depth = 0 | 僅 L0 IoC（來自 CTI 報告的直接 IoC） |
| 單一組織 | 排除多組織共享的 IoC（避免標籤模糊） |
| 組織規模 ≥ 100 IoCs | 排除過小組織（APT12/16/17/18/19 已移除） |

最終訓練集：**5,961 筆 IoC，15 個 APT 組織，127 個報告群組**。

---

## 7. 推論流程（`inference.py`）

單筆 IoC 推論完整步驟：

```
1. IoC 類型偵測（regex: hash/domain/IP）
2. VT Details API 查詢 → 節點屬性
3. VT Relationships API 查詢 → 1-hop 鄰居列表
4. 臨時注入 Master KG 的 adjacency dict
5. 提取 L1(88d) + L2(35d) + L3(7+Kd) + L4(64d) 特徵
6. Imputation（median strategy）
7. XGBoost predict_proba → raw probabilities
8. Temperature calibration → calibrated probabilities
9. Abstention 三條件檢查
10. 輸出：decision, top_k predictions, confidence, abstain_reason, overlap_stats
```

**輸出結構**（JSON）：
```json
{
  "ioc": "185.45.67.89",
  "type": "ip",
  "status": "attributed" | "unknown",
  "decision": "PREDICT" | "ABSTAIN",
  "abstain_reason": null | "high_conflict" | "open_set" | "low_confidence",
  "confidence": 0.85,
  "confidence_raw": 0.72,
  "confidence_calibrated": 0.85,
  "confidence_margin": 0.43,
  "top_k": [
    {"org": "APT28", "probability": 0.85, "probability_raw": 0.72},
    {"org": "Sandworm_Team", "probability": 0.08, "probability_raw": 0.12}
  ],
  "overlap_stats": {
    "overlap_ratio": 0.67,
    "distinct_orgs": 1,
    "dominant_ratio": 1.0
  }
}
```
