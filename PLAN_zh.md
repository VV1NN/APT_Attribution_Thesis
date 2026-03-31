# APT 歸因與攻擊路徑預測系統 — 實作計畫書

> 最後更新：2026-03-31
> 狀態：規劃中

---

## 一、現況盤點

### 1.1 已完成的模組

#### 知識圖譜建構 Pipeline
- [x] IoC 清洗（`clean_iocs_v2.py`）：去重、defang 還原、eTLD 黑名單、跨 hash 合併
- [x] VT 元資料擴充（`build_knowledge_graph.py`）：Phase 1 查 VT Details API 取得完整節點屬性
- [x] VT 關係發現（`fetch_vt_relationships.py`）：11 種邊類型，全域快取避免重複查詢
- [x] 單一組織 KG 建構：Phase 2 載入 VT Relationships，發現 L1 鄰居並查詢其 VT Details
- [x] Master KG 合併（`merge_knowledge_graphs.py`）→ 66,444 節點 / 109,443 條邊

#### 歸因系統
- [x] 詞彙表建構（`build_vocabularies.py`）：ordinal encoding + 頻率表
- [x] 四層特徵提取（`build_features.py`）：L1(88d) + L2(35d) + L3(7+Kd) + L4(64d)
- [x] Node2Vec 訓練（`train_node2vec.py`）：64 維，p=1.0, q=0.5
- [x] XGBoost 分類器 + 5-fold CV（`eval_allnodes_correct_cv.py`）
- [x] SHAP 可解釋性分析（`run_shap_analysis.py`）
- [x] 推論 Pipeline（`inference.py`）：單筆/批次 IoC 歸因

### 1.2 目前實驗結果（15 個組織，不含 TTP）

| 指標 | 無門檻 | 信心度門檻 0.3 |
|------|--------|--------------|
| Micro-F1 | 80.0% | 95.7% |
| Macro-F1 | 81.8% | 95.2% |
| Coverage | 100% | 81.1% |
| Top-3 Accuracy | 90.1% | — |

### 1.3 資料資產

| 項目 | 數量 |
|------|------|
| 已建 KG 的 APT 組織 | 16 個 |
| Master KG 節點數 | 66,444 |
| Master KG 邊數 | 109,443 |
| CTI 報告全文 | 203 份（5.3 MB） |
| 每個 IoC 有 `sources` 欄位 | 可溯源至原始報告 |

---

## 二、組織選擇

### 2.1 保留的 16 個組織（已有知識圖譜）

已移除 5 個不堪用的組織（APT12/16/17/18/19 — IoC 數量和 KG 節點均不足）。

| 地域 | 組織 | 報告數 | Cleaned IoCs | KG Nodes |
|------|------|--------|-------------|----------|
| 俄羅斯 (6) | APT28 | 25 | 296 | 4,888 |
| | APT29 | 28 | 825 | 2,662 |
| | Sandworm_Team | 27 | 433 | 6,713 |
| | Turla | 14 | 254 | 3,544 |
| | Gamaredon_Group | 6 | 734 | 7,515 |
| | Wizard_Spider | 8 | 799 | 6,503 |
| 北韓 (2) | Lazarus_Group | 23 | 505 | 11,529 |
| | Kimsuky | 11 | 251 | 1,107 |
| 伊朗 (3) | Magic_Hound | 11 | 960 | 7,224 |
| | MuddyWater | 8 | 340 | 6,725 |
| | OilRig | 14 | 210 | 3,173 |
| 越南 (1) | APT32 | 9 | 306 | 4,250 |
| 中東 (1) | APT-C-23 | 4 | 261 | 3,334 |
| 拉美 (1) | APT-C-36 | 1 | 141 | 1,135 |
| 中國 (1) | APT1 | 2 | 87 | 2,444 |
| 犯罪組織 (1) | FIN7 | 12 | 365 | 5,083 |

### 2.2 待決事項

- Transparent_Tribe（南亞）：VT Relationships 已完成，KG 建構中斷，待明日恢復
- APT-C-36（僅 1 份報告、141 筆 IoC）：是否移除？
- 是否新增其他組織？（需消耗 VT API 配額）

---

## 三、Phase 1：TTP 攻擊語境提取

### 3.1 目標

從 203 份 CTI 報告中提取攻擊語境實體（Tool、Way、Exp、Purp、Idus、Area），建立「IoC → 報告 → TTP」的三層對應關係。

### 3.2 為什麼要做這件事

現有的歸因系統只使用 **技術指標**（VT metadata、圖拓撲），忽略了 IoC 出現的 **攻擊語境**。我們觀察到：

1. **同一 IoC，不同語境**：同一個 C2 IP 可能同時出現在 spearphishing 和 watering hole 的報告中，攻擊手法不同暗示歸因方向不同
2. **Tool 是 APT 的指紋**：每個 APT 組織偏好使用特定工具（APT28→X-Agent, Lazarus→ThreatNeedle），工具名稱本身具有強歸因力
3. **TTP 比 IoC 更持久**：APT 組織會更換基礎設施（IP/domain），但攻擊手法的改變較慢

### 3.3 子任務 1A：NER-BERT-CRF 環境建置與執行

**模型來源：** https://github.com/stwater20/NER-BERT-CRF-for-CTI

**模型架構：** BERT-base-cased → Linear → CRF（移除 BiLSTM，直接用 BERT 的 token embedding 接 CRF 做序列標注）

**可提取的 13 種實體類型（BIO 標注）：**

| 實體類型 | 說明 | 是否採用 | 用途 |
|---------|------|---------|------|
| **Tool** | 惡意工具/惡意程式 | ✅ | L5 特徵 + 攻擊路徑 |
| **Way** | 攻擊手法 | ✅ | L5 特徵 + 攻擊路徑 |
| **Exp** | 漏洞利用/CVE | ✅ | L5 特徵 + 攻擊路徑 |
| **Purp** | 攻擊目的 | ✅ | L5 特徵 |
| **Idus** | 目標產業 | ✅ | L5 特徵 |
| **Area** | 目標地區 | ✅ | L5 特徵 |
| HackOrg | APT 組織名稱 | ❌ | Label leakage |
| SecTeam | 資安團隊 | ❌ | 與歸因無關 |
| Org | 受害組織 | ❌ | 資訊量不足 |
| OffAct | 攻擊行為 | ❌ | 描述太籠統 |
| SamFile | 樣本檔名 | ❌ | 與 IoC 重疊 |
| Features | 系統功能 | ❌ | 描述太籠統 |
| Time | 時間 | ❌ | 可另外處理 |

**執行步驟：**

```
1. 環境準備
   $ git clone https://github.com/stwater20/NER-BERT-CRF-for-CTI.git
   $ cd NER-BERT-CRF-for-CTI
   $ pip install -r requirements.txt  # 需要 PyTorch + transformers
   # 下載預訓練模型 checkpoint

2. 單篇測試
   $ python predict.py -I "APT28 used X-Agent via spearphishing exploiting CVE-2017-0262"
   → X-Agent: B-Tool, spearphishing: B-Way, CVE-2017-0262: B-Exp

3. 批次推論（自行撰寫腳本）
   輸入：org_iocs/{org}/sources/*.txt（203 份報告）
   輸出：scripts/ttp_extraction/{org}/{report_hash}.json
```

**預期產出格式：**
```json
{
  "report_file": "securelist_sofacy_2017.txt",
  "org": "APT28",
  "entities": {
    "Tool": ["X-Agent", "Zebrocy", "GAMEFISH", "SPLM", "JHUHUGIT"],
    "Way": ["spearphishing", "Flash exploit", "USB stealer"],
    "Exp": ["CVE-2017-0262", "CVE-2017-0263"],
    "Purp": ["cyber-espionage"],
    "Idus": ["military", "defense", "government"],
    "Area": ["NATO", "Ukraine", "Central Asia"]
  }
}
```

**效能預估：**
- 203 份報告，平均 ~3,500 words/report
- GPU 環境：~10-20 分鐘
- CPU 環境：~30-60 分鐘

### 3.4 子任務 1B：TRAM ATT&CK 映射（可選增強）

**工具來源：** https://github.com/center-for-threat-informed-defense/tram/

**目的：** 補充標準化的 ATT&CK Technique ID（如 T1566.001），NER-BERT-CRF 只能抽出「spearphishing」文字，TRAM 可以映射到正式的 Technique ID。

**策略：** 僅保留信心度 100% 的結果（APT-MMF 論文也採用此策略），避免 false positive。

**產出：** 為每份報告的 NER 結果補充 `techniques_tram` 欄位：
```json
{
  "techniques_tram": [
    {"id": "T1566.001", "name": "Spearphishing Attachment", "confidence": 1.0},
    {"id": "T1203", "name": "Exploitation for Client Execution", "confidence": 1.0}
  ]
}
```

**注意：** 此步驟為 optional。如果時間不足，可跳過，僅使用 NER 結果即可。Phase 3 的攻擊路徑預測若要映射到 kill chain 階段，有 TRAM 的 Technique ID 會更準確。

### 3.5 子任務 1C：實體正規化

NER 會抽出同一實體的不同寫法，需要統一：

```
問題範例：
  "X-Agent", "XAgent", "Sofacy backdoor", "SPLM/CHOPSTICK" → 同一個工具
  "spear phishing", "spearphishing", "spear-phishing" → 同一個手法
  "CVE-2017-0262", "cve-2017-0262" → 同一個漏洞
```

**處理步驟：**

1. **收集原始實體**：彙總 203 份報告的所有 NER 輸出
2. **自動正規化**：
   - CVE：regex `CVE-\d{4}-\d{4,7}` 統一大寫格式
   - 文字正規化：lowercase → 移除連字符/空格差異
3. **半自動對照表**：
   - Tool：以 MITRE ATT&CK Software 名單為基礎做 fuzzy matching
   - Way：建立攻擊手法同義詞表（約 50 種常見手法）
4. **產出標準化詞彙表**：`scripts/ttp_extraction/ttp_vocabularies.json`

```json
{
  "tool_vocab": {"X-Agent": 0, "Zebrocy": 1, "Mimikatz": 2, "Cobalt Strike": 3, ...},
  "way_vocab": {"spearphishing": 0, "watering_hole": 1, "template_injection": 2, ...},
  "exp_vocab": {"CVE-2017-0262": 0, "CVE-2017-0263": 1, ...},
  "purp_vocab": {"espionage": 0, "financial_theft": 1, "sabotage": 2, ...},
  "idus_vocab": {"government": 0, "military": 1, "financial": 2, "defense": 3, ...},
  "area_vocab": {"ukraine": 0, "middle_east": 1, "nato": 2, "central_asia": 3, ...}
}
```

### 3.6 子任務 1D：建立 IoC → 報告 → TTP 對應關係

**核心邏輯：**

```
對於每個 cleaned IoC：
  1. 讀取其 "sources" 欄位 → 報告 URL 列表
  2. 將 URL 對應到 sources/*.txt 的實際檔案
  3. 查詢該報告的 NER 結果
  4. 聚合該 IoC 所有來源報告的 TTP 實體
```

**URL 對應邏輯：**

IoC 的 sources 欄位是 URL（如 `https://securelist.com/sofacy-2017/83930/`），而報告檔名是經過 hash 的（如 `securelist.com_sofacy_2017_43867c26a2.txt`）。需要建立 URL → filename 的對應表。

**做法：** 從檔名中提取 domain + path 部分，與 IoC 的 source URL 做前綴比對。

**產出：** `scripts/ttp_extraction/ioc_ttp_mapping.json`
```json
{
  "md5_02b79c468c38c4312429a499fa4f6c81": {
    "org": "APT28",
    "source_reports": ["securelist_sofacy_2017"],
    "tools": ["X-Agent", "Zebrocy", "GAMEFISH"],
    "ways": ["spearphishing", "Flash_exploit"],
    "exps": ["CVE-2017-0262", "CVE-2017-0263"],
    "purps": ["espionage"],
    "idus": ["military", "defense"],
    "areas": ["NATO", "Ukraine"]
  }
}
```

### 3.7 預期涵蓋率

| IoC 類型 | 有 sources 對應？ | TTP 涵蓋率 |
|---------|----------------|-----------|
| L0 IoC（CTI 報告提取的） | ✅ 有 | 高（大部分可對應到報告） |
| L1 IoC（VT 發現的鄰居） | ❌ 無 | 零（無報告來源） |
| 訓練集用的 L0 IoC | ✅ 有 | 預計 >80% 的 L0 IoC 能對應到至少一份報告 |

缺少 TTP 的 IoC 將得到全零的 L5 特徵向量。XGBoost 能自然處理稀疏特徵，不需額外處理。

---

## 四、Phase 2：L5 TTP 特徵工程

### 4.1 目標

將每個 IoC 的 TTP 攻擊語境轉換為數值特徵向量（L5），與現有的 L1-L4 特徵串接後一起送入分類器。

### 4.2 特徵設計：TF-IDF 加權 Multi-hot 向量

**對於每個 IoC，計算以下特徵：**

```
Tool 特徵（N_tool 維）：
  對於 tool_vocab 中的每個工具：
    if 這個工具出現在此 IoC 的 TTP context 中：
      特徵值 = TF × IDF
    else：
      特徵值 = 0

  其中：
    TF = 此工具在該 IoC 的來源報告中出現的次數
    IDF = log(總報告數 / 包含此工具的報告數)

Way、Exp、Purp、Idus、Area 同理計算。
```

**設計理念：**
- 稀有的 TTP（只有某個 APT 使用的工具）→ 高 IDF → 強歸因力
- 常見的 TTP（每個 APT 都用 spearphishing）→ 低 IDF → 弱歸因力
- 這與資訊檢索中的 TF-IDF 邏輯一致

**預估維度：**

| 類別 | 預估詞彙量 | 說明 |
|------|-----------|------|
| Tool | 30-50 維 | 正規化後的工具名稱 |
| Way | 15-20 維 | 常見攻擊手法 |
| Exp | 20-30 維 | 報告中提到的 CVE |
| Purp | 5-8 維 | 攻擊目的（espionage, financial...） |
| Idus | 8-12 維 | 目標產業 |
| Area | 10-15 維 | 目標地區 |
| **合計** | **~88-135 維** | |

**降維策略（若維度過高）：**
- 方案 A：僅保留 IDF 排名前 K 的特徵
- 方案 B：PCA 降至固定 ~80 維
- 方案 C：僅使用 Tool + Way + Exp（跳過 Purp/Idus/Area）→ ~65-100 維

### 4.3 整合至訓練 Pipeline

**修改 `build_features.py`：**
```python
# 在 L4（Node2Vec）之後新增：
ttp_mapping = load_json("scripts/ttp_extraction/ioc_ttp_mapping.json")
ttp_vocab = load_json("scripts/ttp_extraction/ttp_vocabularies.json")

for each L0 IoC:
    ttp_context = ttp_mapping.get(ioc_id, {})
    l5 = compute_tfidf_vector(ttp_context, ttp_vocab)  # ~80-135d
    final_features[ioc_id] = concat(l1, l2, l3, l4, l5)
```

**修改 `train_classifier.py`：**
- 接受新的特徵維度（原 ~194d → ~274-330d）
- 新增 L5 特徵名稱以便 SHAP 分析

### 4.4 特徵完整總覽

| 特徵層 | 維度 | 來源 | 內容 |
|--------|------|------|------|
| L1: 節點自身 | 88d | KG 節點屬性 | detection_ratio, PE info, WHOIS, ASN, JARM, 檔案類型... |
| L2: 鄰域統計 | 35d | KG 鄰居 | 鄰居類型分布, 平均惡意度, degree... |
| L3: 跨組織重疊 | 7+Kd | Master KG | 鄰居中屬於其他 APT 的節點分布 |
| L4: 圖嵌入 | 64d | Node2Vec | 圖結構 embedding |
| **L5: TTP 攻擊語境** | **~80d** | **CTI 報告 NER** | **Tool/Way/Exp/Purp/Idus/Area 的 TF-IDF 向量** |

---

## 五、Phase 3：攻擊路徑預測

### 5.1 目標

在歸因完成後，根據被歸因 APT 組織的歷史 TTP 行為模式，預測下一步可能的攻擊技術，並提供防禦建議。

### 5.2 為什麼可行

CTI 報告通常會描述一個完整（或部分）的攻擊流程：

```
APT28 報告範例：
  "攻擊者透過 spearphishing 郵件（Initial Access）投遞含 Flash exploit
  （Execution）的文件，下載 X-Agent 後門（Persistence），進行鍵盤側錄
  （Collection），最後透過加密 HTTPS 通道回傳資料（Exfiltration）。"
```

從多份報告中可以統計出每個 APT 組織的 **TTP 轉移機率**。

### 5.3 子任務 3A：建立 TTP 序列資料庫

**對於每份報告：**

1. 取出該報告的所有 NER 實體（Tool/Way/Exp）
2. 將每個實體映射到 ATT&CK Kill Chain 階段：

```
Kill Chain 14 階段：
  Reconnaissance → Resource Development → Initial Access → Execution
  → Persistence → Privilege Escalation → Defense Evasion → Credential Access
  → Discovery → Lateral Movement → Collection → C2 → Exfiltration → Impact
```

3. 映射規則（部分範例）：

```python
KILL_CHAIN_MAP = {
    # Tool → 根據工具的主要功能映射
    "X-Agent":       "Persistence",        # 後門
    "Zebrocy":       "Persistence",        # 後門
    "Mimikatz":      "Credential Access",  # 竊取憑證
    "Cobalt Strike": "C2",                 # C2 框架
    "keylogger":     "Collection",         # 鍵盤側錄

    # Way → 直接映射到攻擊階段
    "spearphishing":     "Initial Access",
    "watering_hole":     "Initial Access",
    "template_injection": "Execution",
    "DLL_sideloading":   "Defense Evasion",
    "credential_dump":   "Credential Access",

    # Exp → 通常是 Execution 或 Initial Access
    "CVE-*":         "Execution",  # 預設：漏洞利用屬於 Execution
}
```

4. 按 Kill Chain 順序排列（而非報告中的文字順序，因為文字順序不可靠）
5. 記錄每份報告的攻擊階段序列

### 5.4 子任務 3B：TTP 轉移模型

**對於每個 APT 組織：**

1. 彙總該組織所有報告的攻擊序列
2. 統計階段間的轉移次數
3. 計算轉移機率：`P(階段_j | 階段_i) = count(i→j) / count(i)`
4. 儲存為 14×14 的轉移矩陣

**範例：**
```
APT28 的 TTP 轉移模型（基於 25 份報告）：
  Initial Access → Execution:      出現 20/25 份 = 80%
  Execution → Persistence:         出現 18/25 份 = 72%
  Persistence → Collection:        出現 15/25 份 = 60%
  Collection → C2:                 出現 22/25 份 = 88%
  C2 → Exfiltration:               出現 19/25 份 = 76%

Lazarus_Group 的 TTP 轉移模型（基於 23 份報告）：
  Initial Access → Execution:      出現 15/23 份 = 65%
  Execution → Persistence:         出現 12/23 份 = 52%
  Persistence → Credential Access: 出現 14/23 份 = 61%
  → 兩個 APT 的轉移模式不同，反映不同的行為偏好
```

### 5.5 子任務 3C：預測 Pipeline

**擴充 `inference.py` 的輸出：**

```
輸入：一個 IoC（hash, domain, 或 IP）

Step 1（現有）：歸因
  → "此 IoC 屬於 APT28（信心度 95%）"

Step 2（新增）：判斷當前攻擊階段
  → 查詢此 IoC 的 TTP context（來自其來源報告）
  → 映射到 Kill Chain 階段
  → "當前階段：Initial Access（偵測到 spearphishing）"

Step 3（新增）：預測下一步
  → 查詢 APT28 的轉移模型
  → "APT28 在 Initial Access 之後，歷史上的下一步：
      1. Execution（80%）— 可能透過漏洞利用或惡意巨集
      2. Persistence（65%）— 可能部署 X-Agent/Zebrocy 後門"

Step 4（新增）：防禦建議
  → 將預測的技術映射到 MITRE ATT&CK 的緩解措施
  → "建議防禦措施：
      - 封鎖來自外部的 Office 巨集執行
      - 監控已知的 X-Agent/Zebrocy 指標
      - 啟用端點安全的漏洞利用防護功能"
```

### 5.6 預測結果範例

```
═══════════════════════════════════════════════════
  IoC 歸因與攻擊路徑預測報告
═══════════════════════════════════════════════════

  輸入 IoC：185.45.67.89（IP address）

  ▸ 歸因結果
    Top-1：APT28 / Fancy Bear（信心度 95.3%）
    Top-2：Sandworm_Team（信心度 2.1%）
    Top-3：Turla（信心度 1.2%）

  ▸ 當前攻擊階段
    此 IP 出現在報告 "securelist_sofacy_2017" 中
    報告語境：spearphishing campaign 的 C2 伺服器
    判定階段：Command and Control (C2)

  ▸ 攻擊路徑預測（基於 APT28 的 25 份歷史報告）
    C2 之後的下一步：
    → Exfiltration（76%）— 預計透過加密通道回傳竊取資料
    → Collection（62%）— 可能正在進行鍵盤側錄或檔案竊取
    → Lateral Movement（45%）— 可能嘗試橫向移動到其他主機

  ▸ 防禦建議
    1. 立即封鎖此 IP 的所有出站連線
    2. 檢查網路日誌中是否有大量加密流量外傳
    3. 對內部網路進行橫向移動偵測
    4. 掃描端點是否存在 X-Agent/Zebrocy 特徵
═══════════════════════════════════════════════════
```

---

## 六、Phase 4：實驗評估

### 6.1 歸因消融實驗（Ablation Study）

| 實驗 | 特徵組合 | 預期結果 |
|------|---------|---------|
| Baseline | L1+L2+L3+L4 | Micro-F1 ≈ 80%（目前） |
| +TTP 特徵 | L1+L2+L3+L4+**L5** | Micro-F1 ≈ ?%（預期提升） |
| +TTP + 門檻 | L1+L2+L3+L4+L5 + threshold=0.3 | Micro-F1 ≈ ?%（預期 >95%） |

使用 5-fold CV，與 `eval_allnodes_correct_cv.py` 相同的評估架構。

### 6.2 TTP 特徵分析

- **SHAP 分析：** 哪些 TTP 特徵對歸因貢獻最大？
- **分類別消融：** 只用 Tool vs 只用 Way vs 只用 Exp vs 全部
- **分組織分析：** 哪些 APT 組織從 TTP 特徵中受益最多？
- **涵蓋率影響：** 有 TTP 的 IoC vs 無 TTP 的 IoC，F1 差異

### 6.3 攻擊路徑預測評估

**評估方法：Leave-One-Report-Out**

1. 對於每個 APT 組織，依序留出一份報告作為測試
2. 用剩餘報告建構轉移模型
3. 預測被留出報告的攻擊階段序列
4. 比較預測的下一階段與實際的下一階段
5. 指標：Top-1 準確率、Top-3 準確率

**限制與說明：**
- 某些組織報告數偏少（如 APT-C-36 僅 1 份），無法做 leave-one-out
- 報告中的 TTP 序列可能不完整（只描述部分攻擊流程）
- 在論文中定位為「初步的攻擊路徑預測方法」，未來可透過更多報告改善

### 6.4 與 APT-MMF 比較

| 比較面向 | APT-MMF | 本研究 |
|---------|---------|--------|
| 歸因單位 | CTI 報告（report-level） | 單一 IoC（IoC-level） |
| 輸入特徵 | Attr(64d)+BERT(64d)+N2V(128d) | L1-L4(194d)+L5 TTP(~80d) |
| 圖結構 | 報告為中心的異質圖 | APT 為中心的 VT-enriched KG |
| 模型 | Multilevel Heterogeneous GAT | XGBoost |
| 攻擊路徑預測 | ❌ 無 | ✅ 有 |
| Micro-F1 | 83.21% | ?%（待實驗） |
| 信心度機制 | ❌ 無 | ✅ 有（threshold 機制） |
| 可解釋性 | Attention weights | SHAP values |
| 實務應用性 | 需要完整報告才能歸因 | 只需一個 IoC 即可歸因 |

---

## 七、實作時程

### 第一週：TTP 提取

- [ ] NER-BERT-CRF 環境建置（clone repo, 安裝 PyTorch, 下載 model）
- [ ] 撰寫批次推論腳本（`run_ner_on_reports.py`）
- [ ] 對 203 份報告執行 NER 推論
- [ ] 實體正規化 → `ttp_vocabularies.json`
- [ ] 建立 IoC → Report → TTP 對應關係 → `ioc_ttp_mapping.json`
- [ ] （可選）安裝 TRAM，對報告做 ATT&CK Technique 映射

### 第二週：L5 特徵 + 重新訓練

- [ ] 實作 `build_ttp_features.py`（TF-IDF multi-hot 向量）
- [ ] 將 L5 整合至 `build_features.py`
- [ ] 用 L1+L2+L3+L4+L5 重新訓練 XGBoost
- [ ] 執行消融實驗（Baseline vs +L5）
- [ ] L5 的 SHAP 分析

### 第三週：攻擊路徑預測

- [ ] 從報告中提取 TTP 序列，映射到 Kill Chain 階段
- [ ] 建構每個 APT 的 TTP 轉移模型
- [ ] 擴充 `inference.py`，加入路徑預測功能
- [ ] Leave-One-Report-Out 評估
- [ ] 防禦建議映射（Technique → MITRE Mitigation）

### 第四週：評估 + 論文撰寫

- [ ] 完成所有消融實驗
- [ ] 製作與 APT-MMF 的比較表
- [ ] 撰寫論文第三章（方法）和第四章（實驗）
- [ ] 繪製論文用的架構圖

### 持續進行：KG 擴充（視 VT API 配額而定）

- [ ] 完成 Transparent_Tribe KG（用 `--skip-query` 從斷點恢復）
- [ ] 決定是否新增其他組織
- [ ] 若組織有變動，重建 Master KG

---

## 八、新增檔案結構

```
scripts/
  ttp_extraction/                     # TTP 提取模組
    run_ner_on_reports.py             # 批次 NER 推論（203 份報告）
    run_tram_on_reports.py            # （可選）TRAM ATT&CK 映射
    normalize_entities.py             # 實體去重 + 別名對照
    build_ioc_ttp_mapping.py          # IoC → Report → TTP 對應
    build_ttp_sequences.py            # TTP 序列提取（攻擊路徑用）
    ttp_vocabularies.json             # 正規化後的實體詞彙表
    ioc_ttp_mapping.json              # IoC 級 TTP 對應結果
    ttp_sequences.json                # 每個 APT 的 TTP 轉移資料
    {org}/                            # 每份報告的 NER 結果
      {report_hash}.json
  build_ttp_features.py               # L5 TTP 特徵提取
  eval_with_ttp.py                    # 消融實驗：baseline vs +TTP
  predict_attack_path.py              # 攻擊路徑預測邏輯
```

---

## 九、風險評估與因應

| 風險 | 影響程度 | 發生機率 | 因應措施 |
|------|---------|---------|---------|
| NER 模型在我們的報告上準確度不足 | 高 | 中 | 使用 keyword + regex 作為 baseline 備案 |
| 部分組織報告數太少（APT-C-36: 1 份） | 中 | 確定 | 接受 TTP 特徵稀疏，或移除該組織 |
| TTP 轉移模型因樣本不足而不可靠 | 中 | 高 | 在論文中定位為「初步方法」，強調方法論 |
| VT API 配額不足，無法擴充新組織 | 低 | 中 | 聚焦現有 16 個組織 |
| L5 特徵未能提升 F1 | 高 | 低 | 強調攻擊路徑預測作為主要貢獻 |
| NER-BERT-CRF 環境建置失敗 | 中 | 低 | 改用 keyword + regex 抽取 |
| IoC 的 sources URL 對不上報告檔名 | 中 | 中 | 手動檢查並建立 URL→filename 對照表 |

---

## 十、論文 Story

### 論文題目（草稿）

**基於 VT-Enriched IoC 知識圖譜與 TTP 攻擊語境特徵的 APT 歸因與攻擊路徑預測**

> APT Attribution and Attack Path Prediction via VT-Enriched IoC Knowledge Graph with TTP Context Features

### 核心論述

現有的 APT 歸因方法存在兩個主要限制：

1. **歸因粒度過粗**：以報告為單位進行歸因（如 APT-MMF），但實務中 SOC 分析師拿到的是單一 IoC，不是完整報告
2. **特徵維度單一**：malware-based 方法只用技術指標，CTI-based 方法只用文本語義，未能融合兩者

我們提出一個系統，解決以下問題：

1. 在 **IoC 層級** 進行歸因 — 輸入一個 hash/IP/domain，直接告知最可能的 APT 組織
2. 融合 **技術指標特徵**（VT metadata、圖拓撲）與 **攻擊語境特徵**（CTI 報告中的 TTP 實體）
3. 超越歸因，進一步 **預測攻擊路徑**，提供可行動的防禦建議

### 四項研究貢獻

| 編號 | 貢獻 | 說明 |
|------|------|------|
| **C1** | VT-Enriched 兩層 IoC 知識圖譜建構方法 | 利用 VirusTotal API 自動發現 L1 鄰居，擴展靜態 CTI 報告中的 IoC 關聯 |
| **C2** | 透過 IoC-Report 溯源的 TTP 攻擊語境特徵提取 | 從 NER 抽取的攻擊語境實體，經由 IoC 的報告溯源關係，投射回每個 IoC 節點 |
| **C3** | 多層特徵融合的 IoC 歸因方法 | 結合節點自身(L1)、鄰域(L2)、跨組織重疊(L3)、圖嵌入(L4)、TTP 語境(L5) 五層特徵 |
| **C4** | 基於 TTP 轉移模型的攻擊路徑預測框架 | 統計每個 APT 的歷史 TTP 序列，建構 Kill Chain 階段轉移機率，預測下一步攻擊 |
