---
title: APT Attribution Thesis - Progress Discussion
tags: presentation
slideOptions:
  theme: white
  transition: slide
---

# Multi-Signal APT Attribution Framework
## 碩論進度討論

VT-Enriched Knowledge Graph + TTP + Metadata

---

## Agenda

1. 名詞解釋（先對齊語言）
2. 系統架構 & KG 建構
3. 核心發現：Campaign Contamination
4. 三信號歸因系統 & 實驗結果
5. Link Prediction 實驗（GNN 路線）
6. 統一結論
7. 兩條論文路線 & 討論

---

## 0. 名詞解釋

---

### 基本名詞

| 術語 | 意思 | 例子 |
|------|------|------|
| **APT** (Advanced Persistent Threat) | 國家級駭客組織，長期潛伏攻擊 | APT28（俄羅斯）、Lazarus（北韓） |
| **IoC** (Indicator of Compromise) | 被入侵的痕跡/指標 | 惡意檔案 hash、C2 domain、攻擊者 IP |
| **CTI** (Cyber Threat Intelligence) | 資安公司發布的威脅情報報告 | Mandiant 的 APT1 報告、CrowdStrike 分析 |
| **VT** (VirusTotal) | Google 的惡意程式/網域掃描平台 | 上傳檔案 → 60+ 引擎掃描 → 回傳偵測結果 |
| **KG** (Knowledge Graph) | 知識圖譜，用「節點 + 邊」表示實體間關係 | `file_abc → contacted_ip → 1.2.3.4` |

---

### 機器學習相關

| 術語 | 意思 | 例子 |
|------|------|------|
| **StratifiedKFold** | 隨機分 train/test，保持類別比例 | 同一份報告的 IoC 可能同時在 train 和 test |
| **GroupKFold** | 按「群組」分，同群不會跨 train/test | 同一份報告的 IoC 只會在同一邊 |
| **micro-F1** | 全體樣本的加權準確率 | 大類主導結果 |
| **macro-F1** | 每個類別 F1 平均（不加權） | 小類也佔同等權重 |
| **XGBoost** | 梯度提升決策樹，表格資料的常勝 model | 輸入：209 維特徵向量 → 輸出：15 類 APT 預測 |

---

### 圖神經網路相關

| 術語 | 意思 | 例子 |
|------|------|------|
| **GNN** (Graph Neural Network) | 在圖結構上做深度學習的統稱 | 從鄰居「聚合訊息」來更新節點表示 |
| **R-GCN** (Relational GCN) | GNN 的一種，對不同邊類型用不同權重 | `contacted_ip` 和 `dropped_file` 走不同變換 |
| **Link Prediction (LP)** | 預測圖中缺失的邊 | 給定 `file_abc` 和 `contacted_ip`，預測連到哪個 IP |
| **ComplEx** | 複數值的 KG embedding model（非 GNN） | 每個節點一個獨立向量，用向量內積打分 |
| **MRR** (Mean Reciprocal Rank) | 正確答案的排名倒數平均 | MRR=0.335 表示正確答案平均排第 3 名 |
| **Hits@K** | 正確答案在前 K 名的比例 | Hits@10=0.53 表示 53% 的情況答案在前 10 |
| **Transductive** | 測試的節點在訓練時就看過 | 圖不變，只藏一些邊 |
| **Inductive** | 測試時出現訓練沒見過的新節點 | 新的 domain/IP 出現了 |

---

### TTP 相關

| 術語 | 意思 | 例子 |
|------|------|------|
| **TTP** (Tactics, Techniques, Procedures) | 攻擊者的行為模式 | 用 PowerShell 下載惡意程式、DLL sideloading |
| **MITRE ATT&CK** | TTP 的標準分類框架 | T1059.001 = PowerShell 執行 |
| **NER** (Named Entity Recognition) | 從文字中辨識實體的 NLP 任務 | 「APT28 使用 Mimikatz 竊取憑證」→ Tool:Mimikatz |
| **NER-BERT-CRF** | BERT + CRF 的 NER 模型 | 本研究用來從 CTI 報告提取 Tool/Way/Exp 等實體 |
| **TF-IDF** | 詞頻-逆文件頻率，衡量詞的重要性 | 「Mimikatz」在少數報告出現 → 高 IDF → 有區分力 |

---

### 評估相關（1/2）

| 術語 | 意思 | 例子 |
|------|------|------|
| **Campaign** | 同一組織的一次攻擊行動 | APT28 在 2020 年針對烏克蘭的釣魚攻擊 |
| **Campaign contamination** | 同 campaign 資料洩漏到 train 和 test | 讓 model 看似很準，實際只是「背答案」 |
| **Leave-One-Out (LOO)** | 每次拿一筆當 test | 測試能否歸因「沒見過的」IoC |
| **Coverage** | 系統能給出答案的比例 | 25.5% = 只有 1/4 的 IoC 有 match |

---

### 評估相關（2/2）

| 術語 | 意思 | 例子 |
|------|------|------|
| **Precision** | 給出答案中正確的比例 | 100% = 只要敢答就一定對 |
| **Abstention（拒判）** | 信心不足時選擇不回答 | 避免錯誤歸因比硬猜更有價值 |
| **AUROC** | ROC 曲線下面積，分類能力 | 1.0=完美、0.5=亂猜、0.764=尚可 |
| **False-Flag（偽旗）** | 攻擊者故意模仿別人來混淆歸因 | 北韓駭客在 code 放俄文假裝俄羅斯 |

---

## 1. 系統架構

---

### Knowledge Graph 建構

```
CTI 報告（143 份, 20 個 APT 組織）
  → IoC 提取 + 清洗（6,182 個入侵指標）
  → VT API 查詢每個 IoC 的 metadata + relationships
  → 兩層 KG 自動展開
```

| 指標 | 數值 | 說明 |
|------|------|------|
| Nodes | 66,444 | file=34K, domain=19.5K, ip=12.7K |
| Edges | 109,443 | 10 種 relation type |
| Organizations | 20 | 20 個已知 APT 組織 |
| Edge types | 10 種 | contacted_ip, resolves_to, dropped_file 等 |

---

### 兩層 KG 結構

**L0（來自 CTI 報告，人工標注）：**
```
apt_APT28 --has_ioc--> file_abc123
apt_APT28 --has_ioc--> domain_evil.com
```
> 「報告說 APT28 用了這個檔案/網域」

**L1（VT API 自動發現，機器擴展）：**
```
file_abc123 --contacted_ip--> ip_1.2.3.4
domain_evil.com --resolves_to--> ip_5.6.7.8
file_abc123 --dropped_file--> file_def456
```
> 「VT 告訴我們這個檔案連過哪些 IP、丟了哪些子檔案」

L1 節點佔 95%+ → VT enrichment 讓圖從 6K 擴展到 66K

---

### 推論 Pipeline（已實作 `inference.py`）

```
新的可疑 IoC 進來（例如一個未知 hash）
  │
  ├─ Step 1: VT API 查詢 → 拿到 metadata + 1-hop 鄰居
  │
  ├─ Step 2: Graph Overlap → 鄰居在 KG 裡屬於誰？→ 投票歸因
  │   └─ 如果有明確贏家 → HIGH confidence（100% 正確率）
  │
  ├─ Step 3: TTP Tie-breaking → 平手時用 TTP 特徵打破
  │   └─ MEDIUM confidence
  │
  └─ Step 4: ML Fallback → 用 metadata 特徵 + XGBoost
      └─ LOW confidence（98.5% coverage）
```

---

## 2. 核心發現：Campaign Contamination

---

### 問題：Random Split 嚴重虛高

**什麼是 campaign contamination？**

想像一次攻擊行動（campaign），駭客用了：
- 同一個 C2 server（1.2.3.4）
- 同一家 registrar（Namecheap）
- 同一組 malware（都是 PE32, 同 imphash）

這些 IoC 的 **VT metadata 幾乎一樣**。

如果 random split 把一部分放 train、一部分放 test：
→ model 只要認出「這些特徵長一樣」就能猜對
→ **不是學到 APT 的行為模式，只是記住了同一次攻擊的指紋**

---

### 實驗驗證

| 特徵 | StratifiedKFold（隨機分） | GroupKFold（按報告分） | 差距 |
|------|--------------------------|----------------------|------|
| VT metadata (88d) | 63.8% | 14.0% | **-49.8%** |
| 全部特徵 (209d) | 72.1% | 16.1% | **-56.0%** |

> 15 類隨機猜 = 6.7%
> GroupKFold 結果接近隨機 → **VT metadata 幾乎沒有跨 campaign 歸因力**

**類比：** 就像期中考只把考古題換個數字，以為學生都學會了。
GroupKFold 是出全新題目，馬上現原形。

---

### 分組方式

**問題：** 我們沒有明確的 campaign ID
**解法：** 用 Union-Find 演算法

```
如果 IoC_A 和 IoC_B 來自同一份報告 → 同一組
如果 IoC_B 和 IoC_C 來自同一份報告 → 同一組
→ 遞移閉包：A, B, C 都在同一組
```

> **報告 = campaign 的近似**
> 同一份報告描述的通常是同一次攻擊行動

Limitation: report group 不完全等於 campaign，
但足以證明 contamination 存在 → 寫在 Future Work

---

## 3. 三信號歸因系統

---

### Signal 1: Graph Overlap（圖重疊匹配）

**原理：** 新 IoC 查 VT 拿到鄰居，看這些鄰居在 KG 裡屬於哪個 APT → 多數決投票

**例子：**
```
新 file_X 查 VT 得到：
  → contacted_ip: 1.2.3.4（KG 中屬於 APT28）
  → contacted_ip: 5.6.7.8（KG 中屬於 APT28）
  → dropped_file: abc（KG 中屬於 Lazarus）

投票：APT28=2, Lazarus=1 → 歸因 APT28（clear winner）
```

---

### Graph Overlap 結果

| 指標 | Per-IoC（寬鬆版） | Per-Report（公平版） |
|------|-------------------|---------------------|
| Coverage | 68.2% | 47.5% |
| Accuracy | 93.8% | 66.7% |

**關鍵發現：**
- **Clear winner（票數最高唯一）→ 1,516 個，100% 全部正確**
- Tie（平手）→ 1,348 個，true org 永遠在候選中
- 所有「錯誤」都是平手時的隨機選擇造成

> **只要圖 overlap 有明確贏家，就一定對。**

---

### Signal 2: TTP Context（行為語境特徵）

**原理：** 從 CTI 報告用 NER 提取攻擊行為實體，作為歸因特徵

**NER 提取 6 種實體，例如：**
- **Tool（工具）：** Mimikatz, Cobalt Strike, PsExec
- **Way（手法）：** spear-phishing, DLL sideloading
- **Exp（漏洞）：** CVE-2017-0199, EternalBlue
- **Purp（目的）：** espionage, data exfiltration
- **Idus（產業）：** government, defense
- **Area（地區）：** Ukraine, South Korea

---

### TTP 跨 campaign 表現

| 特徵 | GroupKFold F1 | 說明 |
|------|--------------|------|
| VT metadata only | 14.0% | 幾乎等於亂猜（6.7%） |
| **TTP only** | **34.1%** | 2.4 倍 |
| VT + TTP | 36.9% | 稍微再好一點 |

> **TTP 是目前唯一有跨 campaign 歸因力的特徵**
> 原因：同一組織傾向重複使用相似的工具和手法（e.g., Lazarus 愛用 PowerShell + 加密貨幣相關 lure）

---

### Signal 3: Multi-Signal Cascade（三信號串聯）

| 階段 | 正確率 | 累計 Coverage |
|------|--------|--------------|
| S1: Graph clear winner | **100%** | 25.5% |
| S2: TTP tie-breaking | 50.7% | 46.3% |
| S3: ML fallback | 30.7% | **98.5%** |

> **整體：52.8% accuracy, 98.5% coverage**
> 哲學：先用最確定的方法，不確定才降級

---

### Infrastructure Discovery（基礎設施發現）

**除了歸因，同時自動發現相關基礎設施**

每個正確歸因的 IoC 平均發現 **12.0 個**相關節點

- **97.6% 是 novel**（原始 CTI 報告沒提到，VT 才發現的）
- **P@5 = P@10 = P@20 = 1.000**（發現的節點全部正確）

**例子：**
```
輸入：file_abc（已歸因 APT28）
發現：
  → 3 個同 C2 的 IP（報告沒提到）
  → 5 個同家族的 malware（報告沒提到）
  → 4 個相關 domain（報告沒提到）
```
> 實務價值：一次歸因 = 擴展 12 條新情報線索

---

### Robustness 實驗

| 實驗 | 做了什麼 | 結果 |
|------|---------|------|
| **False-Flag（偽旗攻擊）** | 模擬攻擊者植入假特徵混淆歸因 | Tool mimicry 最有害 (-4.95% F1) |
| **Open-Set（未知組織）** | 輪流留出一個 APT 當「未知」 | AUROC 0.764（偵測能力中等） |
| **Selective（選擇性預測）** | 信心不足時拒絕回答 | 90% coverage 時 75% accuracy |

> False-Flag 例子：北韓駭客在程式碼裡放 Mimikatz（APT28 的愛用工具）來嫁禍俄羅斯

---

## 4. Link Prediction 實驗（GNN 路線）

---

### 什麼是 Link Prediction？

**在知識圖譜中預測缺失的邊**

```
已知：file_abc --contacted_ip--> ip_1.2.3.4
      file_abc --dropped_file--> file_def
問題：file_abc --contacted_ip--> ???（還連過哪些 IP？）
```

**Model 訓練：**
- 看過大量真實的邊 → 學到「什麼樣的節點之間容易有邊」
- 測試時：給一個節點 + 關係類型，在數萬候選中排名

**MRR=0.335 表示：** 正確答案平均排在第 3 名（從 12,751 個 IP 候選中）

---

### 四個 Models 比較

| Model | 類型 | 特點 |
|-------|------|------|
| **DistMult** | Shallow KGE | 每節點一個向量，向量乘法打分 |
| **ComplEx** | Shallow KGE | 複數版 DistMult，能捕捉非對稱關係 |
| **R-GCN + DistMult** | GNN encoder | 用 R-GCN 從鄰居聚合產出向量，再用 DistMult 打分 |
| **R-GCN + ComplEx** | GNN encoder | 同上，改用 ComplEx 打分 |

> Shallow KGE：每個節點一個獨立向量（像查字典）
> R-GCN：節點向量由鄰居的訊息「算」出來（像聽周圍的人講話後形成自己的觀點）

---

### Protocol A: Random Split（已見過的節點）

| Model | MRR | Hits@10 | 說明 |
|-------|-----|---------|------|
| Random | 0.0004 | 0.000 | 亂猜 |
| Degree | 0.023 | 0.053 | 猜最熱門的節點 |
| DistMult | 0.306 | 0.491 | |
| **ComplEx** | **0.335** | **0.531** | **最佳** |
| R-GCN + DistMult | 0.295 | 0.459 | |
| R-GCN + ComplEx | 0.290 | 0.458 | |

> **ComplEx 勝出。** 因為在「已見過的節點」設定下，每個節點有專屬向量（17M 參數），比 R-GCN 共享權重（4.3M）更能 overfit 個別節點特性。

---

### Protocol B: Temporal Split（未見過的新節點）

**設定：** 用歷史邊訓練，預測未來出現的邊。89% test edges 包含新節點。

| Model | MRR | Hits@1 | 說明 |
|-------|-----|--------|------|
| Random | 0.0005 | 0.000 | |
| ComplEx | 0.0004 | 0.0001 | 新節點沒有向量 → 無法打分 |
| Degree | 0.003 | 0.002 | 猜熱門的 |
| **R-GCN** | **0.003** | **0.002** | 跟猜熱門的一樣 |

> **全部模型接近零（MRR < 0.003）**
> R-GCN 理論上能靠 node features 處理新節點，但實際只學到 popularity
> **APT 組織的未來基礎設施無法從歷史結構預測**

---

## 5. 統一結論

---

### 三個獨立實驗範式，同一個結論

| 實驗範式 | 同 campaign 內 | 跨 campaign |
|---------|--------------|------------|
| ML 分類 | 72% | 14% |
| 圖匹配 | 93.8% | 66.7% |
| 邊預測 | MRR=0.335 | MRR=0.003 |

**APT 基礎設施本質上是 campaign-specific**

---

### 核心結論展開

**跨 campaign 幾乎無法預測：**
- 不同攻擊行動間，駭客換全新基礎設施
- 不是 model 不夠好，是信號本身不存在

**但 campaign 內有實務價值：**
- Graph overlap clear winner: **100% 正確**
- 每次歸因平均多發現 **12 條新線索**
- 對「正在進行中」的攻擊行動，系統能高精度運作

---

## 6. 研究 Contributions

---

### Contributions (1/2)

| # | 貢獻 | 簡述 |
|---|------|------|
| C1 | VT-enriched 兩層 KG | 66K nodes, 109K edges, 首個 VT 自動擴展 APT KG |
| C2 | Graph overlap 100% precision | 明確贏家永遠正確 + 發現 tie 問題 |
| C3 | Campaign contamination | random split 虛高 50%+，文獻首次報告 |

---

### Contributions (2/2)

| # | 貢獻 | 簡述 |
|---|------|------|
| C4 | TTP 跨 campaign 驗證 | NER-BERT TTP 是 metadata 的 2.4 倍歸因力 |
| C5 | 三信號 cascade | 100% → TTP → ML + P@K=1.0 基礎設施發現 |
| C6 | LP 在 threat KG 首次應用 | MRR=0.335 + temporal 不可行性 |

---

## 7. 兩條論文路線 & 討論

---

### 路線 A：Multi-Signal Attribution（歸因為主）

**核心故事：** 三信號融合歸因 + campaign contamination 發現

- 已有 10 個實驗、end-to-end 系統
- L1~L5 特徵 + TTP (NER-BERT) + Graph Overlap
- LP 作為補充實驗
- **需討論：** L1~L5 特徵有重複，是否精簡？

**優點：** 實驗完整，故事清楚
**風險：** 歸因 accuracy 不高（52.8%），campaign contamination 是 negative result

---

### 路線 B：GNN Infrastructure Prediction（圖預測為主）

**核心故事：** 用 GNN 預測威脅基礎設施關聯

- ComplEx transductive MRR=0.335（信號強）
- R-GCN 實作完成（node features + message passing）
- Temporal MRR=0.003（negative result 但有意義）
- **可加：** R-GCN node classification 做歸因（已寫好待跑）

**優點：** GNN on threat KG 是全新領域，無人做過
**風險：** R-GCN 沒贏 ComplEx，temporal 全軍覆沒

---

### 兩條線的交叉點

不管選哪條，**campaign contamination 都是核心發現**：
- 路線 A：解釋為什麼歸因難
- 路線 B：解釋為什麼 temporal LP 失敗

**兩條線可以合在一起寫：**
> 章節結構：KG 建構 → 歸因實驗 → LP 實驗 → 統一結論（campaign-specific）

---

### 討論事項

1. **選哪條線？** 還是兩條合併？
2. **L1~L5 特徵重複問題：** 要精簡嗎？怎麼簡？
3. **R-GCN node classification：** 要跑嗎？（腳本已準備好）
4. **Negative result 定位：** finding vs limitation？
5. **缺乏 campaign ID：** report group proxy 夠嗎？
6. **投稿目標：** Computers & Security / Digital Investigation / FGCS？
7. **時程：** 開始寫論文了嗎？

---

### Future Work

- **Campaign-annotated dataset：** 有顯式 campaign ID 的資料集，能做更精確的 within/cross-campaign 分析
- **Temporal-aware GNN：** 加入時間戳 encoding，讓 GNN 知道「這條邊是什麼時候出現的」
- **更多 APT 組織：** 目前 20 個，擴充到 50+ 可提升泛化性
- **Real-time deployment：** 接 SIEM/SOAR 做即時歸因
- **Sandbox + EDR 整合：** 結合動態分析補充行為序列，真正做攻擊路徑預測

---

# Thank you
## Questions & Discussion
