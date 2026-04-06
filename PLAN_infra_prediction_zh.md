# 威脅基礎設施預測：基於 VT 增強的異質知識圖譜補全方法

> **Threat Infrastructure Prediction in a VT-Enriched Heterogeneous Knowledge Graph**
> 
> Temporal 降為 sensitivity analysis，不綁死在標題。
> 版本：v2（2026-04-06，納入 GPT 六點修正）

---

## 一、為什麼要做這個研究？（研究動機）

### 1.1 歸因的困境（你已經證明的）

你的碩士論文原本做 APT 歸因（給一個 IoC，判斷屬於哪個 APT 組織）。但你用嚴格實驗證明了三件事：

1. **VT metadata 特徵是 campaign-specific，不是 APT-specific**
   - StratifiedKFold（隨機切分）：63.8% accuracy
   - GroupKFold（按報告分組，防止同 campaign 洩漏）：14.0% accuracy
   - 差距 **-49.8%** → 模型學到的只是「記住同一次攻擊活動的基礎設施指紋」

2. **TTP 特徵稍好但仍不夠**
   - GroupKFold 下 TTP-only：34.1%（是 metadata 的 2.4 倍，但離可用很遠）

3. **Graph overlap 是查表，不是學習**
   - 100% 準確率，但只有 25.5% 覆蓋率
   - 本質是「如果這個 IoC 的 VT 鄰居剛好只出現在一個 APT 子圖，就歸給它」
   - 無法泛化到新基礎設施

### 1.2 轉向的邏輯

既然「判斷是誰做的」信號太弱，不如問一個你的數據天然能回答的問題：

> **「看到一組攻擊基礎設施，能否預測還有哪些相關的基礎設施？」**

這就是 **威脅基礎設施預測（Threat Infrastructure Prediction）**。

### 1.3 為什麼你的數據適合做這個？

| 資產 | 對歸因的價值 | 對基礎設施預測的價值 |
|------|------------|-------------------|
| 109,443 條邊（11 種關係）| 查表索引 | **直接是訓練樣本** |
| 82% 的邊有時間戳 | 沒用上 | temporal sensitivity analysis |
| 11 種 edge type | edge type SNR 分析 | **多關係 link prediction** |
| 跨 13 年的 resolution_date | 無用 | **時間演化分析** |
| 21 個 APT 的行為模式 | 21 個 class（太少）| 跨組織泛化實驗 |

---

## 二、在開始之前必須先做的四件事

> GPT 正確指出：最大的風險不在模型，而在「時間定義、資料洩漏、實驗邊界」還沒收乾淨。

### ⚠️ 修正 1：Dataset Freeze（凍結資料版本）

**問題：** 不同文件中的數字不一致：
- `feasibility_report.txt`：105,888 edges
- 本計畫：109,443 edges
- `PLAN_zh.md`：203 CTI reports
- 本次分析：143 unique source_reports

**修正：** 
- 第一步就是凍結 `merged_kg.json` 的 snapshot
- 產出一份 `data_snapshot.json`：記錄精確的 node/edge/report 數量
- **所有後續實驗和文件只引用這一版數字**

### ⚠️ 修正 2：has_ioc 在 Temporal Split 中的洩漏

**問題：** 原本計畫把 has_ioc（6,275 條）全塞進 train 當 structural anchors。但如果一份 2026 年才發布的報告的 has_ioc 邊在 train 中，等於告訴模型「這個 IoC 屬於這個 APT」— 這是未來資訊洩漏。

**修正方案（二擇一）：**
- **方案 A（推薦）：** Protocol B 中**完全排除 has_ioc**。模型只學 IoC 之間的 VT 關係，不看 APT→IoC 連結。has_ioc 只在 Protocol C（report-group split）和 Task 3（attribution downstream）中使用。
- **方案 B：** 替 has_ioc 補 report publication time（從 URL 中的日期或 Wayback Machine timestamp 推估），然後按時間切分。但這增加工程量且時間推估有噪音。

### ⚠️ 修正 3：Feature 腳本不能直接複用

**問題：** 
- `build_features.py` 有 `REF_DATE = 2026-01-01`（固定參考日期）
- `build_features.py` 用全圖 frequency/overlap 算特徵
- `build_ttp_features.py` 對全 corpus 做 TF-IDF

這些如果直接當 node features，test 時代的資訊會洩漏到 train。

**修正：** 
- **不直接複用這些腳本**
- Node features 必須 **split-aware**：每個 split 只用 train 資料 fit vocabulary / IDF / frequency
- 初始 node features 只用最基本的 VT 屬性（type one-hot、detection_ratio、size 等），不用 frequency-based 特徵

### ⚠️ 修正 4：Temporal 不能當核心 Novelty

**問題：** `last_analysis_date` 是 VT 重新分析的時間，不是攻擊發生時間。`contacted_ip` 有 84% 的邊落在 2026 test — 這是 VT 批量重分析造成的，不是真正的時間演化。

**修正：**
- 標題不含 "Temporal" — 改為 **"Threat Infrastructure Prediction in a VT-Enriched Heterogeneous Knowledge Graph"**
- Temporal split 降為 **sensitivity analysis**（Protocol B 的一個變體），不是核心實驗
- 核心實驗用 Protocol A（random split）證明 link prediction 有信號
- B-DNS（只用 `resolution_date` 的 31,955 條 resolves_to 邊）作為最嚴格的時序實驗

---

## 三、問題定義

### 3.1 知識圖譜的正式定義

$\mathcal{G} = (\mathcal{V}, \mathcal{E}, \mathcal{R}, \tau)$

- **$\mathcal{V}$**：節點集合，5 種類型
  - file（34,005）、domain（19,525）、ip（12,751）、email（142）、apt（21）
- **$\mathcal{R}$**：11 種邊關係
- **$\mathcal{E} \subseteq \mathcal{V} \times \mathcal{R} \times \mathcal{V}$**：邊集合，每條邊 $e = (h, r, v)$
  - $h$ = head node、$r$ = relation type、$v$ = tail node
- **$\tau: \mathcal{E} \rightarrow \mathbb{R} \cup \{\bot\}$**：時間戳函數（82% 有值）

### 3.2 兩個任務（簡化，不過度展開）

#### Task 1：異質 Link Prediction（主任務）

**白話：** 給定知識圖譜中的部分邊，預測缺失的邊。

**數學：** 給定觀測到的子圖 $\mathcal{G}_{obs}$，對候選邊 $(h, r, v)$ 評分：

$$score(h, r, v) = f_\theta(h, r, v \mid \mathcal{G}_{obs})$$

排名越高 = 越可能存在。

**預測目標：** 10 種 VT 關係（排除 has_ioc）。

#### Task 2：預測驅動的歸因（下游驗證）

**白話：** 用 Task 1 預測出的鄰域做 overlap matching 歸因，和現有基線比較。

**做法：** 預測出的鄰居 → 和已知 APT 子圖做 overlap → 組織投票

**對比基線：** 現有 graph overlap（25.5% coverage / 100% precision）

> 注意：從三任務簡化為兩任務。原本的「IoC Expansion」和 Task 1 本質相同（都是 link prediction），不需要分開定義。IoC Expansion 是 Task 1 在特定場景下的應用方式。

---

## 四、切分協議

### Protocol A：Random Edge Split（主要實驗）

```
103,168 條邊（排除 has_ioc 6,275 條）
  → 80% train / 10% valid / 10% test
  → 按 relation type 分層抽樣
  → Transductive：test 邊的兩端節點必須出現在 train 圖中
```

**用途：** 證明 link prediction 有信號。這是核心實驗。

### Protocol B：Temporal Split（Sensitivity Analysis）

**目的：** 回答「歷史基礎設施模式能預測未來嗎？」— 但由於 `last_analysis_date` 不可靠，這是 sensitivity analysis，不是核心 claim。

**三個變體：**

| 變體 | 邊集合 | 時間欄位 | 嚴格度 |
|------|--------|---------|--------|
| **B-Pragmatic** | 全部 103,168 條（無時間戳 → train） | `resolution_date` 優先，else `last_analysis_date` | 最寬鬆 |
| **B-Strict** | 只有有時間戳的 83,529 條 | 同上 | 中等 |
| **B-DNS** | 只有 `resolves_to` 的 31,955 條 | `resolution_date`（語義正確）| **最嚴格** |

年份切分：Train ≤ 2024 / Valid = 2025 / Test = 2026

**has_ioc 在 Protocol B 中完全排除。**

**必須報告 Transductive + Inductive：**
- Transductive：test 邊兩端都在 train 中出現過
- Inductive：至少一端是新節點（冷啟動）

### Protocol C：Report-Group Split（Task 2 only）

```
複用 split_utils.py（Union-Find 報告分組）
  → GroupKFold by report group
  → 移除 test fold 的 has_ioc 邊 + 獨佔 L1 鄰居
  → 和之前的歸因實驗直接可比
```

---

## 五、評估指標

### 5.1 Task 1：Link Prediction

**Type-Constrained Filtered Ranking：**

| 邊類型 | head 類型 | tail 候選集 |
|--------|----------|-----------|
| `resolves_to` | domain | 只有 ip（12,751 個）|
| `contacted_domain` | file | 只有 domain（19,525 個）|
| `execution_parent` | file | 只有 file（34,005 個）|
| `contacted_ip` | file | 只有 ip（12,751 個）|
| ... | ... | 以此類推 |

指標：
- **MRR**：正確答案排名倒數的平均值（越接近 1 越好）
- **Hits@1**：正確答案排第一名的比例
- **Hits@10**：正確答案在前 10 名的比例

**按 relation type 分別報告 + micro/macro 聚合。**

**Open-World 假設（論文必須聲明）：**
> 未觀測到的邊視為「未知」而非「負樣本」。使用 filtered ranking：train/valid 中已知正樣本從候選排名中排除。

### 5.2 Task 2：Attribution

| 指標 | 定義 | 現有基線 |
|------|------|---------|
| Coverage | 能做出歸因的 IoC 比例 | 25.5% |
| Det. Accuracy | clear winner 的準確率 | 100% |
| Tie Rate | 無法決定的比例 | 46.4% |
| **AP@Coverage 曲線** | 不同 coverage 門檻下的 precision | 新指標 |

---

## 六、模型設計

### 6.1 先驗證信號，再上模型（GPT 建議的正確順序）

**階段 1：Non-Neural Baselines（先做這些）**

| 模型 | 做法 | 目的 |
|------|------|------|
| Random | 隨機排名 | 下界 |
| Degree/Popularity | 按 node degree 排序 | 「熱門節點」能預測多少？ |
| Common Neighbors | 共同鄰居數量 | 「兩個節點有多少共同鄰居」→ 越多越可能有邊 |
| 2-hop Heuristic | 2-hop 路徑數量 | 同上，但看 2-hop |
| DistMult | $score = \mathbf{z}_h^T \cdot \text{diag}(\mathbf{w}_r) \cdot \mathbf{z}_v$ | 最簡單的 learnable KGE |
| ComplEx | complex-valued DistMult | 處理非對稱關係 |

**只有當這些 baseline 顯示 link prediction 確實有信號（MRR 顯著高於 random），才進入階段 2。**

**階段 2：GNN（只在有信號時才做）**

| 模型 | 做法 | 目的 |
|------|------|------|
| R-GCN + DistMult | 圖卷積學 node embedding → DistMult 評分 | 利用圖結構 |
| + Temporal encoding | 加入 sinusoidal time encoding | 時間有幫助嗎？（ablation）|

### 6.2 Node Features（Split-Aware）

**初始特徵（不涉及 leakage 的）：**
- Node type one-hot（5 維）
- detection_ratio（VT 偵測率）
- malicious / undetected counts
- file: size (log), type_tag encoding
- domain: TLD encoding
- ip: ASN encoding, country encoding

**不使用的（有 leakage 風險）：**
- ❌ 全圖 frequency-based 特徵
- ❌ 全 corpus TF-IDF
- ❌ REF_DATE-based 時間差特徵
- ❌ overlap/共享 org 計數

### 6.3 Negative Sampling

Type-constrained：
- `resolves_to` 邊：固定 head domain，隨機替換 tail 為其他 ip（不會替換成 file）
- `execution_parent` 邊：固定 head file，隨機替換 tail 為其他 file

### 6.4 訓練

- Loss：Binary cross-entropy 或 margin ranking loss
- Early stopping：validation MRR
- 只有 R-GCN 需要 GPU；KGE baselines CPU 即可

---

## 七、實驗設計（簡化版）

### Exp 1：Signal Verification（Protocol A，最重要）
- 所有 non-neural baselines + DistMult/ComplEx
- **如果 MRR ≈ random → 停下來，link prediction 在這個 KG 上不可行**
- 如果有信號 → 繼續

### Exp 2：Per-Relation Analysis（Protocol A）
- 按 relation type 分別報告 MRR/Hits@K
- 回答：「哪種關係最容易預測？execution_parent vs resolves_to vs contacted_ip？」
- 這本身就是一個有價值的分析結果

### Exp 3：R-GCN（只在 Exp 1 有信號時）
- R-GCN + DistMult vs 純 DistMult
- 圖結構有幫助嗎？

### Exp 4：Temporal Sensitivity（Protocol B，降級為 sensitivity analysis）
- B-DNS（最嚴格）: 只用 resolves_to + resolution_date
- B-Pragmatic：proxy time
- 回答：「歷史模式能預測未來嗎？」
- **不是核心 claim，是 additional analysis**

### Exp 5：Prediction-Driven Attribution（Protocol C，Task 2）
- 預測鄰域 → overlap matching → 和現有 25.5%/100% 比較
- AP@Coverage 曲線

### Exp 6：Ablation（如果 Exp 3 做了 R-GCN）
- 移除 temporal encoding → 時間有幫助嗎？
- 只用因果邊 vs 全部邊 → 因果 vs 結構？
- 加入 TTP 語義節點 → NER 有幫助嗎？

---

## 八、論文架構

```
第一章：Introduction
  - 威脅基礎設施預測的重要性
  - 現有方法的「模擬環境」限制
  - 貢獻：首次在大規模真實 VT 知識圖譜上做 link prediction

第二章：Related Work
  - 知識圖譜補全（TransE, R-GCN, temporal KGE）
  - 攻擊圖與攻擊路徑預測
  - APT 歸因方法與其局限

第三章：Background & Motivation
  - VT-enriched KG 建構（已有工作）
  - Campaign memorization 問題（歸因負面結果 → 動機）
  - 為什麼轉向 infrastructure prediction

第四章：Method
  - 問題定義（Task 1 + Task 2）
  - 切分協議（Protocol A/B/C）
  - 評估指標（type-constrained filtered ranking）
  - 模型（baselines → R-GCN）

第五章：Experiments
  - Exp 1: Signal verification
  - Exp 2: Per-relation analysis
  - Exp 3: R-GCN（如果有信號）
  - Exp 4: Temporal sensitivity
  - Exp 5: Attribution downstream
  - Exp 6: Ablation

第六章：Discussion
  - 哪些關係可預測、哪些不可
  - 時間欄位語義的影響與限制
  - 對 threat hunting 實務的意義
  - 從 prediction 反推 attribution 的可能性

第七章：Conclusion
```

---

## 九、正確的實作順序

> GPT 建議的順序是對的：**先收乾淨，再跑實驗；先 non-neural，再 GNN。**

### Step 0：Dataset Freeze（最優先）
- 凍結 `merged_kg.json` 版本
- 產出 `data_snapshot.json`：精確記錄 node/edge/report 數量
- 統一所有文件中的數字

### Step 1：Split Builder + Evaluator
- `scripts/build_splits.py`：Protocol A / B / C
- `scripts/eval_link_prediction.py`：type-constrained filtered ranking
- **不碰 GNN，不裝 torch-geometric**

### Step 2：Non-Neural MVP
- Degree baseline、Common Neighbors、2-hop heuristic
- DistMult / ComplEx（用 PyTorch 手寫，不需要 torch-geometric）
- **在 Protocol A 上跑，確認有信號**

### Step 3：信號確認 → 決定是否繼續
- 如果 MRR 顯著高於 random → 繼續 Step 4
- 如果 MRR ≈ random → **停下來，重新評估方向**

### Step 4：（只在 Step 3 通過後）R-GCN
- 安裝 torch-geometric
- R-GCN encoder + DistMult scoring
- Protocol A + B + C 全跑

### Step 5：分析與撰寫
- Per-relation / per-org / temporal 分析
- Case studies
- 論文撰寫

---

## 十、需要新建/修改的檔案

| 檔案 | 用途 | 在哪個 Step |
|------|------|------------|
| `scripts/data_snapshot.py` | 凍結資料版本，產出精確數字 | Step 0 |
| `scripts/build_splits.py` | Protocol A/B/C 切分建構 | Step 1 |
| `scripts/eval_link_prediction.py` | 評估框架 | Step 1 |
| `scripts/baselines_link_prediction.py` | Non-neural baselines | Step 2 |
| `scripts/train_kge.py` | DistMult/ComplEx 訓練 | Step 2 |
| `scripts/models/rgcn.py` | R-GCN（只在 Step 4）| Step 4 |
| `scripts/train_link_prediction.py` | GNN 訓練迴圈（只在 Step 4）| Step 4 |

## 可複用的現有檔案

| 檔案 | 複用什麼 |
|------|---------|
| `scripts/split_utils.py` | Union-Find 報告分組（Protocol C）|
| `scripts/eval_infra_discovery.py` | Task 2 的雛形邏輯 |
| `scripts/ttp_extraction/ioc_ttp_mapping.json` | IoC → TTP（Ablation 用）|
| `knowledge_graphs/master/merged_kg.json` | 源數據 |

---

## 十一、驗證清單

1. ✅ Dataset freeze：所有文件數字一致
2. ✅ Protocol A: train + valid + test = 103,168（排除 has_ioc）
3. ✅ Protocol B: has_ioc 完全不在 temporal split 中
4. ✅ Node features 沒有使用全圖 frequency/TF-IDF
5. ✅ Random baseline MRR ≈ 1/|候選集|（非常低）
6. ✅ Type-constrained ranking：resolves_to 只在 ip 中排名
7. ✅ Task 2 歸因結果和現有 25.5%/100% 基線直接可比

---

## 十二、風險管理

| 風險 | 發生條件 | 應對 |
|------|---------|------|
| Link prediction 無信號 | Exp 1 MRR ≈ random | 論文轉為「分析性貢獻」：campaign memorization + per-relation predictability 分析 |
| Temporal split 效果差 | Exp 4 MRR 遠低於 Exp 1 | 已降級為 sensitivity analysis，不影響核心 claim |
| R-GCN 沒比 DistMult 好 | Exp 3 差異不顯著 | 本身就是一個有價值的 negative result（圖結構對此任務幫助有限）|
| Attribution coverage 沒提升 | Exp 5 和基線差不多 | 至少 Task 1 的 link prediction 結果仍成立 |
