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

1. 系統架構 & KG 建構
2. 核心發現：Campaign Contamination
3. 三信號歸因系統 & 實驗結果
4. Link Prediction 實驗
5. 統一結論
6. 目前狀態 & 討論事項

---

## 1. 系統架構

---

### Knowledge Graph 建構

```
CTI 報告（143 份, 20 orgs）
  → IoC 提取 + 清洗（6,182 IoCs）
  → VT API 查詢 metadata + relationships
  → 兩層 KG 展開
```

| 指標 | 數值 |
|------|------|
| Nodes | 66,444 (file=34K, domain=19.5K, ip=12.7K) |
| Edges | 109,443 (10 種 relation type) |
| Organizations | 20 個 APT 組織 |
| Edge types | contacted_ip, resolves_to, dropped_file, ... |

---

### 兩層 KG 結構

- **L0（來自 CTI 報告）：** `apt --has_ioc--> file/domain/ip`
- **L1（VT 自動發現）：** file↔ip, file↔domain, domain↔ip, file↔file

> L1 節點佔 95%+ → VT enrichment 大幅擴展圖規模

---

### 推論 Pipeline（已實作, `inference.py`）

```
新 IoC 輸入
  → VT API 查詢 → metadata + 1-hop 鄰居
  → Signal 1: Graph overlap（KG 匹配）
  → Signal 2: TTP context（NER 特徵）
  → Signal 3: ML classifier（metadata 特徵）
  → Confidence-gated 輸出 (HIGH/MEDIUM/LOW)
  → Abstention 拒判（false-flag / open-set 防禦）
```

---

## 2. 核心發現：Campaign Contamination

---

### 問題：Random Split 嚴重虛高

同一份 CTI 報告的 IoC 來自同一 campaign，
共享相同基礎設施（C2、registrar、ASN）

**Random split 讓同 campaign 的 IoC 同時在 train/test**
→ 分類器只需 memorize campaign fingerprint

---

### 實驗驗證：GroupKFold vs StratifiedKFold

| 特徵組合 | StratifiedKFold | GroupKFold | **差距** |
|---------|----------------|-----------|---------|
| L1 (88d metadata) | 63.8% | 14.0% | **-49.8%** |
| L1+L2 (123d) | 69.6% | 17.3% | **-52.3%** |
| L1+L2+L3+L4 (209d) | 72.1% | 16.1% | **-56.0%** |

> 15-class random guess = 6.7%
> GroupKFold 下所有配置接近 random level

**結論：VT metadata 是 campaign-specific，不是 APT-specific**

---

### 分組方式

- 無顯式 campaign ID
- 用 **Union-Find on shared source reports** 作為 proxy
- 共享報告的 IoC 歸為同一 group → 防止 train/test 洩漏
- `assert_no_report_leak()` 確保零報告重疊

> Limitation: report group ≠ true campaign，但足以證明 contamination 存在

---

## 3. 三信號歸因系統

---

### Signal 1: Graph Overlap

移除 test IoC + 同報告獨佔 L1 鄰居後，
看剩餘鄰居的 org 投票

| 指標 | Per-IoC | **Per-Report（公平版）** |
|------|---------|----------------------|
| Coverage | 68.2% | 47.5% |
| Accuracy | 93.8% | 66.7% |

**關鍵發現：Clear winner（無 tie）→ 100% 正確**
- 1,516 個 clear winner，全部正確
- 1,348 個 tie（true org 永遠在候選中）
- **所有「錯誤」都是 tie-breaking 的 set 遍歷順序造成**

---

### Signal 2: TTP Context

NER-BERT-CRF 從 207 份 CTI 報告提取 6 種實體
→ TF-IDF → 1,538 維 sparse features

| Config | GroupKFold F1 |
|--------|--------------|
| L1 only (VT metadata) | 14.0% |
| **L5 only (TTP)** | **34.1%** |
| L1+L5 | 36.9% |

> **TTP 跨 campaign 歸因力是 VT metadata 的 2.4 倍**

---

### Signal 3: Multi-Signal Cascade

| Stage | Decided | Accuracy | Cum. Coverage |
|-------|---------|----------|---------------|
| S1: Graph clear winner | 1,553 | **100%** | 25.5% |
| S2: TTP tie-breaking | 1,272 | 50.7% | 46.3% |
| S3: ML fallback | 3,186 | 30.7% | **98.5%** |

> Overall: 52.8% accuracy, 98.5% coverage

---

### Infrastructure Discovery (Exp 6)

每個正確歸因 IoC 平均發現 **12.0 個**相關基礎設施節點

- **97.6% 是 novel**（VT 發現，原始報告未提及）
- **P@5 = P@10 = P@20 = 1.000**
- IP: 9,554 / File: 6,232 / Domain: 2,855

> 實務價值：歸因的同時自動擴展威脅情報

---

### Robustness 實驗

| 實驗 | 結果 |
|------|------|
| **False-Flag** | Tool mimicry 最有害 (-4.95% F1)，source weighting 有效抵禦 |
| **Open-Set** | AUROC 0.764，未知 APT 誤歸因率 77.7% |
| **Selective** | 90% coverage 時 75% accuracy |

---

## 4. Link Prediction 實驗

---

### 目標

在 VT-enriched 異質 KG 上做 link prediction
- 主任務：預測缺失的基礎設施關聯
- 驗證：KG 結構的可預測性

Models: ComplEx, DistMult, R-GCN + DistMult, R-GCN + ComplEx

---

### Protocol A: Random Split（Transductive）

| Model | MRR | Hits@10 |
|-------|-----|---------|
| Random | 0.0004 | 0.000 |
| Degree | 0.023 | 0.053 |
| DistMult | 0.306 | 0.491 |
| **ComplEx** | **0.335** | **0.531** |
| R-GCN + DistMult | 0.295 | 0.459 |
| R-GCN + ComplEx | 0.290 | 0.458 |

> 信號極強：ComplEx 正確答案平均排第 3 名（數萬候選中）
> R-GCN 未超越 shallow KGE（transductive 下 per-node embedding 更強）

---

### Protocol B: Temporal Split（Inductive）

| Model | MRR | Hits@1 |
|-------|-----|--------|
| Random | 0.0005 | 0.000 |
| ComplEx | 0.0004 | 0.0001 |
| Degree | 0.003 | 0.002 |
| R-GCN | 0.003 | 0.002 |

> **所有模型全軍覆沒 (MRR < 0.003)**
> 89% test edges 有新 node → 未來基礎設施無法從歷史結構預測
> R-GCN ≈ Degree heuristic → GNN 只學到 node popularity

---

## 5. 統一結論

---

### 三個實驗範式，同一個結論

| 實驗範式 | 同 campaign 內 | 跨 campaign |
|---------|--------------|------------|
| VT metadata ML | StratifiedKFold 72% | GroupKFold 14% |
| Graph overlap | Per-IoC 93.8% | Per-Report 66.7% |
| **Link Prediction** | **MRR=0.335** | **MRR=0.003** |

### APT 基礎設施本質上是 campaign-specific

- 不管用 ML / graph / LP，跨 campaign 泛化都極其困難
- APT 組織在不同 campaign 間 routine 更換基礎設施
- **這不是 model 不夠好，是信號本身不存在**

---

### 但 campaign 內有極高可預測性

- Graph overlap clear winner: **100% precision**
- ComplEx transductive LP: **MRR=0.335**
- Infrastructure discovery: **P@K=1.000**

> **實務意義：對進行中的 campaign，
> 系統能高精度歸因 + 自動發現相關基礎設施**

---

## 6. 研究 Contributions

---

### 6 個 Contributions

1. **VT-enriched 兩層 IoC KG**（66K nodes, 109K edges, 20 orgs）
2. **Graph overlap 100% deterministic precision** + tie 問題發現
3. **Campaign contamination 分析**（StratifiedKFold vs GroupKFold 差距 -50%+）
4. **TTP 跨 campaign 歸因力驗證**（2.4x metadata）
5. **Multi-signal cascade** + infrastructure discovery
6. **LP 在 threat KG 的首次應用** + temporal 不可行性發現

---

## 7. 目前狀態 & 討論事項

---

### 已完成

- [x] KG 建構 (66K nodes)
- [x] 10 個實驗全部完成
- [x] End-to-end inference pipeline (`inference.py`)
- [x] R-GCN 實作 + LP baseline + temporal 實驗

---

### 討論事項

1. **論文定位**：以歸因系統 + campaign contamination 發現為主，LP 作為補充實驗？還是 LP 獨立成章？

2. **Negative result 的寫法**：temporal LP 失敗如何定位（limitation vs finding）？

3. **缺乏顯式 campaign ID**：report group 作為 proxy 是否足夠？寫在 limitation + future work？

4. **投稿目標**：Computers & Security / Digital Investigation / FGCS？

5. **論文章節結構**：開始寫了嗎？需要討論大綱？

---

### Future Work 方向

- Campaign-annotated dataset（顯式 campaign ID）
- Temporal-aware GNN（時間戳 encoding）
- 更多 APT 組織（目前 20 個）
- Real-time deployment integration
- 結合 sandbox 動態分析 + endpoint telemetry

---

# Thank you
## Questions & Discussion
