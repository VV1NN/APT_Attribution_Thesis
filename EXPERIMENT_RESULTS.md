# Multi-Signal APT Attribution Framework — 實驗結果報告

> 日期：2026-04-01
> 資料集：21 APT orgs, 66,444 nodes, 109,443 edges, 6,101 L0 IoCs (15 major orgs for classification)
> 評估框架：GroupKFold by source report（5-fold, 127 report groups）防止 same-campaign contamination

---

## 一、實驗總覽

| 實驗 | 目的 | 核心結果 |
|------|------|----------|
| Exp 1 | Campaign Memorization 揭露 | StratifiedKFold vs GroupKFold 差距 -50%+ |
| Exp 2 | Graph Overlap 100% Precision | Clear winner = 100% det. accuracy, 25.5% coverage |
| Exp 3 | TTP Cross-Campaign 歸因力 | L5-only micro-F1 = **34.1%** (vs L1 metadata 14.0%) |
| Exp 4 | TTP Tie-Breaking | 打破 94.6% ties, tie-break accuracy = 50.7% |
| Exp 5 | Multi-Signal Fusion | Cascade micro-F1 = **52.8%**, macro-F1 = **63.5%**, coverage 98.5% |
| Exp 6 | Infrastructure Discovery | P@5 = P@10 = P@20 = 1.000, avg 12 nodes/IoC |

---

## 二、Experiment 1: Campaign Memorization Analysis

**核心發現：StratifiedKFold 的結果因 same-campaign contamination 嚴重虛高。**

| 特徵組合 | StratifiedKFold micro-F1 | GroupKFold micro-F1 | 差距 |
|---------|------------------------|--------------------|----|
| L1 (88d metadata) | 63.8% | 14.0% | **-49.8%** |
| L1+L2 (123d) | 69.6% | 17.3% | **-52.3%** |
| L1+L2+L3 (145d) | 69.8% | 12.8% | **-57.0%** |
| L1+L2+L3+L4 (209d) | 72.1% | 16.1% | **-56.0%** |
| L3 alone (22d) | 8.3% | 17.5% | +9.2% |

> 15-class random guess = 6.7%
> 結論：VT metadata (L1-L4) 學到的是 campaign fingerprint，不是 APT-specific 特徵。
> L3（overlap features）在 GroupKFold 下反而比 L1 好（17.5% vs 14.0%），因為 graph overlap 捕捉的是跨 campaign 的 infrastructure reuse。

**腳本：** `scripts/eval_groupkfold_ablation.py`
**結果：** `scripts/results/eval_groupkfold_ablation.json`

---

## 三、Experiment 2: Graph Overlap Deterministic Precision

**核心發現：Graph overlap 的 clear winner 永遠正確。之前報的 63-70% accuracy 是 tie-breaking 假象。**

### 2.1 Tie 分析（Per-Report Leave-One-Out）

| 類別 | 數量 | 佔比 | 說明 |
|------|------|------|------|
| **Clear winner** | 1,553 | 25.5% | **100% 正確**（deterministic） |
| **Tie（true org 在候選中）** | 1,345 | 22.0% | 需 tie-breaking |
| No match — 無鄰居 | 1,677 | 27.5% | VT 沒有 relationship 資料 |
| No match — LOO 移除 | 1,526 | 25.0% | 跨 campaign 無 infra reuse |

> `tie_true_not = 0`：true org 永遠在 tie 候選中，不存在「猜錯且 true org 不在候選」的情況。
> 之前報的 63-70% accuracy 完全取決於 `Counter.most_common()` 的 set 遍歷順序（不確定性）。

### 2.2 Edge Type 歸因力排名

| Edge Type | Vote Precision | SNR | 總票數 |
|-----------|---------------|-----|-------|
| execution_parent | 56.7% | 1.3x | 210 |
| communicating_file | 46.3% | 0.9x | 618 |
| referrer_file | 33.4% | 0.5x | 8,610 |
| bundled_file | 29.9% | 0.4x | 7,003 |
| dropped_file | 20.9% | 0.3x | 9,162 |
| resolves_to | 17.5% | 0.2x | 49,137 |
| contacted_domain | 11.9% | 0.1x | 23,957 |
| contacted_ip | 11.1% | 0.1x | 50,945 |

> 代碼層面關係（execution_parent, 56.7%）比網路層面（contacted_ip, 11.1%）歸因力高 **5 倍**。
> APT 可以換 IP/domain，但 malware 之間的執行鏈關係更難改變。

### 2.3 Voting Weighting 無效

| 策略 | Accuracy |
|------|----------|
| Uniform Vote | identical |
| EdgeType-weighted | identical |
| IDF (1/|orgs|) | identical |
| Edge x IDF | identical |

> 原因：同一 shared L1 node 對所有 org 投等比例票，reweighting 不改變排名。
> 問題不在 weighting，在於 shared infrastructure 本身是歧義的。

### 2.4 Org Count Filter Sweep

| 只接受 ≤ N org 的 neighbor | Match | Clear Correct | Tie | Det. Acc |
|---------------------------|-------|---------------|-----|---------|
| ≤1 org (exclusive only) | 810 | 810 | 0 | 100% |
| ≤2 orgs | 1,858 | 1,179 | 679 | 100% |
| ≤5 orgs | 2,174 | 1,374 | 800 | 100% |
| ≤10 orgs | 2,675 | 1,494 | 1,181 | 100% |
| all | 2,864 | 1,516 | 1,348 | 100% |

> Exclusive neighbors (≤1 org) → 100% accuracy, 100% clear rate, 但 coverage 降到 13.3%
> Deterministic accuracy 在所有 threshold 下都是 100%

### 2.5 Coverage Gap 分析

| No-Match 原因 | 數量 | 佔比 |
|--------------|------|------|
| KG 中完全沒有鄰居（VT 無回傳） | 1,677 | 52.4% |
| 有鄰居但全被 LOO 移除（同報告獨佔） | 1,526 | 47.6% |

各 IoC 類型 coverage：

| Type | Total | Match | No-Neighbor | LOO-Removed | Match% |
|------|-------|-------|-------------|-------------|--------|
| domain | 2,347 | 1,349 | 306 | 692 | 57.5% |
| file | 2,680 | 1,272 | 1,101 | 307 | 47.5% |
| ip | 936 | 277 | 132 | 527 | 29.6% |
| email | 138 | 0 | 138 | 0 | 0.0% |

> file 類 coverage 最低（1,101 個在 KG 中完全沒有鄰居），因為很多 malware sample 在 VT 上沒有 relationship。

**腳本：** `scripts/eval_edge_type_analysis.py`, `scripts/eval_noise_filter_sweep.py`
**結果：** `scripts/results/eval_edge_type_analysis.json`, `scripts/results/eval_noise_filter_sweep.json`

---

## 四、Experiment 3: TTP Cross-Campaign Evaluation

**核心發現：TTP 跨 campaign 歸因力是 VT metadata 的 2.4 倍。**

### 3.1 GroupKFold F1 Scores

| Config | Dims | micro-F1 | macro-F1 |
|--------|------|----------|----------|
| L1 only (VT metadata) | 88 | 14.0% | 12.3% |
| **L5 only (TTP)** | **1,538** | **34.1%** | **40.9%** |
| L1+L5 | 1,626 | 36.9% | 41.6% |
| L1+L2+L5 | 1,661 | 37.9% | 40.4% |
| L3+L5 (graph+TTP) | 1,560 | 36.3% | 42.6% |
| L1+L2+L3+L5 | 1,683 | 38.2% | 41.7% |
| Full (L1+L2+L3+L4+L5) | 1,747 | 38.2% | 41.7% |

> L5 macro-F1 (40.9%) > micro-F1 (34.1%)：表示 TTP 對小 org 的歸因效果相對好。
> L3+L5 的 macro-F1 = 42.6% 是所有組合中最高的（純「乾淨信號」組合）。
> 加入 L1-L4 後 micro-F1 僅從 34.1% → 38.2%（+4.1%），邊際效益遞減。

### 3.2 Per-APT TTP Classification Accuracy（L5-only, GroupKFold）

| APT Group | IoCs | Correct | Accuracy | 分析 |
|-----------|------|---------|----------|------|
| FIN7 | 360 | 358 | **99.4%** | TTP 極有區分力（CARBANAK 生態系獨特） |
| APT32 | 288 | 234 | **81.2%** | 越南 APT，工具組合獨特 |
| APT-C-23 | 249 | 189 | **75.9%** | Android spyware 工具獨特 |
| Turla | 188 | 136 | **72.3%** | 長期使用 Carbon, Mosquito 等 |
| Sandworm_Team | 339 | 242 | **71.4%** | BlackEnergy, KillDisk, NotPetya |
| Kimsuky | 179 | 100 | 55.9% | 中等 |
| APT28 | 241 | 125 | 51.9% | 工具與 Sandworm 部分重疊 |
| Lazarus_Group | 422 | 166 | 39.3% | 工具多樣，跨 campaign 變化大 |
| Gamaredon_Group | 723 | 183 | 25.3% | 報告數多但 TTP 描述相似 |
| APT29 | 712 | 172 | 24.2% | SolarWinds 報告佔比大 |
| OilRig | 189 | 38 | 20.1% | 低 |
| MuddyWater | 250 | 25 | 10.0% | 低 |
| Magic_Hound | 906 | 22 | **2.4%** | IoC 最多但 TTP 描述最弱 |
| Wizard_Spider | 797 | 0 | **0.0%** | TTP 完全無法區分（TrickBot 生態太泛用） |

> FIN7 (99.4%) vs Wizard_Spider (0.0%) 的極端差異：
> FIN7 的工具鏈（CARBANAK, DICELOADER, BIRDWATCH）幾乎只出現在 FIN7 報告。
> Wizard_Spider 使用的工具（TrickBot, Ryuk）太泛用，多個 APT 共享。

**腳本：** `scripts/eval_groupkfold_ttp.py`
**結果：** `scripts/results/eval_groupkfold_ttp.json`

---

## 五、Experiment 4: TTP Tie-Breaking

**核心發現：TTP 能打破 94.6% 的 graph overlap ties，但 accuracy 因 APT 差異極大。**

### 5.1 整體效果

| 指標 | Before TTP | After TTP |
|------|-----------|-----------|
| Deterministic decisions | 1,553 | 2,825 |
| Coverage | 25.5% | 46.3% |
| Accuracy | 100% | 77.8% |
| Tie rate | 46.4% | 5.4% (73 unbroken) |

> +1,272 個 IoC 從「無法判定」變成「有歸因結果」（+20.8% coverage）。
> 代價：accuracy 從 100% 降到 77.8%（tie-break accuracy = 50.7%）。

### 5.2 Per-APT Tie-Breaking Accuracy

| APT Group | Clear Winner | Ties | Broken | TB Accuracy | 分析 |
|-----------|-------------|------|--------|-------------|------|
| Sandworm_Team | 114 | 57 | 57 | **96%** | TTP profile 極有區分力 |
| APT-C-23 | 45 | 114 | 114 | **94%** | Android 工具獨特 |
| APT28 | 77 | 75 | 75 | **87%** | 工具鏈辨識度高 |
| Turla | 61 | 30 | 30 | **83%** | 長期工具穩定 |
| FIN7 | 168 | 84 | 84 | **76%** | CARBANAK 生態 |
| MuddyWater | 131 | 51 | 51 | 69% | 中等 |
| Lazarus_Group | 218 | 40 | 40 | 68% | 工具多樣但可辨識 |
| Magic_Hound | 144 | 150 | 148 | 54% | TTP 描述弱 |
| APT29 | 88 | 137 | 137 | 53% | SolarWinds 報告主導 |
| APT32 | 68 | 75 | 75 | 45% | 中等 |
| OilRig | 61 | 43 | 43 | 33% | 低 |
| APT1 | 25 | 9 | 9 | 22% | 低 |
| Gamaredon_Group | 173 | 151 | 151 | **18%** | TTP 太泛用 |
| Wizard_Spider | 129 | 208 | 208 | **16%** | TrickBot 生態太泛 |
| Kimsuky | 13 | 50 | 50 | **8%** | TTP 無法辨識 |

> Infrastructure reuse 強的 APT（Sandworm, APT28）同時 TTP 也強。
> 兩者正相關：穩定的 APT 同時重用基礎設施和攻擊工具。

**腳本：** `scripts/eval_ttp_tiebreak.py`
**結果：** `scripts/results/eval_ttp_tiebreak.json`

---

## 六、Experiment 5: Multi-Signal Fusion

**核心發現：三信號 cascade 達到 52.8% micro-F1 / 63.5% macro-F1，98.5% coverage。**

### 6.1 Cascade 逐 Stage 效果

| Stage | 策略 | Decided | Stage Acc | Cum. Coverage | Cum. Accuracy |
|-------|------|---------|-----------|---------------|---------------|
| S1 | Graph clear winner | 1,553 | 100% | 25.5% | 100% |
| S2 | TTP tie-breaking | 1,272 | 50.7% | 46.3% | 77.8% |
| S3 | ML fallback (L1+L5) | 3,186 | 30.7% | 98.5% | 52.8% |
| — | Unresolved | 90 | — | — | — |

### 6.2 Cascade F1 Scores

| Cascade 版本 | micro-F1 | macro-F1 | Accuracy | Coverage |
|-------------|----------|----------|----------|----------|
| **A (clean: L1+L5)** | **52.8%** | **63.5%** | 52.8% | 98.5% |
| B (full: L1-L5) | 53.4% | 63.9% | 53.4% | 98.5% |

> Cascade A vs B 差距僅 0.6%，表示 L2/L3/L4 在 cascade 框架下邊際效益極小。
> 推薦使用 Cascade A（clean），避免 L3/L4 的 leakage 疑慮。

### 6.3 Per-Stage F1

| Stage | micro-F1 | macro-F1 | n |
|-------|----------|----------|---|
| S1: Graph Overlap | 100.0% | 100.0% | 1,553 |
| S2: TTP Tie-Breaking | 50.7% | 40.1% | 1,272 |
| S3: ML Fallback | 30.7% | 38.0% | 3,186 |

### 6.4 與單一信號比較

| 方法 | micro-F1 | macro-F1 | Coverage | 備註 |
|------|----------|----------|----------|------|
| VT Metadata only (L1, GroupKFold) | 14.0% | 12.3% | 100% | campaign fingerprint |
| TTP only (L5, GroupKFold) | 34.1% | 40.9% | 100% | 跨 campaign |
| Graph Overlap only (clear winner) | — | — | 25.5% | 100% det. accuracy |
| **Cascade A (Graph+TTP+ML)** | **52.8%** | **63.5%** | **98.5%** | **三信號融合** |

> Cascade 的 micro-F1 (52.8%) 是 L1-only (14.0%) 的 **3.8 倍**。
> macro-F1 (63.5%) 高於 micro-F1 (52.8%)：小 org 受益於 graph clear winner 的高精度。

**腳本：** `scripts/eval_multisignal_fusion.py`
**結果：** `scripts/results/eval_multisignal_fusion.json`

---

## 七、Experiment 6: Infrastructure Discovery

**核心發現：每個正確歸因的 IoC 平均可發現 12 個相關攻擊基礎設施節點，97.6% 是原始報告未提及的。**

### 7.1 整體統計

| 指標 | 數值 |
|------|------|
| 正確歸因 IoCs（clear winner） | 1,553 |
| 總發現基礎設施節點 | 18,641 |
| 平均每 IoC 發現 | 12.0 個 |
| Novel（L1, VT-discovered） | 18,202 (97.6%) |

### 7.2 按 Node Type 分類

| Type | 發現數 | Novel 數 | Novel% |
|------|--------|----------|--------|
| IP | 9,554 | 9,284 | 97.2% |
| File | 6,232 | 6,168 | 99.0% |
| Domain | 2,855 | 2,750 | 96.3% |

### 7.3 Precision@K

| K | Precision |
|---|-----------|
| 5 | **1.000** |
| 10 | **1.000** |
| 20 | **1.000** |

> P@K = 1.0 是因為只分析 clear winner 案例，其 matched neighbors 全部屬於正確 org。
> 這驗證了 graph overlap 的副產品：correctly attributed IoC 的 matched paths 可直接作為 infrastructure intelligence。

**腳本：** `scripts/eval_infra_discovery.py`
**結果：** `scripts/results/eval_infra_discovery.json`

---

## 八、TTP 特徵工程摘要

### 8.1 Entity Normalization 效果

| Type | Before | After | 保留率 | Unique Before | Unique After |
|------|--------|-------|--------|---------------|-------------|
| Tool | 8,858 | 753 | 8.5% | 6,700 | 345 |
| Way | 2,010 | 369 | 18.4% | 1,098 | 66 |
| Exp | 248 | 199 | 80.2% | 208 | 146 |
| Purp | 925 | 897 | 97.0% | 617 | 552 |
| Idus | 1,505 | 1,340 | 89.0% | 722 | 522 |
| Area | 2,026 | 1,520 | 75.0% | 741 | 493 |
| **Total** | **15,572** | **5,078** | **32.6%** | — | — |

> Tool 從 6,700 → 345 unique（-95%）：MITRE ATT&CK 白名單移除了平台名、廠商名、泛稱。
> Top-5 Tool：mimikatz(18), cobalt strike(17), psexec(16), killdisk(10), trickbot(9)

### 8.2 L5 Feature Matrix

| 指標 | 數值 |
|------|------|
| Samples | 5,961 |
| Features | 1,538 |
| Non-zero | 199,053 (2.17%) |
| IoCs with TTP data | 5,957 / 5,961 (99.9%) |

Per entity type TF-IDF terms：Tool=271, Way=57, Exp=121, Purp=394, Idus=347, Area=348

---

## 九、研究貢獻總結

| 貢獻 | 內容 | 支撐實驗 |
|------|------|---------|
| **C1** | VT-enriched two-layer IoC KG（66K nodes, 109K edges, 21 APT orgs） | — |
| **C2** | Graph overlap 100% deterministic precision + edge type 歸因力排名 + confidence-gated attribution | Exp 2 |
| **C3** | TTP 跨 campaign 歸因力驗證（2.4x metadata）+ multi-signal fusion（52.8% micro-F1, 63.5% macro-F1） | Exp 3, 4, 5 |
| **C4** | Campaign memorization 分析（StratifiedKFold vs GroupKFold 差距 -50%+） | Exp 1 |
| **C5** | 攻擊基礎設施發現（P@K=1.0, avg 12 nodes/IoC, 97.6% novel） | Exp 6 |

---

## 十、完整腳本與結果檔案索引

### 評估腳本

| 腳本 | 對應實驗 |
|------|---------|
| `scripts/eval_groupkfold_ablation.py` | Exp 1: Campaign memorization |
| `scripts/eval_edge_type_analysis.py` | Exp 2: Edge type precision + voting strategies |
| `scripts/eval_noise_filter_sweep.py` | Exp 2: Noise filter + confidence-gated |
| `scripts/eval_overlap_by_report.py` | Exp 2: Per-report LOO baseline |
| `scripts/eval_groupkfold_ttp.py` | Exp 3: TTP GroupKFold |
| `scripts/eval_ttp_tiebreak.py` | Exp 4: TTP tie-breaking |
| `scripts/eval_multisignal_fusion.py` | Exp 5: Multi-signal cascade |
| `scripts/eval_infra_discovery.py` | Exp 6: Infrastructure discovery |

### TTP Pipeline 腳本

| 腳本 | 功能 |
|------|------|
| `scripts/ttp_extraction/run_ner_on_reports.py` | NER-BERT-CRF 推論（207 reports） |
| `scripts/ttp_extraction/normalize_entities.py` | Entity normalization + ATT&CK 白名單 |
| `scripts/ttp_extraction/build_ioc_ttp_mapping.py` | IoC → Report → TTP 映射 |
| `scripts/build_ttp_features.py` | L5 TF-IDF 特徵建構 |

### 結果檔案

| 檔案 | 內容 |
|------|------|
| `scripts/results/eval_groupkfold_ablation.json` | Exp 1 消融結果 |
| `scripts/results/eval_edge_type_analysis.json` | Exp 2 edge type 分析 |
| `scripts/results/eval_noise_filter_sweep.json` | Exp 2 noise filter sweep |
| `scripts/results/eval_overlap_by_report.json` | Exp 2 per-report LOO |
| `scripts/results/eval_groupkfold_ttp.json` | Exp 3 TTP GroupKFold |
| `scripts/results/eval_ttp_tiebreak.json` | Exp 4 TTP tie-breaking |
| `scripts/results/eval_multisignal_fusion.json` | Exp 5 cascade fusion |
| `scripts/results/eval_infra_discovery.json` | Exp 6 infra discovery |

### 資料產出

| 檔案 | 內容 |
|------|------|
| `scripts/ttp_extraction/ioc_ttp_mapping.json` | 6,054 IoCs 的 TTP mapping |
| `scripts/ttp_extraction/attack_software_list.txt` | MITRE ATT&CK 白名單（1,059 tools） |
| `scripts/features/features_l5_ttp_matrix.npz` | L5 sparse TF-IDF matrix |
| `scripts/features/features_l5_ttp.npz` | L5 metadata (node_ids, feature_names) |
| `scripts/features/ttp_vocabularies.json` | TTP TF-IDF vocabularies |
| `figures/system_architecture.png` | 系統架構圖 |
| `figures/system_architecture.drawio` | 系統架構圖（可編輯） |

---

## 十一、2026-04-06 更新：Honest Evaluation + Trustworthy Decision

> 本節為 2026-04-06 新增，對應 Prompt 1~5 的修補與新實驗。

### 11.1 Leakage 修補（切分、L5、L4、前處理）

#### A) Report-connected split（Prompt 1）

- `build_report_connected_groups` 改為 connected components（DSU），不再只看 `reports[0]`。
- `eval_groupkfold_ablation.py` / `eval_groupkfold_ttp.py` 每 fold 強制 `assert_no_report_leak`。
- 實測：兩支腳本均為 **92 groups**，fold 皆 `leak check PASS`。

#### B) L5 改為 fold-aware TF-IDF（Prompt 2）

主實驗改為每 fold train-only TF-IDF（Tool/Way/Exp），並加入：
- 權重：`tfidf * source_reliability_score * exp(-lambda * age_days)`
- consistency features：
  - `source_disagreement_rate`
  - `ttp_conflict_entropy`
  - `num_independent_sources`

同時保留 legacy global L5 當比較基線：

| L5 設定 | micro-F1 | macro-F1 |
|---|---:|---:|
| Legacy global L5 | 0.1839 | 0.2103 |
| Fold-aware weighted L5 | 0.1049 | 0.1571 |

> 觀察：分數下降但評估更 honest；TF-IDF transductive leakage 已移除（主實驗不再使用全域 fit）。

#### C) L4 honest mode（Prompt 3）

兩支腳本新增 `--l4-mode {off,transductive}`：
- `off`：主結果（不納入 L4）
- `transductive`：舊做法（附錄比較）

`eval_groupkfold_ablation.py`（GroupKFold, L1+L2+L3+L4）：

| 模式 | micro-F1 | macro-F1 |
|---|---:|---:|
| `l4_mode=off` | 0.1219 | 0.0982 |
| `l4_mode=transductive` | 0.1505 | 0.1173 |
| 差距（transductive-off） | +0.0286 | +0.0191 |

> 建議：主文用 `off`，`transductive` 放附錄當敏感度分析。

### 11.2 Calibration + Selective + Open-set（Prompt 4）

新增：
- `scripts/model/calibrate_probs.py`
- `scripts/evaluate_selective.py`
- `scripts/evaluate_openset.py`
- `scripts/model/calibrator.pkl`

Calibration（temperature scaling）：

| 指標 | Before | After | Δ |
|---|---:|---:|---:|
| ECE | 0.2844 | 0.0462 | -0.2381 |
| Brier | 1.0754 | 0.9295 | -0.1459 |

Selective classification：
- AURC(raw) = `0.771402`
- AURC(calibrated) = `0.767033`
- ΔAURC = `-0.004368`（越低越好）

Open-set（actor holdout）：
- AUROC mean = `0.7644 ± 0.0382`
- FPR@95TPR mean = `0.4456 ± 0.0518`
- Unknown 誤歸因率 mean = `0.7775 ± 0.0998`

`inference.py` 同步升級：
- 載入 `calibrator.pkl`
- 輸出 `confidence_raw` / `confidence_calibrated`
- 新增 `decision: PREDICT/ABSTAIN`
- 新增 `abstain_reason: low_confidence / high_conflict / open_set`

### 11.3 False-Flag 韌性（Prompt 5）

新增 `scripts/eval_false_flag.py`，攻擊：
- `tool_mimicry`
- `way_mimicry`
- `source_poisoning`

強度：`r = 0.1, 0.3, 0.5`

新增指標：
- `delta micro/macro F1`
- `abstain_rate_change`
- `misattribution_rate`
- `conditional_misattribution_rate`

整體排名（平均 attacked 表現）：
- Utility（avg attacked micro-F1）：`baseline_raw > weighted_l5 ≈ weighted_l5_calibrated > weighted_l5_calibrated_abstain`
- Safety（avg attacked misattribution，越低越好）：`weighted_l5_calibrated_abstain` 最佳
- Risk-aware（限制 abstain <= 0.4）：`baseline_raw > weighted_l5 ≈ weighted_l5_calibrated`

攻擊面向結論：
- **最傷攻擊**：`tool_mimicry`
- `way_mimicry` 對 baseline 破壞最小
- `source_poisoning` 主要影響 weighted 路線（尤其高強度）

> 註：false-flag 實驗為避免退化為全拒判，abstain thresholds 採實務化 clipping（腳本內已記錄）。

### 11.4 本次新增腳本與結果檔

新增腳本：
- `scripts/split_utils.py`
- `scripts/ttp_extraction/build_source_quality_table.py`
- `scripts/model/calibration_utils.py`
- `scripts/model/calibrate_probs.py`
- `scripts/evaluate_selective.py`
- `scripts/evaluate_openset.py`
- `scripts/eval_false_flag.py`

新增/更新結果：
- `scripts/results/eval_groupkfold_ablation.json`（含 `l4_mode` metadata）
- `scripts/results/eval_groupkfold_ttp.json`（含 fold-aware L5 與 legacy 基線比較）
- `scripts/model/calibration_metrics.json`
- `scripts/results/evaluate_selective.json`
- `scripts/results/evaluate_openset.json`
- `scripts/results/eval_false_flag.json`
