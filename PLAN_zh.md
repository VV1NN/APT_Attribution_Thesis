# APT 歸因與組織識別研究計畫（投稿版 v2）

> 最後更新：2026-04-06
> 狀態：投稿導向改版（可執行）
> 研究主軸：在不確定與衝突情資下，實現可校準、可拒判、可追溯的 IoC-level APT 歸因

---

## 0. 投稿定位與一句話貢獻

### 0.1 目標投稿路線

- 第一層：Computers & Security / Digital Investigation / FGCS 類期刊（快速形成完整論文）
- 第二層：USENIX Security / NDSS / CCS workshop 或 short paper（強化新穎性實驗後）

### 0.2 一句話貢獻（論文摘要核心句）

我們提出一個 **IoC-level APT Attribution** 系統，不只輸出 actor label，還能在多源 CTI 衝突與資料漂移下提供 **可信度校準（calibration）**、**拒判機制（abstention/open-set）**、**證據溯源（traceability）** 與 **抗偽旗評估（false-flag robustness）**。

---

## 1. 問題定義、研究問題與假設

### 1.1 研究問題（RQ）

- **RQ1（效能）**：融合 VT 圖特徵與 TTP 語境後，是否能在 IoC-level 歸因上穩定優於單一模態方法？
- **RQ2（可信）**：模型輸出的機率是否可校準，能否在給定 coverage 下控制風險？
- **RQ3（韌性）**：面對偽旗/模仿（mimicry）與來源衝突，歸因性能下降幅度為何？
- **RQ4（實務）**：在未知組織（open-set）與時間漂移（temporal drift）下，系統是否能合理拒判並維持可行動性？

### 1.2 可驗證假設（Hypotheses）

- **H1**：`L1+L2+L3+L4+L5` 在 `Temporal + Source-disjoint split` 下 Macro-F1 顯著優於 `L1~L4`。
- **H2**：經 calibration 後，ECE 與 Brier Score 顯著下降。
- **H3**：加入來源可信度與時間衰減權重後，在 false-flag 模擬下性能下降較小。
- **H4**：open-set 模式可在可接受 FPR 下維持高拒判品質（降低誤歸因）。

---

## 2. 現有資產與基線（保留）

### 2.1 已完成模組

#### 知識圖譜建構 Pipeline
- [x] IoC 清洗（`clean_iocs_v2.py`）：去重、defang 還原、eTLD 黑名單、跨 hash 合併
- [x] VT 元資料擴充（`build_knowledge_graph.py`）
- [x] VT 關係發現（`fetch_vt_relationships.py`）：11 種邊類型
- [x] 單一組織 KG 建構 + Master KG 合併（66,444 節點 / 109,443 邊）

#### 歸因系統
- [x] 詞彙表建構（`build_vocabularies.py`）
- [x] 四層特徵（`build_features.py`）：L1(88d) + L2(35d) + L3(7+Kd) + L4(64d)
- [x] Node2Vec 訓練（`train_node2vec.py`）
- [x] XGBoost + 5-fold CV（`eval_allnodes_correct_cv.py`）
- [x] SHAP 分析（`run_shap_analysis.py`）
- [x] 推論（`inference.py`）

### 2.2 目前結果（15 組織，不含 TTP）

| 指標 | 無門檻 | 門檻 0.3 |
|------|--------|----------|
| Micro-F1 | 80.0% | 95.7% |
| Macro-F1 | 81.8% | 95.2% |
| Coverage | 100% | 81.1% |
| Top-3 Accuracy | 90.1% | — |

> 註：投稿版將把「門檻」正式化為 selective prediction，而非僅固定閾值。

---

## 3. 系統架構改版（從工程整合到研究貢獻）

## 3.1 改版目標

把目前「高準確分類器」升級為「可信歸因系統」：

1. 輸出 `label + confidence + abstain decision + evidence chain`
2. 可處理資料衝突、時間漂移、未知組織與偽旗攻擊
3. 所有設計都有可量化評估指標

## 3.2 架構總覽（V2）

```text
[Data Layer]
  ├─ Sighted IoCs (hash/IP/domain/url)
  ├─ VT metadata + VT relationships
  ├─ CTI reports (203)
  ├─ ATT&CK/TTP mapping
  └─ Source metadata (time, publisher, confidence)

[Evidence Fusion Layer]
  ├─ IoC-Report-TTP 三層對應
  ├─ Source reliability scoring
  ├─ Time decay weighting
  └─ Evidence Graph (with provenance edges)

[Representation Layer]
  ├─ L1-L4 technical/graph features
  ├─ L5 weighted TTP context features
  └─ Consistency features (cross-source disagreement)

[Attribution Engine]
  ├─ Stage A: Base classifier (XGBoost)
  ├─ Stage B: Probability calibration
  ├─ Stage C: Open-set reject / abstention
  └─ Stage D: Counterfactual robustness check

[Post-Attribution Layer]
  ├─ Attack path forecasting
  ├─ SHAP + evidence trace report
  └─ SOC-actionable recommendations
```

## 3.3 模組級修改清單（你現有系統對應）

### M1. 資料層：加入來源可信度與時間資訊

**現況**：IoC 有 `sources`，但未量化來源品質與時效。

**修改**：
- 在 IoC 或 evidence table 新增欄位：
  - `first_seen_ts`, `report_pub_ts`, `source_vendor`, `source_type`
  - `source_reliability_score`（0~1）
  - `ioc_recency_weight = exp(-lambda * age_days)`

**效果**：
- 可量化「老 IoC vs 新 IoC」權重差異
- 能支撐 RQ2/RQ3（可信與韌性）

### M2. 特徵層：L5 從 plain TF-IDF 升級為加權融合

**現況**：L5 只做 TTP TF-IDF。

**修改**：

對每個 IoC 的 TTP 實體（Tool/Way/Exp）使用：

`weighted_tfidf = tf * idf * source_reliability_score * recency_weight`

再新增一組一致性特徵：
- `source_disagreement_rate`
- `ttp_conflict_entropy`
- `num_independent_sources`

**效果**：
- 不是只看「有沒有提到 TTP」，而是看「這個 TTP 可信不可信」
- 可直接回應商業 TI 歸因分歧問題

### M3. 模型層：三階段決策（分類、校準、拒判）

**現況**：單一 XGBoost + threshold。

**修改**：

- **Stage A**：XGBoost 輸出 class probability
- **Stage B**：Calibration（Temperature Scaling / Isotonic）
- **Stage C**：Selective prediction + Open-set reject
  - 若 `max_prob < tau_calibrated` 或 `uncertainty > u0` → 輸出 `ABSTAIN`

**效果**：
- 從「硬分類」升級為「可控風險決策」
- 可在論文中報 `Coverage-Risk`，更有實務價值

### M4. 韌性層：偽旗與模仿攻擊檢測

**現況**：未有對抗評估。

**修改**：
- 實作 `simulate_false_flag.py`
  - Tool mimicry：替換工具名稱到其他 actor 常見工具
  - Way mimicry：替換/注入常見手法
  - Source poisoning：降低高可信來源比例
- 評估模型降幅與拒判行為

**效果**：
- 把「攻擊者會偽裝」變成可量化實驗
- 這是投稿版新穎性的關鍵

### M5. 推論層：輸出格式升級

**現況**：Top-k + score。

**修改輸出**：
- `Top-3 actors`
- `Calibrated confidence`
- `Decision: Predict / Abstain`
- `Abstain reason`（low confidence / source conflict / open-set）
- `Evidence chain`（IoC→report→TTP→feature contribution）

**效果**：
- 審稿人可看到可操作性而非純學術指標

---

## 4. TTP 提取（Phase A）

### 4.1 目標

從 203 份 CTI 報告提取攻擊語境，建立 `IoC → Report → TTP` 對應，產生可加權 L5 特徵。

### 4.2 設計決策

- 主模型：NER-BERT-CRF（Tool/Way/Exp/Purp/Idus/Area）
- 投稿版主實驗先採 `Tool + Way + Exp`
- `Purp/Idus/Area` 放 ablation（避免主線被噪音拖累）

### 4.3 必做輸出

- `ttp_vocabularies.json`
- `ioc_ttp_mapping.json`
- `source_quality_table.json`（新增）

---

## 5. 特徵與模型（Phase B）

### 5.1 最終特徵組

| 層 | 內容 | 維度（估計） |
|----|------|------------|
| L1 | 節點自身屬性 | 88 |
| L2 | 鄰域統計 | 35 |
| L3 | 跨組織重疊 | 7+K |
| L4 | Node2Vec | 64 |
| L5a | TTP weighted TF-IDF (Tool/Way/Exp) | 65~100 |
| L5b | 一致性特徵（衝突/來源數） | 5~12 |

### 5.2 模型流程

1. XGBoost 訓練（主模型）
2. 校準模型（validation split）
3. 推論時進行 selective decision

### 5.3 新增腳本

- `calibrate_probs.py`
- `evaluate_selective.py`
- `evaluate_openset.py`
- `simulate_false_flag.py`

---

## 6. 實驗設計（投稿版核心）

## 6.1 資料切分（必改）

### S1. Random 5-fold（保留）
用於與舊結果對齊，不作主結論。

### S2. Temporal split（主結果 1）
- Train：較早期報告
- Test：較新報告
- 目的：評估時間漂移下泛化

### S3. Source-disjoint split（主結果 2）
- 同一報告來源不可同時出現在 train/test
- 目的：避免來源洩漏造成過度樂觀

### S4. Actor holdout open-set（主結果 3）
- 留出 1~2 組織完全不參與訓練
- 測試是否能拒判未知組織

## 6.2 評估指標

### 分類能力
- Micro-F1 / Macro-F1 / Top-1 / Top-3

### 校準能力
- ECE
- Brier Score
- Reliability Diagram

### 選擇性預測（Selective）
- Coverage-Risk Curve
- AURC（Area Under Risk-Coverage）

### Open-set 能力
- AUROC（known vs unknown）
- FPR@95TPR
- Unknown 上的誤歸因率

### 韌性能力
- 偽旗攻擊下性能下降 `ΔF1`
- 偽旗攻擊下 `Abstain rate` 變化

## 6.3 消融矩陣

| 實驗 | 特徵/機制 |
|------|-----------|
| E1 | L1+L2+L3+L4 |
| E2 | E1 + L5（未加權） |
| E3 | E1 + L5（來源+時間加權） |
| E4 | E3 + calibration |
| E5 | E4 + abstention/open-set |
| E6 | E5 + consistency features |

> 投稿主張：E5/E6 在真實切分與偽旗情境下，整體風險最低。

---

## 7. 攻擊路徑預測（Phase C，作為第二貢獻）

### 7.1 定位調整

攻擊路徑預測在投稿版中定位為 **secondary contribution**：
- 目的是增強 SOC 可行動性
- 不作主 novelty（避免主線分散）

### 7.2 方法

- 以 ATT&CK tactic/kill chain stage 建序列
- 先做一階轉移模型（可重現）
- 輸出下一步 `Top-k stage + confidence`

### 7.3 評估

- Leave-One-Report-Out
- Top-1/Top-3 下一步預測準確率
- 和「固定最常見下一步」基線比較

---

## 8. 投稿版四項貢獻（重寫）

| 編號 | 投稿版貢獻 |
|------|-----------|
| C1 | 建立可追溯的 IoC-Report-TTP 融合框架，顯式建模來源與時間資訊 |
| C2 | 提出來源可信度與時間衰減加權的 TTP 融合特徵，提升歸因穩定性 |
| C3 | 將 IoC-level 歸因升級為可校準、可拒判的風險可控決策流程 |
| C4 | 建立針對偽旗/模仿攻擊的歸因韌性評估框架與實證分析 |

---

## 9. 實作排程（8 週）

### Week 1-2：資料與特徵重構
- [ ] 建立 `source_quality_table`
- [ ] 完成 TTP 抽取與正規化
- [ ] 實作 L5 加權特徵與一致性特徵

### Week 3：切分器與基線重跑
- [ ] Temporal split
- [ ] Source-disjoint split
- [ ] 重跑 E1~E3

### Week 4：校準與選擇性預測
- [ ] Calibration
- [ ] Coverage-Risk 評估
- [ ] 重跑 E4~E5

### Week 5：open-set + 偽旗評估
- [ ] Actor holdout
- [ ] false-flag 模擬
- [ ] 重跑 E6

### Week 6：攻擊路徑預測
- [ ] 序列抽取
- [ ] 轉移模型 + 評估

### Week 7：論文寫作
- [ ] Method
- [ ] Experiment
- [ ] Threats to Validity

### Week 8：投稿整理
- [ ] 圖表與附錄（可重現）
- [ ] 程式與設定檔整理

---

## 10. 新增檔案結構（投稿版）

```text
scripts/
  ttp_extraction/
    run_ner_on_reports.py
    normalize_entities.py
    build_ioc_ttp_mapping.py
    build_source_quality_table.py        # NEW
    build_ttp_sequences.py
  features/
    build_ttp_features_weighted.py       # NEW
    build_consistency_features.py        # NEW
  model/
    train_xgb.py
    calibrate_probs.py                   # NEW
    inference_selective.py               # NEW
  eval/
    make_temporal_split.py               # NEW
    make_source_disjoint_split.py        # NEW
    evaluate_selective.py                # NEW
    evaluate_openset.py                  # NEW
    simulate_false_flag.py               # NEW
    eval_attack_path.py
```

---

## 11. 風險與因應（投稿版）

| 風險 | 影響 | 因應 |
|------|------|------|
| NER 在部分報告準確度不足 | 中 | 加 keyword/regex 備援、手動抽樣校驗 |
| 來源可信度分數主觀 | 高 | 透明規則 + 敏感度分析（不同權重設定） |
| open-set 樣本不足 | 中 | 多輪 actor holdout + bootstrap |
| 偽旗模擬過於理想化 | 中 | 設計多種攻擊強度與組合策略 |
| 路徑預測樣本少 | 中 | 降定位為次貢獻，避免過度宣稱 |

---

## 12. 論文故事線（投稿時用）

1. 現況問題：APT 歸因不只要準，更要可被信任與可行動。
2. 缺口：現有方法多輸出硬分類，忽略來源衝突、時間漂移與偽旗。
3. 方法：IoC-level 多源融合 + 校準 + 拒判 + 韌性評估。
4. 結果：在嚴格切分下仍具穩定性能，且能顯著降低高風險誤歸因。
5. 價值：可直接落地 SOC，支援 analyst 決策。

---

## 13. 最小可投稿版本（MVP）

若時間有限，先完成以下即可形成一篇有說服力論文：

- 完整 E1~E5（含 temporal/source-disjoint）
- calibration + selective prediction
- 至少一組 false-flag robustness 實驗
- 攻擊路徑預測只保留簡版結果作輔助

