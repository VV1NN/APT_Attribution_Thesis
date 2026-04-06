# APT 歸因文獻綜述 (2020-2025)

> 搜集日期：2026-04-06
> 目的：整理 APT 歸因領域 2020-2025 年所有主要論文，按方法分類，識別研究缺口

---

## 一、綜述論文 (Surveys)

| # | 論文 | 年份 | 期刊/會議 | 重點 |
|---|------|------|-----------|------|
| S1 | Saha et al., "A Comprehensive Survey of Automated APT Attribution" | 2024/2025 | JISA (arXiv:2409.11415) | 最完整的歸因分類法：malware-based / threat-report-based / attack-pattern-based / heterogeneous |
| S2 | "A Survey of Cyber Threat Attribution: Challenges, Techniques, and Future Directions" | 2025 | Computers & Security, Vol.157 | 更廣泛的歸因挑戰，含雲端環境歸因衰退、OPSEC 改進 |
| S3 | Saha et al., "Expert Insights into APT: Analysis, Attribution, and Challenges" | 2025 | **USENIX Security 2025** | 15 位實務專家訪談：三層歸因（technical / TTP / country-level），IoC 可靠性低於 TTP |
| S4 | SoK: TTP Extraction from CTI Reports | 2025 | **USENIX Security 2025** | 傳統 NLP 在 TTP 提取上仍優於 LLM |
| S5 | MITRE ATT&CK Survey | 2024 | ACM Computing Surveys | ATT&CK 在威脅情報、歸因中的系統性回顧 |

**關鍵觀察：** S3 的專家訪談指出 practitioners 更信任 TTP 而非 IoC，與我們的實驗發現一致（TTP 跨 campaign 歸因力 2.4 倍於 VT metadata）。

---

## 二、方法分類

### A. 惡意程式行為分析 (Malware Behavioral Analysis)

以沙箱動態行為、API 呼叫序列、opcode 等為特徵，用 ML/DL 分類 APT 群組。

| # | 論文 | 年份 | 期刊/會議 | 方法 | 資料規模 | APT 組數 | 最佳結果 | 評估方式 |
|---|------|------|-----------|------|---------|---------|---------|---------|
| A1 | DeepAPT (Rosenberg et al.) | 2020 | Entropy (MDPI) | 10-layer DNN + transfer learning | Cuckoo Sandbox | Multiple | **99.75%** | Random split |
| A2 | MVFCC (Haddadpajouh et al.) | 2020 | IEEE Access | Multi-view fuzzy consensus clustering | 1,200 samples | 5 | 95.2% | 4,000+ experiments |
| A3 | Li et al. (SMOTE-RF) | 2021 | Security & Comm Networks | SMOTE + Random Forest | Dynamic behavior | Multiple | >80% | Not specified |
| A4 | Kida & Olukoya (Fuzzy Hashing) | 2023 | IEEE Access | RF/SVM/KNN + 5 fuzzy hash types | APT malware | Multiple | Best: RF+IMPFUZZY | Not specified |
| A5 | **Bon-APT** (Shenderovitz & Nissim) | 2024 | Computers & Security | Temporal segmentation of API calls | **12,655 samples** | **188 groups** | 97.65% | Unknown modus operandi test |
| A6 | Zhang et al. (Multi-Feature Fusion) | 2024 | PLOS ONE | CNN-LSTM (opcode images) + GNN (behavior graphs) | 2,809 files | 12 | F1=93.57% | Random split |
| A7 | DRL Attribution | 2024 | ACM DTRAP (arXiv:2410.11463) | Deep Reinforcement Learning | 3,500+ samples | 12 | 94.12% | Random split |
| A8 | TCN-GAN (Chen & Yan) | 2025 | PLOS ONE | Temporal Conv Net + CWGAN-GP | Mixed datasets | Multiple | **99.8%** | Random split |
| A9 | PGPNet | 2024 | **ACM CCS** (Poster) | Meta-learning / few-shot prototype network | APT malware | Multiple | SOTA few-shot | Few-shot eval |
| A10 | Scalable Classification (Subedar) | 2025 | arXiv:2504.15497 | SVM/KNN/CNN + GPU parallel | Opcode-based | Multiple | Focus on speed | Not specified |
| A11 | Asm2Vec APT | 2022 | ACM ICCIP | Assembly semantic embeddings | Disassembled malware | Multiple | Homology analysis | Not specified |

**此類方法的共同問題：**
- 幾乎全部使用 **random train/test split**，未考慮 campaign contamination
- 高準確率（>95%）很可能虛高（我們證明 random split vs GroupKFold 差距 -50%+）
- 需要取得惡意程式樣本進行沙箱分析，**無法從 IoC 直接歸因**
- 資料集多為同一個 APTMalware dataset（3,500 samples, 12 groups），可重複性受限

---

### B. CTI 報告文本分析 (NLP on CTI Reports)

從威脅情報報告提取文本特徵進行歸因。

| # | 論文 | 年份 | 期刊/會議 | 方法 | 資料來源 | 最佳結果 | 評估方式 |
|---|------|------|-----------|------|---------|---------|---------|
| B1 | NO-DOUBT (Perry et al.) | 2019 | IEEE ISI | ML + SMOBI text representation | CTI reports | > baseline | Not specified |
| B2 | Deep Learning from Reports (Angappan & Puzis) | 2020 | IEEE ISI | DNN + domain-specific embeddings (SIMVER) | CTI reports | > NO-DOUBT | Not specified |
| B3 | Wang et al. (Explainable NLP) | 2021 | IEEE QRS | RF + paragraph vectors + BoW + **LIME** | Malware code + strings | — | First LIME for APT |
| B4 | Irshad & Siddiqui (Attack2vec) | 2022 | Egyptian Informatics J | Attack2vec embeddings + RF/SVM | Unstructured CTI | **96%** | Random split |
| B5 | Abdi et al. | 2023 | ACM Workshop | NLP on CTI reports | CTI reports | 97% | Report-level |
| B6 | **Unveiling CTAs** (Ertan et al.) | 2025 | ACM DTRAP | Transformer + CNN on **command sequences** | C2 commands (Cobalt Strike) | **F1=95.11%** | vs BERT/RoBERTa/SecureBERT |
| B7 | Context-Aware Hybrid (Thai CERT) | 2024 | ICT Express | ML/DL + hybrid features | Thai CERT Encyclopedia | 97%/98.8% | Random split |
| B8 | High vs Low IoC | 2023 | arXiv:2307.10252 | Multiple ML classifiers | Real-world CTI | **High-level: 95%, Low-level: 40%** | Not specified |

**此類方法的觀察：**
- B6 最有趣：從 C2 command sequences 歸因（類似行為指紋），但需取得即時 C2 流量
- B8 實驗性地證明 high-level indicators（TTP）遠優於 low-level（hash/IP），與我們結論一致
- 報告級歸因（B4, B5）本質上是在分類「哪個 vendor 分析了哪個 APT」，可能學到 vendor 寫作風格而非 APT 行為

---

### C. TTP / ATT&CK 分析 (TTP-Based Attribution)

基於 MITRE ATT&CK 戰術技術程序進行歸因。

| # | 論文 | 年份 | 期刊/會議 | 方法 | 資料來源 | APT 組數 | 最佳結果 |
|---|------|------|-----------|------|---------|---------|---------|
| C1 | Kim et al. (Vectorized ATT&CK) | 2021 | Sensors (MDPI) | Vectorized ATT&CK matrix + cosine similarity | Mobile malware (Joe Sandbox) | 12 | P=0.91 |
| C2 | **CAPTAIN** | 2024 | arXiv:2409.16400 | Novel TTP sequence similarity measure | TTP sequences | Multiple | **Top-1: 61.36%** |
| C3 | **ATTRACT** | 2025 | Info Security J | Kill-chain-phase-encoded TTP sequences | TTP sequences | Multiple | Interpretable |
| C4 | APTer | 2023 | — | Alert correlation + TTP mapping | SIEM alerts | Multiple | — |

**此類方法的觀察：**
- CAPTAIN 的 top-1 precision 只有 61.36%，說明單獨 TTP 歸因的天花板
- 我們的 TTP（L5）GroupKFold 34.1% 看似較低，但那是在 **嚴格跨 campaign 評估**下
- TTP-based 方法的根本假設是 APT 有穩定的行為模式 → 但部分 APT 會演化/借用工具

---

### D. 知識圖譜 (Knowledge Graph Construction & Attribution)

構建 CTI 知識圖譜用於歸因推理。

| # | 論文 | 年份 | 期刊/會議 | 方法 | 圖結構 | 最佳結果 |
|---|------|------|-----------|------|--------|---------|
| D1 | **CSKG4APT** (Ren et al.) | 2023 | **IEEE TKDE** | KG + DL extraction + expert reasoning | APT attack ontology | Attribution + countermeasures |
| D2 | AttacKG (Li et al.) | 2022 | **ESORICS** | NLP → attack graph → technique KG | Attack techniques + IoCs | F1=0.789 (techniques) |
| D3 | APTKG | 2022 | IEEE DSIT | STIX-based ontology + BiGRU | STIX entities | > alternatives |
| D4 | **AEKG4APT** (Zhou et al.) | 2025 | **ACM TIST** | LLM-enhanced KG construction | APT-focused ontology | LLM > traditional DL |
| D5 | LLM-TIKG (Hu et al.) | 2024 | Computers & Security | GPT few-shot → KG | OSCTI entities | NER P=87.88%, TTP P=96.53% |
| D6 | ThreatKG (Gao et al.) | 2024 | ACM LAMPS | End-to-end KG construction system | Hierarchical threat ontology | Scalable system |
| D7 | STIX Enhancement (Zych & Mavroeidis) | 2022 | ECCWS | STIX 2.1 enrichment | MITRE ATT&CK groups | Ontology contribution |

**此類方法的觀察：**
- 多數專注於 KG **建構**（NER/RE），而非 KG **歸因推理**
- 2024-2025 趨勢：LLM 取代傳統 NER 進行 CTI 實體提取（D4, D5）
- 我們的 KG 獨特之處：VT API enriched 兩層圖（CTI → VT relationships），不依賴 NLP 從報告提取

---

### E. 圖神經網路歸因 (GNN-Based Attribution)

用 GNN 在知識圖譜或異質圖上做歸因分類。

| # | 論文 | 年份 | 期刊/會議 | 方法 | 圖結構 | 最佳結果 | 評估方式 |
|---|------|------|-----------|------|--------|---------|---------|
| E1 | **APT-MMF** (Xiao et al.) | 2024 | Computers & Security | HAN + BERT + Node2Vec | Heterogeneous attributed graph | **83.2%** | Random 8:1:1 split |
| E2 | Het-GNN + SBERT | 2025 | Electronics (MDPI) | Heterogeneous GNN + Sentence-BERT | Tripartite (APT, TTP, CKC stages) | **F1=0.84, Acc=85%** | Classification |
| E3 | APTMalKG (ICCS) | 2024 | ICCS (Springer) | GraphSAGE + domain meta-paths | Malware behavior ontology | **91.16%, AUC=98.99%** | Not specified |
| E4 | HG-CTA (Duan et al.) | 2024 | ACM ICMLC | Metapath-context HetGraph embedding | CTI heterogeneous graph | Link prediction | Link prediction |
| E5 | GAT Classification | 2025 | J Supercomputing | Multi-head GAT | Security entity KG | Improved classification | Not specified |
| E6 | GA-ConvE | 2025 | Neural Networks | GAT + ConvE embedding | APT + CVE/CWE/CAPEC | Link prediction | Link prediction |
| E7 | APT-ST-AN | 2025 | Cyber Security & Apps | KG embedding + spatio-temporal reasoning | Small-scale APT KG | KG completion | Not specified |
| E8 | **HGNN + Explainable AI** (Ghadekar) | 2025 | ICAIQSA | HetGAT + **SHAP** | Static + behavioral + **VirusTotal** | **F1=97.88** | Not specified |
| E9 | HINTI (Zhao et al.) | 2020 | **USENIX RAID** | HIN + GCN | Heterogeneous IoC network | IoC ranking | Ranking |

**此類方法的觀察：**
- APT-MMF 是最直接的競爭者，但有三大問題：random split / GNN transductive leakage / 不開源資料集
- E8 最相似（VT enrichment + SHAP），但 F1=97.88 極可能是 campaign contamination
- 多數用 link prediction 而非 classification，與我們的 overlap voting 方法完全不同
- **無一篇做 cross-campaign（GroupKFold）驗證**

---

### F. 多信號融合 / 混合方法 (Multi-Signal Fusion / Hybrid)

結合多種信號源的歸因方法。

| # | 論文 | 年份 | 期刊/會議 | 方法 | 融合方式 | 最佳結果 |
|---|------|------|-----------|------|---------|---------|
| F1 | **APT-MMF** | 2024 | Computers & Security | HAN + BERT + Node2Vec | Multilevel attention fusion | 83.2% |
| F2 | **ADAPT** (Saha et al.) | 2024 | **ACM RAID** | ML clustering across heterogeneous files | Two-level (campaign + group) | **93-95% precision** |
| F3 | MLDSJ | 2025 | Cybersecurity J | **Dempster-Shafer** evidence fusion | Multiple evidence sources | — |
| F4 | APT-ATT | 2025 | Computer Networks | N-Gram + TF-IDF + CTGAN + stacking | Feature-level fusion | 94.91% |
| F5 | **APT-Scope** (Gulbay) | 2024 | Ain Shams Eng J | HIN + FastRP + Logistic Regression | DNS/WHOIS/SSL enrichment | Link prediction |
| F6 | AutoML + Graph (ICONIP) | 2025 | Springer LNCS | AutoML + graph clustering + hierarchical | Feature + structure | 87.4%/AUC=98.6% |

**此類方法的觀察：**
- ADAPT (F2) 是唯一明確區分 campaign-level 和 group-level 歸因的論文，但用的是無監督聚類
- APT-Scope (F5) 的 DNS/WHOIS/SSL enrichment 最接近我們的 VT enrichment
- **沒有任何論文使用我們的 confidence-gated cascade（Graph → TTP → ML fallback）架構**
- MLDSJ (F3) 的 Dempster-Shafer fusion 概念上最接近我們的 cascade，但細節不同

---

### G. NER 在 CTI 的應用 (Named Entity Recognition for CTI)

| # | 論文 | 年份 | 期刊/會議 | 方法 | 實體類型 | 結果 |
|---|------|------|-----------|------|---------|------|
| G1 | **AttackER** | 2024 | arXiv:2408.05149 | First NER dataset for attribution | **18 entity types** | F1=0.85 (GPT-3.5) |
| G2 | NER-BERT-CRF-for-CTI | — | GitHub | BERT-base + CRF | 13 entity types (BIO) | 我們使用的模型 |

---

### H. 資料集 (Datasets)

| # | 資料集 | 年份 | 規模 | APT 組數 | 特點 |
|---|--------|------|------|---------|------|
| H1 | APTMalware | <2020 | 3,500+ samples | 12 | 最廣泛使用的 benchmark |
| H2 | dAPTaset (Laurenza) | 2020 | 86 APTs, 350 campaigns | 86 | Semi-automatic, 2008-2020 |
| H3 | **APT-ClaritySet** | 2025 | **34,363 samples** | **305** | 最大規模，graph dedup，label acc 96.43% |
| H4 | ThreatInsight | 2024 | CTI structured | Multiple | IEEE dataset for evaluation |

---

## 三、研究缺口分析 (Research Gaps)

### Gap 1: Campaign Contamination 幾乎無人提及
- **現狀：** 除了 ADAPT (RAID 2024) 區分 campaign/group level 外，**沒有任何論文**驗證 cross-campaign generalization
- **影響：** 所有使用 random split 的論文（A1-A8, B4, E1, E3, E8 等）的高準確率可能嚴重虛高
- **我們的貢獻：** 首次用 StratifiedKFold vs GroupKFold 量化 campaign contamination（-50%+ 準確率差距）

### Gap 2: Graph Overlap 的 100% 確定性精度未被發現
- **現狀：** 圖譜方法多用 GNN/link prediction，沒有人嘗試簡單的 1-hop neighbor overlap voting
- **影響：** 錯失了一個高精度、可解釋、無需訓練的歸因方法
- **我們的貢獻：** Clear winner 100% deterministic precision（1,516/1,516 correct），但 coverage 僅 25.5%

### Gap 3: 缺乏 Confidence-Gated 分層歸因
- **現狀：** 所有方法都是「單一模型 → 單一答案」，沒有信心度門檻分流
- **影響：** 無法在 precision 和 coverage 之間做細粒度 trade-off
- **我們的貢獻：** Graph(100% precision, 25.5%) → TTP tie-break → ML fallback 的 cascade 架構

### Gap 4: VT-Enriched IoC KG 未被充分探索
- **現狀：** KG 方法多基於 CTI 報告 NLP 提取（D1-D6），或 MITRE ATT&CK 結構
- **接近的：** APT-Scope (DNS/WHOIS/SSL enrichment), HGNN+XAI (VirusTotal)
- **我們的貢獻：** 66K nodes/109K edges 的 VT-enriched 兩層 IoC KG（直接查 VT API，非 NLP 提取）

### Gap 5: TTP 的跨 Campaign 歸因力未被量化
- **現狀：** TTP 被普遍認為比 IoC 更穩定（S3 專家訪談、B8 high-vs-low），但缺乏在嚴格跨 campaign 設定下的定量比較
- **我們的貢獻：** GroupKFold 下 TTP(34.1%) vs VT metadata(14.0%) = **2.4 倍**，首次定量證明

### Gap 6: IoC → 基礎設施發現 (Infrastructure Discovery) 幾乎無人做
- **現狀：** 歸因後沒有論文進一步探討「正確歸因後能發現多少未知相關基礎設施」
- **我們的貢獻：** 平均 12.0 個 novel 基礎設施節點 / 正確歸因 IoC，P@K=1.000

### Gap 7: Evaluation 方法學普遍薄弱
- **具體問題：**
  - Random split 而非 campaign-aware split
  - 多數論文不報告 dataset 構成（每個 APT 的樣本數、campaign 數）
  - 缺乏 ablation study 來分離各信號的貢獻
  - 跨論文比較困難（不同 APT 組數、不同資料集、不同評估指標）
- **我們的貢獻：** 7 個實驗的系統性消融（L1-L5 各層、各種 split 策略）

### Gap 8: 可解釋性不足
- **現狀：** 僅 Wang et al. (B3) 用 LIME、HGNN+XAI (E8) 用 SHAP
- **影響：** 分析師無法理解模型為何歸因到特定 APT
- **我們的貢獻：** Graph overlap 天然可解釋（可列出具體 shared nodes），SHAP 分析已完成

---

## 四、與我們系統的對比定位

| 維度 | 現有最佳 | 我們的系統 | 優勢 |
|------|---------|-----------|------|
| **資料來源** | CTI 報告 NLP / 惡意程式沙箱 | VT API enriched IoC KG | 不需樣本，IoC 即可 |
| **圖譜規模** | APT-MMF (未公開) | 66K nodes / 109K edges / 21 orgs | 最大公開 APT IoC KG 之一 |
| **評估誠實度** | Random split (所有論文) | **GroupKFold (cross-campaign)** | 唯一做 honest eval |
| **確定性歸因** | 無 | **Graph clear winner: 100% precision** | 獨有發現 |
| **多信號融合** | APT-MMF (attention fusion) | Confidence-gated cascade | 可控 precision-coverage trade-off |
| **TTP 定量比較** | B8 (high vs low, no cross-campaign) | **TTP 2.4x metadata (GroupKFold)** | 首次跨 campaign 定量 |
| **基礎設施發現** | 無 | 12.0 avg novel nodes, P@K=1.0 | 獨有實驗 |

---

## 五、論文索引（按年份）

### 2020
1. DeepAPT (Rosenberg) — DNN on sandbox behavior — Entropy
2. MVFCC (Haddadpajouh) — Multi-view fuzzy clustering — IEEE Access
3. HINTI (Zhao) — Heterogeneous IoC network — USENIX RAID
4. dAPTaset (Laurenza) — Dataset 86 APTs — Springer
5. Deep Learning from Reports (Angappan) — DNN + SIMVER — IEEE ISI

### 2021
6. Li et al. — SMOTE-RF — Security & Comm Networks
7. Kim et al. — Vectorized ATT&CK mobile — Sensors
8. Wang et al. — RF + LIME explainability — IEEE QRS

### 2022
9. CSKG4APT (Ren) — KG + DL extraction — IEEE TKDE
10. AttacKG (Li) — NLP → technique KG — ESORICS
11. APTKG — STIX-based KG — IEEE DSIT
12. Asm2Vec APT — Assembly embeddings — ACM ICCIP
13. Irshad & Siddiqui — Attack2vec — Egyptian Informatics J
14. STIX Enhancement (Zych) — Ontology — ECCWS

### 2023
15. Kida & Olukoya — Fuzzy hashing — IEEE Access
16. High vs Low IoC — ML comparison — arXiv
17. Abdi et al. — NLP CTI reports — ACM Workshop
18. APT-KGL — Provenance graph + GNN — IEEE TDSC
19. KG + Contrastive Learning (Do Xuan) — GCN/GIN — J Intelligent & Fuzzy Systems
20. GCN APT Detection — Vulnerability KG — IJCIS
21. APTer — Alert correlation — —

### 2024
22. **APT-MMF** (Xiao) — HAN + BERT + Node2Vec — Computers & Security ⭐
23. **ADAPT** (Saha) — Heterogeneous file clustering — **ACM RAID** ⭐
24. **Bon-APT** (Shenderovitz) — API temporal segmentation — Computers & Security
25. APTMalKG — GraphSAGE + meta-paths — ICCS
26. HG-CTA (Duan) — HetGraph link prediction — ACM ICMLC
27. DRL Attribution — Deep Reinforcement Learning — ACM DTRAP
28. Zhang et al. — CNN-LSTM + GNN fusion — PLOS ONE
29. LLM-TIKG (Hu) — GPT few-shot → KG — Computers & Security
30. ThreatKG (Gao) — End-to-end KG system — ACM LAMPS
31. **APT-Scope** (Gulbay) — HIN + DNS/WHOIS/SSL — Ain Shams Eng J
32. Clustering APT Groups — NER + weighted similarity — IEEE Access
33. CAPTAIN — TTP sequence similarity — arXiv
34. Context-Aware Hybrid — ML/DL + Thai CERT — ICT Express
35. PGPNet — Few-shot meta-learning — ACM CCS Poster
36. AttackER — NER for attribution (18 types) — arXiv
37. ThreatInsight — Evaluation dataset — IEEE
38. MITRE ATT&CK Survey — ACM Computing Surveys

### 2025
39. **AEKG4APT** (Zhou) — LLM-enhanced KG — **ACM TIST**
40. **Expert Insights** (Saha) — Practitioner interviews — **USENIX Security**
41. SoK: TTP Extraction — NLP vs LLM — **USENIX Security**
42. Comprehensive Survey (Saha) — JISA
43. Cyber Threat Attribution Survey — Computers & Security
44. Het-GNN + SBERT — Tripartite attribution — Electronics
45. GAT Classification — Multi-head GAT — J Supercomputing
46. GA-ConvE — GAT + ConvE link prediction — Neural Networks
47. APT-ST-AN — Spatio-temporal KG embedding — Cyber Security & Apps
48. TCN-GAN (Chen) — TCN + GAN — PLOS ONE
49. **Unveiling CTAs** (Ertan) — Transformer + CNN commands — ACM DTRAP
50. APT-ATT — CTGAN + stacking — Computer Networks
51. AutoML + Graph — ICONIP — Springer
52. MLDSJ — Dempster-Shafer fusion — Cybersecurity J
53. HGNN + Explainable AI — HetGAT + SHAP + VT — ICAIQSA
54. Scalable Classification — GPU parallel — arXiv
55. **APT-ClaritySet** — 34K samples, 305 groups — arXiv
56. ATTRACT — Kill-chain TTP sequences — Info Security J
57. LLM TTP Attribution (Guru) — GPT-4 + embeddings — arXiv
58. Unsupervised Profiling — Hierarchical clustering — arXiv
59. Guru et al. — LLM+Bayesian attribution — arXiv

---

## 六、論文方法分布趨勢

```
2020:  ████ Malware behavioral, HIN
2021:  ███  SMOTE-RF, ATT&CK mobile, LIME
2022:  █████ KG construction 爆發 (CSKG4APT, AttacKG, APTKG)
2023:  ████ Fuzzy hashing, provenance graph, contrastive learning
2024:  ██████████ 最多產年 — APT-MMF, ADAPT, Bon-APT, GNN methods
2025:  ██████████ LLM 進入 (AEKG4APT, LLM-TIKG), 大型 dataset (ClaritySet)
```

**趨勢：**
1. 2020-2022: 傳統 ML + KG 建構
2. 2023-2024: GNN 歸因 + 多模態融合
3. 2025: LLM-enhanced extraction + 更大資料集 + 可解釋性需求增加
