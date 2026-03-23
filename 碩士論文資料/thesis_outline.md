# 碩士論文詳細架構

## 論文題目
融合目擊 IoC 與 CTI 情資資料進行 APT 組織辨識之方法研究

---

## 第一章　緒論 (Introduction)

### 1.1 研究背景與動機 (Research Background and Motivation)

要點：
- APT 組織對全球資安的威脅現況（可引用近年重大 APT 事件：SolarWinds/APT29、Colonial Pipeline 等）
- 威脅情資（CTI）在現代資安防禦中的角色：從被動防禦到主動獵捕
- 「目擊 IoC」的概念：社群媒體（X/Twitter）、OSINT、Paste sites 等非結構化來源出現的零碎 IoC
- 現有 APT 歸因方法的局限：
  - 人工分析：依賴資深分析師經驗，耗時且無法規模化
  - 單一維度比對：僅比 hash 或 IP，無法應對基礎設施輪替
  - 缺乏預測能力：只能事後歸因，無法預判攻擊者下一步
- 引出研究問題：「如何利用已知 APT 組織的歷史 IoC 與 VT 關聯性資料，自動歸因新出現的目擊 IoC，並預測潛在後續威脅？」

### 1.2 研究目的 (Research Objectives)

要點：
1. 建立一套系統化的 APT IoC 資料收集與清洗管道，涵蓋 177 個 APT 組織
2. 提出基於多層次子圖相似度的 APT 歸因方法，融合 IoC 身份、屬性與結構三個維度
3. 設計子圖差集分析機制，從歸因結果延伸至下一步威脅預測
4. 透過實驗驗證所提方法之有效性，包含歸因準確率、消融分析與權重敏感度分析

### 1.3 研究範圍與限制 (Scope and Limitations)

要點：
- 資料來源範圍：MITRE ATT&CK、VirusTotal API（免費帳號限制）、公開 APT 報告
- IoC 類型範圍：file hash (MD5/SHA256)、domain、IP，不含 URL 和 email
- VirusTotal 免費帳號每日 500 次 API 限額的影響
- 僅涵蓋具有足夠公開 IoC 資料的 APT 組織
- 不涉及惡意程式逆向分析或沙箱行為分析

### 1.4 論文架構 (Thesis Organization)

要點：
- 簡述各章內容（一段話即可）

---

## 第二章　文獻探討 (Literature Review)

### 2.1 進階持續性威脅概述 (Overview of APT)

要點：
- APT 的定義與特徵（持續性、隱蔽性、目標針對性）
- APT 攻擊生命週期（Kill Chain / MITRE ATT&CK 框架）
- 知名 APT 組織簡介（APT28/Fancy Bear、APT29/Cozy Bear、Lazarus Group 等）
- APT 與一般網路犯罪的區別

### 2.2 威脅情資與入侵指標 (Cyber Threat Intelligence and IoC)

要點：
- CTI 的定義與分層模型（戰略/作戰/戰術層級）
- IoC 的定義與類型分類（Network indicators, Host indicators, File indicators）
- IoC 的生命週期與老化問題（IoC aging）
- 結構化威脅情資標準：STIX 2.1、TAXII
- 開放威脅情資平台：MITRE ATT&CK、AlienVault OTX、ThreatFox、Malpedia
- VirusTotal 平台介紹：API v3、relationship 查詢、Graph 功能

### 2.3 APT 歸因方法相關研究 (Related Work on APT Attribution)

要點：
- 傳統歸因方法：
  - 基於 IoC 比對的歸因（IoC matching / IoC overlap）
  - 基於 TTP 分析的歸因（MITRE ATT&CK mapping）
  - 基於惡意程式分析的歸因（code similarity、compiler fingerprint）
  - 基於基礎設施追蹤的歸因（WHOIS、passive DNS、SSL certificate）
- 機器學習方法：
  - 基於特徵工程的分類器（Random Forest、XGBoost）
  - 圖神經網路（GNN）應用於威脅情資
- 現有方法的不足：
  - 單一維度（只比 hash 或只比 TTP）
  - 缺乏結構性分析（沒有考慮 IoC 之間的關聯拓撲）
  - 缺乏預測能力（只能歸因，無法預測下一步）
- 本研究與現有工作的定位差異

### 2.4 圖論與子圖相似度 (Graph Theory and Subgraph Similarity)

要點：
- 異質圖（Heterogeneous Graph）定義：多類型節點與多類型邊
- 圖相似度度量方法：
  - Graph Edit Distance (GED)
  - Weisfeiler-Lehman (WL) Kernel
  - Jaccard / cosine similarity 在圖節點層級的應用
  - 子圖匹配（Subgraph Matching）
- 圖在資安領域的應用：
  - Provenance Graph（系統溯源圖）
  - Knowledge Graph（知識圖譜）用於 CTI
  - Attack Graph（攻擊圖）
- 本研究選擇多層次子圖相似度（而非 GED 或 WL Kernel）的理由：
  - 可解釋性高（每一層的匹配結果都可追溯）
  - 計算效率優於 GED（NP-hard）
  - 不需要固定的節點標籤體系（優於 WL Kernel）

### 2.5 本章小結 (Summary)

---

## 第三章　研究方法 (Methodology)

### 3.1 系統架構總覽 (System Architecture Overview)

要點：
- 五階段流程圖（放之前畫的系統架構圖）
- 各階段簡要說明
- 雙路徑設計：已知 APT CTI → Prototype / 未知目擊 IoC → Query

### 3.2 資料收集與清洗 (Data Collection and Cleaning)

#### 3.2.1 IoC 資料來源
- MITRE ATT&CK Groups（177 個組織）
- 公開 APT 報告（Mandiant、CrowdStrike、Kaspersky 等）
- 各組織的 IoC 原始格式（iocs.json schema 說明）

#### 3.2.2 IoC 清洗管道
- 類型過濾：僅保留 ipv4、domain、md5、sha1、sha256
- Defanged 還原（hxxp → http、[.] → .）
- 同值去重與 sources 合併
- Cross-hash 合併（同檔案的 MD5/SHA1/SHA256 合併）
- eTLD+1 黑名單過濾與 DDNS 白名單保留
- 清洗統計（177 → 176 組織，附 all_cleaning_stats.json 的分析）

#### 3.2.3 VirusTotal 特徵富化
- VT API v3 掃描流程
- 提取的節點屬性：malicious、suspicious、harmless、undetected、reputation、network_info
- 172 個組織的掃描結果統計

#### 3.2.4 VirusTotal 關聯性擴展
- VT Relationship API endpoints（file → contacted_domains/ips、domain → resolutions、IP → resolutions）
- 關聯資料的 JSON 格式
- 資料收集策略：API 限額下的優先順序設計
- 有效 IoC 類型過濾（排除 url、email）

### 3.3 異質關聯子圖建構 (Heterogeneous Subgraph Construction)

#### 3.3.1 節點類型定義
- File 節點：malware hash，屬性含 malicious/suspicious/reputation
- Domain 節點：惡意域名，屬性含 malicious/reputation/whois
- IP 節點：中繼 IP，屬性含 malicious/reputation/ASN/country
- TTP 節點：ATT&CK Technique ID，屬性含 tactic 分類
- CTI 節點：事件容器節點（不參與相似度比較）

#### 3.3.2 邊類型定義
- resolutions（domain → IP）
- contacted_domains（file → domain）
- contacted_ips（file → IP）
- dropped_files（file → file）
- execution_parents（file → file）
- uses_technique（CTI → TTP）
- communicates_with（CTI → IP/domain）

#### 3.3.3 節點 ID 命名規則
- 格式：`{type}_{value}`
- 確保跨組織的 IoC 可透過 value 直接比對

#### 3.3.4 Prototype Subgraph 與 Query Subgraph
- Prototype：已知 APT 組織的完整歷史 IoC 關聯圖
- Query：新出現的未知目擊 IoC 經 VT 擴張後的子圖
- JSON 儲存格式規範（apt_name、nodes、edges、edge_source）

### 3.4 三層次子圖相似度引擎 (Three-Level Subgraph Similarity Engine)

**（本節為論文核心貢獻，需詳細撰寫）**

#### 3.4.1 設計理念
- 遞進式匹配：從最精確（身份匹配）到最寬鬆（結構匹配）
- 每一層處理前一層未匹配的節點
- Greedy matching 策略：每個 query 節點最多匹配一個 prototype 節點

#### 3.4.2 第一層：節點身份匹配 (Level 1 — Node Identity Matching)

公式：
$$L_1(G_q, G_p) = J(V_q, V_p) = \frac{|V_q \cap V_p|}{|V_q \cup V_p|}$$

其中 $V_q$、$V_p$ 為兩圖中非 CTI 類型節點的 value 集合。

說明：
- CTI 容器節點排除的理由
- 匹配結果記錄（shared_iocs 列表）
- L1 > 0 代表兩起事件共享基礎設施，是最強歸因信號

#### 3.4.3 第二層：類型感知節點屬性相似度 (Level 2 — Type-Aware Node Attribute Similarity)

設計：
- 同類型節點才互相比較（file vs file、domain vs domain）
- 各類型專屬特徵向量：

$$\vec{f}_{file} = \left[\frac{mal}{72}, \frac{sus}{72}, \frac{har}{72}, \frac{und}{72}, \frac{rep}{100}, \frac{mal}{total}\right] \in \mathbb{R}^6$$

$$\vec{f}_{domain} = \left[\frac{mal}{72}, \frac{sus}{72}, \frac{har}{72}, \frac{rep}{100}, whois\right] \in \mathbb{R}^5$$

$$\vec{f}_{ip} = \left[\frac{mal}{72}, \frac{sus}{72}, \frac{har}{72}, \frac{rep}{100}, \frac{asn}{10^5}, h(country)\right] \in \mathbb{R}^6$$

$$\vec{f}_{ttp} = \text{one-hot}(tactic) \in \mathbb{R}^{14}$$

配對公式：
$$\text{sim}(q, p) = \frac{\vec{f}_q \cdot \vec{f}_p}{||\vec{f}_q|| \cdot ||\vec{f}_p||}$$

門檻：$\text{sim} \geq 0.6$

分數計算：
$$L_2 = \frac{|\{q \in Q_{unmatched} : \exists p, \text{sim}(q,p) \geq 0.6\}|}{|Q_{unmatched}|}$$

說明：
- 為何不用統一維度向量（type one-hot 主宰 cosine 的問題）
- Greedy matching 的貪婪配對策略
- 門檻 0.6 的選擇（待 grid search 確認）

#### 3.4.4 第三層：鄰居結構相似度 (Level 3 — Neighborhood Structure Similarity)

設計：
- 對 L1+L2 都未匹配的節點，檢查其 1-hop 鄰居
- 兩種匹配方式：

**2.1.1 型匹配**（鄰居身份重疊）：
$$J_{nbr}(q, p) = \frac{|N(q) \cap N(p)|}{|N(q) \cup N(p)|} \geq 0.2$$

**2.1.2 型匹配**（鄰居屬性相似，fallback）：

鄰居統計摘要向量（固定 8 維）：
$$\vec{s}(v) = \left[\frac{|N|}{20}, r_{file}, r_{domain}, r_{ip}, \frac{\bar{mal}}{72}, \frac{\bar{rep}}{100}, r_{mal>0}, r_{rep<0}\right]$$

$$\text{sim}_{nbr}(\vec{s}(q), \vec{s}(p)) \geq 0.5$$

分數計算：
$$L_3 = \frac{|\text{structural\_matches}|}{|Q_{remaining}|}$$

#### 3.4.5 全局分數聚合與歸因判定

$$S(G_q, G_p) = w_1 \cdot L_1 + w_2 \cdot L_2 + w_3 \cdot L_3$$

$$\text{Attribution} = \begin{cases} \arg\max_p S(G_q, G_p) & \text{if } \max_p S \geq t \\ \text{Unknown} & \text{otherwise} \end{cases}$$

- 權重透過 Grid Search（66 種組合，$w_1 + w_2 + w_3 = 1$）最佳化
- 門檻 $t$ 透過 Precision-Recall-F1 曲線選定

### 3.5 下一步威脅預測 (Next-Stage Threat Prediction)

#### 3.5.1 子圖差集分析
$$\text{Predicted} = \{v \in V_{proto} : \text{value}(v) \notin \text{Values}(G_q)\}$$

#### 3.5.2 信心度計算
$$\text{confidence}(v) = \alpha \cdot \frac{1}{1 + d_{hop}(v)} + \beta \cdot \frac{\deg(v)}{\max_{u \in V_{proto}} \deg(u)}$$

其中 $\alpha = 0.6$，$\beta = 0.4$，$d_{hop}$ 為到最近已匹配節點的最短路徑。

#### 3.5.3 預測結果解釋
- 距離已匹配節點越近（hop 小）→ 信心度越高
- 在 prototype 中 degree 越高（越核心）→ 信心度越高

### 3.6 本章小結 (Summary)

---

## 第四章　系統實作 (System Implementation)

### 4.1 開發環境 (Development Environment)

要點：
- Python 3.12、uv 套件管理
- 主要套件：NetworkX、NumPy、scikit-learn、requests
- VirusTotal API v3

### 4.2 系統模組設計 (Module Design)

要點：
- 模組架構圖（cti_predictor/ 下各 .py 的關係）
- 各模組職責說明（對應表格）

#### 4.2.1 特徵提取模組 (feature_extractor.py)
- VTFeatureExtractor 類別設計
- API 呼叫與 rate limiting
- file / domain / IP 三種 endpoint 的特徵提取

#### 4.2.2 相似度引擎模組 (similarity.py)
- SubgraphSimilarity 類別設計
- _build_graph() 靜態方法（方案 C 決策理由）
- 三層計算方法的實作細節
- _node_to_feature_vector() 的 type-aware 設計

#### 4.2.3 歸因器模組 (predictor.py)
- APTAttributor 類別設計
- Prototype 載入與管理
- 歸因流程（attribute() 方法）
- 批量歸因（attribute_batch() 方法）

#### 4.2.4 評估模組 (evaluator.py)
- CTIEvaluator 類別設計
- Top-K Accuracy、MRR 計算
- 多類別混淆矩陣
- 威脅預測 Precision/Recall

#### 4.2.5 資料轉換工具 (convert_vt_to_prototype.py)
- VT_results → Prototype JSON 的轉換邏輯
- 支援 vt_relationships 真實邊 vs co_occurrence 邊

### 4.3 命令列介面 (CLI Interface)

要點：
- 三個子命令：build-prototype、attribute、evaluate
- 使用範例與參數說明

### 4.4 本章小結 (Summary)

---

## 第五章　實驗結果與分析 (Experiments and Analysis)

### 5.1 資料集描述 (Dataset Description)

#### 5.1.1 IoC 資料集統計
- 原始 IoC：177 組織
- 清洗後：176 組織
- VT 掃描：172 組織
- IoC 類型分布圖（bar chart）
- 各組織 IoC 數量分布圖（長尾分布 CDF）

**[Figure] 各 APT 組織有效 IoC 數量分布（降序 bar chart + cutoff 線）**
**[Figure] IoC 類型分布（file hash / domain / IP 的 stacked bar chart）**

#### 5.1.2 實驗用 APT 組織
- 選擇標準：具有 VT relationship 真實邊資料
- 各組織的 prototype 統計（節點數、邊數、IoC 類型分布）

**[Table] 實驗用 APT 組織 Prototype 統計**
| APT 組織 | 國家 | 節點數 | 邊數 | File | Domain | IP | 邊來源 |
|---------|------|-------|------|------|--------|-----|--------|
| APT28   | 俄羅斯 | 850 | 881 | 228 | 382 | 240 | vt_relationships |
| APT-C-23 | 中東 | 202 | 170 | 124 | 34 | 44 | vt_relationships |
| APT-C-36 | 中國 | 120 | 8 | 105 | 5 | 10 | vt_relationships |
| ...（擴展後的組織）| | | | | | | |

### 5.2 實驗設計 (Experimental Design)

#### 5.2.1 評估指標
- Top-1 / Top-3 / Top-5 Accuracy
- Mean Reciprocal Rank (MRR)
- Unknown Detection Rate
- 混淆矩陣
- 威脅預測 Precision / Recall / F1

#### 5.2.2 實驗方法
- Leave-One-Out 交叉驗證設計（30% query / 70% reduced prototype）
- 隨機試驗次數：5 trials per APT
- Random seed 固定（可重現性）

### 5.3 實驗一：歸因準確率評估 (Attribution Accuracy)

要點：
- Leave-One-Out 結果表格
- 各 APT 的 Top-1, Top-3 表現
- 混淆矩陣分析：哪些組織容易混淆、為什麼

**[Table] Leave-One-Out 歸因結果**
**[Figure] 混淆矩陣 Heatmap**

### 5.4 實驗二：消融實驗 (Ablation Study)

要點：
- 四種權重配置：L1 only / L1+L2 / L1+L2+L3 / Equal
- 各配置的 Top-1 和 MRR 比較
- 分析每一層的貢獻
- 討論 L2 heavy 反而下降的原因

**[Table] 消融實驗結果**
**[Figure] 消融實驗 Bar Chart（Top-1 和 MRR 對比）**

### 5.5 實驗三：權重敏感度分析 (Weight Sensitivity Analysis)

要點：
- Grid Search：66 種 (w1, w2, w3) 組合
- Top-10 最佳配置
- 最終選擇的權重及理由

**[Table] Grid Search Top-10 權重配置**
**[Figure] 權重 Grid Search 三角 Heatmap**

### 5.6 實驗四：歸因門檻分析 (Threshold Sensitivity Analysis)

要點：
- 掃描 threshold = 0.05 ~ 0.70
- Precision / Recall / F1 曲線
- 最佳 operating point 的選擇

**[Figure] Threshold vs Precision-Recall-F1 曲線**

### 5.7 實驗五：分數分布分析 (Score Distribution Analysis)

要點：
- 正確歸因 vs 錯誤歸因的分數分布
- Gap 分析
- 分離度（separability）討論

**[Figure] 正確 vs 錯誤歸因分數分布 Histogram**

### 5.8 實驗六：威脅預測評估 (Threat Prediction Evaluation)

要點：
- 隱藏 30% 節點作為 ground truth
- 預測命中率（Precision / Recall）
- 信心度與實際命中的相關性分析

**[Table] 威脅預測評估結果**

### 5.9 討論 (Discussion)

要點：
- Prototype 大小對歸因準確率的影響（APT28 大圖 = 100% vs APT-C-36 小圖 = 20%）
- 同國家不同組織的區分能力（俄系 APT28/29/Turla 三角對照）
- L1 在 leave-one-out 設計下的限制與 holdout 實驗的補充
- VT API 資料品質對結果的影響
- 與現有方法的比較（如果有 baseline 的話）

### 5.10 本章小結 (Summary)

---

## 第六章　結論與未來展望 (Conclusion and Future Work)

### 6.1 研究結論 (Conclusion)

要點：
- 回顧研究目的（四個目標）逐一說明是否達成
- 主要貢獻：
  1. 提出三層次子圖相似度歸因方法
  2. 建立 177 組織的 IoC 資料集與 VT 富化管道
  3. 消融實驗驗證三層設計的必要性
  4. 子圖差集預測機制的概念驗證
- 最終實驗數據摘要

### 6.2 未來展望 (Future Work)

要點：
- 擴大 VT Relationship 資料覆蓋率（目前僅部分組織有真實邊）
- 引入圖神經網路（GNN）替代或增強 Level 2/3 的相似度計算
- 時間衰減因子：IoC 老化的處理（較新的 IoC 權重較高）
- 自動化持續更新：當新的 APT 報告發布時自動更新 prototype
- 結合 STIX/TAXII 標準實現威脅情資自動交換
- 與 SIEM/SOAR 平台整合，實現即時歸因

---

## 參考文獻 (References)

---

## 附錄 (Appendix)

### 附錄 A：Prototype JSON 格式規範
### 附錄 B：VT API Endpoint 對照表
### 附錄 C：ATT&CK Technique → Tactic 對照表
### 附錄 D：完整 Grid Search 結果表
### 附錄 E：各 APT 組織 IoC 統計明細
