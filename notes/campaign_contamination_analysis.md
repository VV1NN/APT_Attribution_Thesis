# Campaign-Specific Contamination 分析筆記

> 日期：2026-03-31
> 背景：在 APT 歸因系統的 evaluation 中發現，StratifiedKFold 與 GroupKFold 之間存在巨大落差，揭露了 metadata-based 歸因方法的根本性問題。

---

## 1. 問題發現

### 1.1 實驗設定

- **資料集**：16 個 APT groups、5,961 筆 L0 IoCs（depth=0，來自 CTI 報告）
- **特徵**：L1 (88d VT metadata) + L2 (35d 鄰域拓撲) + L3 (22d overlap voting) + L4 (64d Node2Vec)
- **分類器**：XGBoost (n_estimators=500, max_depth=8, balanced sample_weight)
- **IoC 來源**：127 份 CTI 報告，分布於 15 個 org（APT-C-36 僅 1 份報告）

### 1.2 兩種 CV 比較

| CV 方式 | 語義 | 特性 |
|---------|------|------|
| **StratifiedKFold** | Random split，保持 class 比例 | 同一份報告的 IoC 可能同時出現在 train 和 test |
| **GroupKFold (by report)** | 以報告為單位分組 | 同報告 IoC 只能全部在 train 或全部在 test |

### 1.3 核心結果

| 特徵組合 | StratifiedKFold | GroupKFold | Δ (差距) |
|---------|----------------|-----------|----------|
| L1 (88d) | 63.8% | 14.0% | **-49.8%** |
| L1+L2 (123d) | 69.6% | 17.3% | **-52.3%** |
| L1+L2+L3 (145d) | 69.8% | 12.8% | **-57.0%** |
| L1+L2+L3+L4 (209d) | 72.1% | 16.1% | **-56.0%** |
| L3 alone (22d) | 8.3% | 17.5% | +9.2% |

> 15 class random guess = 6.7%，GroupKFold 下所有配置都接近 random level。

### 1.4 Per-class 全面崩潰

即使是有 16 個 report groups 的 Lazarus_Group（最多報告的 org），F1 仍從 66.8% 掉到 35.6%。

只做 ≥5 report groups 的 12 個 org 子集（排除 APT-C-36、APT-C-23、Wizard_Spider），差距仍為 **-46.2%**，排除了「GroupKFold class 不平衡」的解釋。

---

## 2. 為什麼會這樣：Campaign-Specific vs. APT-Specific

### 2.1 根本原因

同一份 CTI 報告中的 IoC 來自**同一次攻擊行動 (campaign)**。同一 campaign 的 IoC 共享：

- **相同的基礎設施**：同一 C2 server → 同一 ASN/country/registrar
- **相同的工具鏈**：同一 builder 產生的 payload → 同一 PE imphash/type_tag/entropy
- **相同的偵測特徵**：同時被提交分析 → 相似的 detection_ratio/threat_label
- **相同的 DNS 架構**：同一 campaign 的 domain 常用同一 registrar、同一 TLD

### 2.2 StratifiedKFold 的問題

```
Report X (APT28, 50 IoCs):
  hash_1, hash_2, ..., hash_50   ← 全部用同一 C2, 同一 packer

StratifiedKFold:
  Train: hash_1 ~ hash_40   (80%)
  Test:  hash_41 ~ hash_50  (20%)

模型學到: "PE imphash=0xABC + registrar=GoDaddy + ASN=Amazon → APT28"
→ 這不是 APT28 的 general pattern，而是 Report X 這次 campaign 的 fingerprint
→ hash_41~50 和 hash_1~40 幾乎一模一樣 → 輕鬆猜對 → 虛高 F1
```

### 2.3 GroupKFold 揭露了什麼

```
GroupKFold:
  Train: Report A, B, C (APT28 的其他 campaigns)
  Test:  Report X (全部 50 IoCs)

模型需要: 從 campaign A/B/C 學到 APT28 的 general pattern
→ 但 campaign A 用 Namecheap + DigitalOcean
→ campaign B 用 Cloudflare + Hetzner
→ campaign C 用 GoDaddy + OVH
→ 沒有 cross-campaign 一致的 metadata pattern → F1 崩潰
```

### 2.4 直覺解釋

想像你要辨認一個人：

| 特徵類型 | 類比 | 跨場景穩定性 |
|---------|------|------------|
| VT metadata (registrar, ASN, TLD) | 這個人今天穿什麼衣服 | ❌ 每天不同 |
| PE structure (imphash, entropy) | 這個人的身材、體型 | ⚠️ 有辨識度但可偽裝 |
| Code reuse patterns | 這個人的筆跡 | ✅ 相對穩定 |
| Behavioral / TTP | 這個人的行為習慣、說話方式 | ✅✅ 最穩定 |

**現有系統全在看「穿什麼衣服」，所以換一套衣服（新 campaign）就認不出來了。**

---

## 3. 特徵層次分析

### 3.1 L1 (88d VT metadata) — Campaign-Specific

| 特徵 | 來源 | 跨 campaign 穩定性 | 說明 |
|------|------|-------------------|------|
| detection_ratio | VT 掃描結果 | ❌ 低 | 新樣本偵測率低，舊的高 |
| malicious/suspicious | VT 引擎 | ❌ 低 | 隨時間和提交時機變化 |
| type_tag (peexe/pedll...) | 檔案格式 | ⚠️ 中 | 同 APT 可能用不同格式 |
| pe_imphash | PE import hash | ⚠️ 中 | 同 builder 相同，換 builder 就不同 |
| pe_resource_lang | PE 資源語言 | ⚠️ 中 | 有些 APT 固定用某語言，但可偽造 |
| registrar | 域名註冊商 | ❌ 低 | 隨 campaign 更換 |
| tld | 頂級域名 | ❌ 低 | .com/.org/.xyz 隨機選擇 |
| creation_year | 域名建立年份 | ❌ 低 | 每次 campaign 註冊新域名 |
| country | IP 所屬國家 | ⚠️ 中 | 有些 APT 偏好特定 hosting provider，但不穩定 |
| asn / as_owner | 自治系統 | ⚠️ 中 | 同上 |
| jarm | TLS fingerprint | ⚠️ 中 | 取決於 C2 framework，有一定穩定性 |

**結論：L1 特徵中沒有任何一個 feature 在跨 campaign 場景下高度穩定。**

### 3.2 L2 (35d 鄰域拓撲) — 部分 Campaign-Specific

- 邊類型分布（12d）：某 IoC 有多少 contacted_ip / dropped_file / resolves_to 等
  - ⚠️ 反映的是該 campaign 的攻擊架構，不完全是 APT 的行為風格
- 1-hop 鄰居統計（10d）：鄰居的 detection ratio、類型分布
  - ❌ 高度依賴該 campaign 的基礎設施
- 2-hop 統計（5d）：更遠的鄰居
  - ❌ 同上

**在 GroupKFold 下 L2 提供了 +3.3% 增量**（14.0% → 17.3%），說明鄰域拓撲有微弱的跨 campaign 信號（例如某些 APT 偏好「file→多個 contacted_ip」vs.「file→少量 contacted_domain」的攻擊模式）。

### 3.3 L3 (22d Overlap Voting) — 理論上最強，但受限於 evaluation

L3 的核心邏輯：「你的鄰居屬於哪些 org？」

- 在 StratifiedKFold：同 report 的其他 IoC 在 overlap dict → 強信號
- 在 GroupKFold + test IoC removal：同 report 的 IoC 全被移除 → L3 幾乎全零

**GroupKFold 下 L3 反而是負貢獻**（L1+L2=17.3% → +L3=12.8%），因為零值 L3 特徵干擾了分類器。

**但 L3 alone 在 GroupKFold 表現 17.5% > StratifiedKFold 的 8.3%**，因為：
- GroupKFold 時，test IoC 的鄰居如果跨報告共享（不同 campaign 的 IoC 連到同一 L1 節點），L3 仍能捕捉到
- 這代表 **跨 campaign 的基礎設施共享確實存在**，只是太稀少

### 3.4 L4 (64d Node2Vec) — 結構性 Campaign-Specific

Node2Vec embedding 捕捉的是圖上的結構位置。同一 campaign 的 IoC 在圖上彼此鄰近 → embedding 相似 → 跨 campaign 不泛化。

---

## 4. 對現有文獻的影響

### 4.1 多數論文未驗證跨 campaign 泛化

| 論文類型 | 典型 CV 方式 | 是否有 campaign contamination 風險 |
|---------|------------|--------------------------------|
| Malware family classification | Random split | ⚠️ 是（同 family 的 variants 高度相似） |
| APT attribution (metadata) | Stratified CV | ❌ 嚴重（同 campaign IoC 幾乎相同） |
| APT attribution (behavioral) | Random split | ⚠️ 較輕（行為特徵跨樣本變異較大） |
| Malware clustering | 無 CV（unsupervised） | N/A |

### 4.2 為什麼某些方法能跨 campaign 歸因

能夠真正跨 campaign 歸因的方法，使用的是 **APT-invariant** 特徵：

**程式碼重用 (Code Reuse)**
- APT 組織跨 campaign 共用 code module / library
- 特徵：function-level hashing (ssdeep, TLSH)、BinDiff similarity、shared code blocks
- 代表：code clone detection、binary similarity analysis
- 穩定性來源：開發成本高，不會每次 campaign 都重寫所有程式碼

**行為序列 (Behavioral Sequences)**
- Sandbox 動態分析產生的 API call sequences、process trees
- 同 APT 的惡意程式即使外觀不同，內部行為模式相似
- 代表：dynamic analysis → sequence embedding → classification

**TTP 層級 (Tactics, Techniques, Procedures)**
- 映射到 MITRE ATT&CK 框架
- 同 APT 跨 campaign 使用相似的攻擊技術組合
- 例：APT28 偏好 T1566.001 (Spearphishing Attachment) + T1059.001 (PowerShell) + T1071.001 (Web Protocols)
- 穩定性來源：攻擊者的技能和偏好不會因為換一次 campaign 就改變

**網路行為模式 (Network Behavior)**
- C2 communication patterns（beacon interval、jitter、protocol structure）
- DNS query patterns
- 這些比「用哪個 IP/domain」更穩定

### 4.3 特徵層次光譜

```
Campaign-specific ──────────────────────────────── APT-specific
(換 campaign 就變)                               (跨 campaign 穩定)

VT metadata    PE structure    Code reuse    Behavioral    TTP
(registrar,    (imphash,       (function     (API calls,   (ATT&CK
 ASN, TLD,     entropy,        hashing,      process       technique
 det.ratio)    sections)       BinDiff)      trees)        sequences)

  ← 你現在在這裡                                    你的 NER pipeline →
                                                   可以到這裡
```

---

## 5. 實驗數據細節

### 5.1 Report Group 分布

| Org | Report Groups | IoCs | Avg IoC/Report | 說明 |
|-----|--------------|------|---------------|------|
| APT29 | 17 | 712 | 41.9 | 多 report，相對公平 |
| Lazarus_Group | 16 | 422 | 26.4 | 多 report |
| Sandworm_Team | 15 | 339 | 22.6 | |
| APT28 | 14 | 241 | 17.2 | |
| Turla | 10 | 188 | 18.8 | |
| OilRig | 9 | 189 | 21.0 | |
| Magic_Hound | 8 | 906 | 113.3 | 少數報告有大量 IoC |
| FIN7 | 7 | 360 | 51.4 | |
| Kimsuky | 7 | 179 | 25.6 | |
| MuddyWater | 7 | 250 | 35.7 | |
| APT32 | 5 | 288 | 57.6 | |
| Gamaredon_Group | 5 | 723 | 144.6 | 大量 IoC 集中在少數報告 |
| APT-C-23 | 3 | 249 | 83.0 | 太少 report |
| Wizard_Spider | 3 | 797 | 265.7 | 788/797 來自 1 份報告 |
| APT-C-36 | 1 | 118 | 118.0 | 僅 1 份報告，無法做 GroupKFold |

### 5.2 Campaign 集中度問題

部分 org 的 IoC 高度集中在少數報告：
- **Wizard_Spider**：788/797 IoCs (98.9%) 來自同一份報告
- **Gamaredon_Group**：5 份報告涵蓋 723 IoCs
- **Magic_Hound**：8 份報告涵蓋 906 IoCs

這意味著 StratifiedKFold 下這些 org 的 F1 幾乎完全是 campaign memorization。

### 5.3 Graph Connectivity 的跨 campaign 驗證

Per-Report Leave-One-Out 實驗（移除整份報告的所有 IoC + 獨佔 L1 鄰居）：

| 測試方式 | Coverage | Accuracy | Overall |
|---------|----------|----------|---------|
| Per-IoC (同 campaign 還在) | 68.2% | 93.8% | 63.9% |
| **Per-Report (跨 campaign)** | **47.5%** | **66.7%** | **31.7%** |
| ML classifier (GroupKFold) | 100% | ~14% | ~14% |

Graph connectivity 比 metadata 好得多（31.7% vs 14%），但也受 campaign 影響。

**關鍵差異：Infrastructure reuse 程度因 APT 而異：**

| APT | Per-IoC Acc | Per-Report Acc | Δ | 解讀 |
|-----|------------|---------------|---|------|
| Lazarus_Group | 95.8% | 88.8% | -7.0% | 強 infrastructure reuse |
| Sandworm_Team | 97.7% | 88.3% | -9.4% | 強 |
| Gamaredon_Group | 99.8% | 84.3% | -15.5% | 中等 |
| Turla | 90.9% | 80.2% | -10.7% | 中等 |
| FIN7 | 89.3% | 75.4% | -14.0% | 中等 |
| APT28 | 92.3% | 59.2% | -33.1% | 弱 |
| APT29 | 93.4% | 45.3% | -48.1% | 極弱 |
| Kimsuky | 92.2% | 25.4% | -66.9% | 幾乎不 reuse |

完全無跨 campaign 連結的大型報告：
- Magic_Hound (ClearSky 2017)：527 IoCs，exclusive L1=1,776
- Wizard_Spider (FireEye 2020)：457 IoCs，exclusive L1=5,010
- Gamaredon_Group (Symantec)：218 IoCs，exclusive L1=637

**結論：Graph overlap 是目前最強的跨 campaign 歸因信號，但 coverage 不足（47.5%）且 accuracy 因 APT 而異。真實場景的 accuracy 介於 67%~94% 之間，取決於 IoC 是否來自全新 campaign。**

### 5.4 L2 是唯一正增量的線索

L2 在 GroupKFold 下提供 +3.3% 增量，暗示**攻擊拓撲模式**有微弱的跨 campaign 信號。具體來說：

- 邊類型分布：某些 APT 的攻擊模式偏好更多 `dropped_file` (stage 式攻擊) vs. 更多 `contacted_domain` (C2 通訊式)
- 鄰居類型比例：file-heavy vs. domain-heavy 的攻擊架構
- 這些是 APT 攻擊「形狀」的粗略特徵，比 metadata 穩定一些

---

## 6. 對本論文的啟示

### 6.1 這個發現本身就是貢獻

多數 APT attribution 論文使用 random/stratified split，**未驗證跨 campaign 泛化能力**。本研究通過 GroupKFold 實驗，首次系統性地量化了 campaign contamination 對 metadata-based 歸因的影響。

### 6.2 重新定位研究框架

```
原本的故事：
  "我們用 KG + VT metadata + overlap 做歸因，達到 80% F1"
  → 不成立，因為是 campaign memorization

更好的故事：
  1. 揭露問題：metadata-based 歸因在跨 campaign 場景下失效 (63.8% → 14%)
  2. Graph connectivity 驗證：infrastructure overlap 是最強信號
     - 同 campaign: 93.8% accuracy / 68.2% coverage
     - 跨 campaign: 66.7% accuracy / 47.5% coverage
     - 但因 APT 而異：Lazarus 88.8% vs Kimsuky 25.4%
  3. KG 的真正價值：APT infrastructure fingerprint database
     - 66K nodes 中 60K 是 L1（歷史 APT 基礎設施）
     - 新 IoC 透過 VT relationship 連到已知 infrastructure → 歸因
  4. Coverage gap (52.5%) 需要 TTP-level 特徵填補
     → NER pipeline 提取 campaign-invariant 特徵
```

### 6.3 TTP 特徵（NER Pipeline）的重要性被驗證

現有 NER pipeline 提取的 6 種實體（Tool, Way, Exp, Purp, Idus, Area）正好對應 campaign-invariant 層級：
- **Tool**：APT 慣用的工具（Mimikatz, Cobalt Strike...）→ 跨 campaign 重複使用
- **Way**：攻擊手法 → 對應 ATT&CK techniques
- **Exp**：利用的漏洞 → APT 偏好特定漏洞類型
- **Purp**：攻擊目的 → 與 APT 的 mission 一致
- **Idus/Area**：目標產業/地區 → APT 的戰略目標相對穩定

**如果 TTP 特徵在 GroupKFold 下能顯著提升 F1，那就是本論文最強的實驗結果。**

---

## 7. 可複現的實驗腳本

```bash
# L1-only GroupKFold vs StratifiedKFold
python3 scripts/eval_groupkfold_l1.py

# 全層消融 GroupKFold
python3 scripts/eval_groupkfold_ablation.py
```

結果存於：
- `scripts/results/eval_groupkfold_l1.json`
- `scripts/results/eval_groupkfold_ablation.json`

---

## 8. 結論

> **VT metadata 歸因的 63.8% F1 中，約 50% 來自 campaign-level memorization，而非 APT-level pattern recognition。**
>
> 這不是 feature engineering 的問題，而是 **feature semantics 的問題** — 基礎設施 metadata 本質上描述的是「這次 campaign 用了什麼」，而不是「這個 APT 是誰」。
>
> 真正的 APT 歸因需要 campaign-invariant 特徵：程式碼重用、行為序列、TTP 模式。
