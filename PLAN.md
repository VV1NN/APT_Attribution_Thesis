# APT Attribution & Attack Path Prediction — Implementation Plan

> Last updated: 2026-03-31
> Status: Planning

---

## 1. Current State (已完成)

### 1.1 KG Pipeline
- [x] IoC cleaning (`clean_iocs_v2.py`)
- [x] VT metadata enrichment (`build_knowledge_graph.py`)
- [x] VT relationship discovery (`fetch_vt_relationships.py`)
- [x] Per-org KG construction (16 orgs completed)
- [x] Master KG merge (`merge_knowledge_graphs.py`) → 66,444 nodes / 109,443 edges

### 1.2 Attribution System
- [x] Vocabulary building (`build_vocabularies.py`)
- [x] 4-layer feature extraction (`build_features.py`) → L1(88d) + L2(35d) + L3(7+Kd) + L4(64d)
- [x] Node2Vec training (`train_node2vec.py`)
- [x] XGBoost classifier training + 5-fold CV (`eval_allnodes_correct_cv.py`)
- [x] SHAP analysis (`run_shap_analysis.py`)
- [x] Inference pipeline (`inference.py`)

### 1.3 Current Results (15 orgs, no TTP)
- Micro-F1: 80.0% (no threshold)
- Micro-F1: 95.7% (confidence threshold 0.3)
- Coverage at threshold 0.3: 81.1%

### 1.4 Data Assets
- 16 orgs with completed KGs
- 203 CTI reports in `org_iocs/{org}/sources/*.txt`
- Each IoC has `sources` field → traceable to specific reports

---

## 2. Organization Selection (待確認)

### 2.1 Keep (16 orgs with valid KG)
Remove 5 unusable orgs (APT12, APT16, APT17, APT18, APT19 — too few IoCs/nodes).

| Region | Orgs | Status |
|--------|------|--------|
| Russia (6) | APT28, APT29, Sandworm_Team, Turla, Gamaredon_Group, Wizard_Spider | KG done |
| North Korea (2) | Lazarus_Group, Kimsuky | KG done |
| Iran (3) | Magic_Hound, MuddyWater, OilRig | KG done |
| Vietnam (1) | APT32 | KG done |
| Middle East (1) | APT-C-23 | KG done |
| Latin America (1) | APT-C-36 | KG done (考慮移除，IoC 僅 141) |
| China (1) | APT1 | KG done |
| Cybercrime (1) | FIN7 | KG done |

### 2.2 Potential additions (需跑完整 pipeline)
- Transparent_Tribe (South Asia) — VT relationships done, KG building interrupted, 待續建
- 其他候選: CopyKittens, Patchwork, PROMETHIUM — 需從零跑 pipeline

### 2.3 Decision needed
- 最終用 16 orgs? 還是等 Transparent_Tribe 完成後 17 orgs?
- 是否移除 APT-C-36 (141 cleaned IoCs, 1 report)?

---

## 3. Phase 1: TTP Context Extraction

### 3.1 Goal
從 203 份 CTI 報告中抽取 TTP 相關實體，建立 IoC → Report → TTP 的對應關係。

### 3.2 Sub-task 1A: NER-BERT-CRF Setup

**Source:** https://github.com/stwater20/NER-BERT-CRF-for-CTI

**Steps:**
1. Clone repo, set up Python environment (需 PyTorch + transformers)
2. Download pre-trained model checkpoint (`ner_bert_crf_checkpoint.pt`)
3. Test inference on one report
4. Write batch inference script: `scripts/run_ner_on_reports.py`

**Input:** `org_iocs/{org}/sources/*.txt` (203 files, 5.3 MB)

**Output:** `scripts/ttp_extraction/{org}/{report_hash}.json`
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

**Relevant entity types (6 of 13):**
| Entity | Use for | Example |
|--------|---------|---------|
| Tool | L5 feature + attack path | X-Agent, Mimikatz |
| Way | L5 feature + attack path | spearphishing, watering hole |
| Exp | L5 feature + attack path | CVE-2017-0262 |
| Purp | L5 feature | espionage, data theft |
| Idus | L5 feature | financial, defense |
| Area | L5 feature | Ukraine, Middle East |

**Ignore:** HackOrg (label leakage), SecTeam, Org, OffAct, SamFile, Features, Time

### 3.3 Sub-task 1B: TRAM Mapping (Optional Enhancement)

**Source:** https://github.com/center-for-threat-informed-defense/tram/

**Steps:**
1. Install TRAM
2. Run on 203 reports → ATT&CK Technique IDs per sentence
3. Filter: only keep results with 100% confidence (APT-MMF 也這樣做)
4. Merge with NER results

**Output:** Additional field in the per-report JSON:
```json
{
  "techniques_tram": [
    {"id": "T1566.001", "name": "Spearphishing Attachment", "confidence": 1.0},
    {"id": "T1203", "name": "Exploitation for Client Execution", "confidence": 1.0}
  ]
}
```

**Note:** TRAM 是 optional 的。NER-BERT-CRF 已經能抽取 Tool/Way/Exp，TRAM 只是補充標準化的 Technique ID。如果時間不夠可以跳過。

### 3.4 Sub-task 1C: Entity Normalization

NER 會抽出不同寫法的同一個 entity：
```
"X-Agent", "XAgent", "Sofacy backdoor", "SPLM" → 同一個工具
"spear phishing", "spearphishing", "spear-phishing" → 同一個手法
```

**Steps:**
1. 收集所有 NER 抽出的 raw entities
2. 建立 alias mapping table（手動 + 自動）
   - Tool: 用 MITRE ATT&CK Software 名單做 fuzzy matching
   - Exp: CVE 格式統一（regex 標準化）
   - Way: 建立同義詞表（~50 個常見攻擊手法）
3. 輸出 normalized vocabulary: `scripts/ttp_vocabularies.json`

```json
{
  "tool_vocab": {"X-Agent": 0, "Zebrocy": 1, "Mimikatz": 2, ...},
  "way_vocab": {"spearphishing": 0, "watering_hole": 1, ...},
  "exp_vocab": {"CVE-2017-0262": 0, "CVE-2017-0263": 1, ...},
  "purp_vocab": {"espionage": 0, "financial_theft": 1, ...},
  "idus_vocab": {"government": 0, "military": 1, "financial": 2, ...},
  "area_vocab": {"ukraine": 0, "middle_east": 1, ...}
}
```

### 3.5 Sub-task 1D: IoC → Report → TTP Mapping

**Core logic:**
```
For each IoC in cleaned IoCs:
  1. Read its "sources" field → list of report URLs
  2. Match URL to report file in sources/*.txt
  3. Look up that report's NER results
  4. Aggregate TTP entities across all source reports for this IoC
```

**Script:** `scripts/build_ioc_ttp_mapping.py`

**Output:** `scripts/ttp_extraction/ioc_ttp_mapping.json`
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

**Challenge:** 有些 IoC 的 sources URL 可能對不上 sources/*.txt 的檔名。
需要寫 URL → filename 的 matching logic。

---

## 4. Phase 2: L5 TTP Feature Engineering

### 4.1 Goal
將每個 IoC 的 TTP context 轉成數值特徵向量，作為 L5 加入訓練。

### 4.2 Feature Design: TF-IDF Weighted Multi-hot

**Script:** `scripts/build_ttp_features.py`

**For each IoC, compute:**

```
Tool features (N_tool dimensions):
  For each tool in tool_vocab:
    if tool in this IoC's tools:
      value = TF-IDF weight
    else:
      value = 0

  TF = count of this tool in this IoC's source reports
  IDF = log(total_reports / reports_containing_this_tool)

Same for: Way, Exp, Purp, Idus, Area
```

**Dimension estimate:**
| Category | Estimated vocab size | Notes |
|----------|---------------------|-------|
| Tool | ~30-50 | After normalization |
| Way | ~15-20 | Common attack methods |
| Exp | ~20-30 | CVEs mentioned |
| Purp | ~5-8 | espionage, financial, sabotage, ... |
| Idus | ~8-12 | government, military, financial, ... |
| Area | ~10-15 | Regions/countries |
| **Total** | **~88-135d** | |

**Dimensionality reduction (if too high):**
- Option A: Only keep top-K features by IDF score
- Option B: PCA to reduce to fixed ~80d
- Option C: Only use Tool + Way + Exp (skip Purp/Idus/Area) → ~65-100d

### 4.3 Handling missing TTP

IoCs without source reports (or reports that NER failed on) will have all-zero L5 features.
This is fine — XGBoost handles sparse features naturally.

**Expected coverage:**
- IoCs from CTI reports: have sources → have TTP features
- L1 VT-discovered nodes: no sources → all-zero TTP features
- Training is on L0 IoCs only → most should have sources

### 4.4 Integration into Training Pipeline

Modify `scripts/build_features.py`:
```python
# After L4 (Node2Vec), add:
# L5: TTP Context features
ttp_mapping = load_ttp_mapping()
ttp_vocab = load_ttp_vocab()

for each L0 IoC:
    ttp = ttp_mapping.get(ioc_id, {})
    l5_features = compute_tfidf_vector(ttp, ttp_vocab)
    features[ioc_id] = concat(l1, l2, l3, l4, l5_features)
```

Modify `scripts/train_classifier.py`:
- Accept new feature dimension
- Add L5 feature names for SHAP analysis

---

## 5. Phase 3: Attack Path Prediction

### 5.1 Goal
Given an attributed IoC, predict the next likely attack technique based on the APT group's historical TTP patterns.

### 5.2 Sub-task 3A: Build TTP Sequence Database

**Script:** `scripts/build_ttp_sequences.py`

**For each report:**
1. Extract all TTP entities with their text positions
2. Map each entity to ATT&CK kill chain phase:
   ```
   Reconnaissance → Resource Development → Initial Access → Execution
   → Persistence → Privilege Escalation → Defense Evasion → Credential Access
   → Discovery → Lateral Movement → Collection → C2 → Exfiltration → Impact
   ```
3. Sort by kill chain phase (NOT by text position — text order is unreliable)
4. Record the sequence: `[phase1_techniques, phase2_techniques, ...]`

**Output:** `scripts/ttp_extraction/ttp_sequences.json`
```json
{
  "APT28": {
    "sequences": [
      {
        "report": "securelist_sofacy_2017",
        "sequence": [
          {"phase": "Initial Access", "techniques": ["spearphishing", "Flash_exploit"]},
          {"phase": "Execution", "techniques": ["CVE-2017-0262"]},
          {"phase": "Persistence", "techniques": ["X-Agent_backdoor"]},
          {"phase": "Collection", "techniques": ["keylogger", "filestealer"]},
          {"phase": "C2", "techniques": ["encrypted_HTTPS"]},
          {"phase": "Exfiltration", "techniques": ["exfiltration_over_C2"]}
        ]
      },
      ...
    ],
    "transition_model": {
      "Initial Access → Execution": {"count": 20, "total": 25, "prob": 0.80},
      "Execution → Persistence": {"count": 18, "total": 25, "prob": 0.72},
      ...
    }
  }
}
```

### 5.3 Sub-task 3B: TTP Transition Model

**For each APT group:**
1. Aggregate all report sequences
2. Count transitions between kill chain phases
3. Compute transition probability: `P(phase_j | phase_i) = count(i→j) / count(i)`
4. Store as a transition matrix (14x14, one per APT)

**Mapping NER entities to kill chain phases:**
```python
PHASE_MAP = {
    # Tool → based on tool's primary function
    "X-Agent": "Persistence",       # backdoor
    "Mimikatz": "Credential Access", # credential dumping
    "Cobalt Strike": "C2",          # C2 framework

    # Way → direct mapping
    "spearphishing": "Initial Access",
    "watering_hole": "Initial Access",
    "DLL_sideloading": "Defense Evasion",
    "template_injection": "Execution",

    # Exp → typically Execution or Initial Access
    "CVE-*": "Execution",  # default for exploits
}
```

### 5.4 Sub-task 3C: Prediction Pipeline

**Script:** Extend `scripts/inference.py`

```
Input: IoC (hash, domain, or IP)

Step 1 (existing): Attribution
  → "This IoC belongs to APT28 (confidence: 95%)"

Step 2 (new): Current Phase Identification
  → Look up IoC's TTP context from its source reports
  → Map to kill chain phase
  → "Current phase: Initial Access (spearphishing detected)"

Step 3 (new): Next Step Prediction
  → Look up APT28's transition model
  → "After Initial Access, APT28 historically proceeds to:"
  →   "1. Execution (80%) — likely via exploit or macro"
  →   "2. Persistence (65%) — likely deploying X-Agent/Zebrocy"

Step 4 (new): Defense Recommendations
  → Map predicted techniques to MITRE ATT&CK mitigations
  → "Recommended defenses:"
  →   "- Block Office macros from internet-sourced documents"
  →   "- Monitor for known X-Agent/Zebrocy indicators"
  →   "- Enable exploit protection in endpoint security"
```

---

## 6. Phase 4: Evaluation

### 6.1 Attribution Ablation Study

| Experiment | Features | Expected Result |
|------------|----------|-----------------|
| Baseline | L1+L2+L3+L4 | Micro-F1 ≈ 80% (current) |
| +TTP (Method A) | L1+L2+L3+L4+L5 | Micro-F1 ≈ ?% |
| Full | L1+L2+L3+L4+L5 | With confidence threshold |

Run 5-fold CV for each configuration using `eval_allnodes_correct_cv.py`.

### 6.2 TTP Feature Analysis

- SHAP analysis: which TTP features contribute most?
- Per-entity-type ablation: Tool only vs Way only vs Exp only vs all
- Per-org analysis: which orgs benefit most from TTP features?

### 6.3 Attack Path Prediction Evaluation

**Method: Leave-One-Report-Out**
1. For each APT group, hold out one report
2. Build transition model from remaining reports
3. Predict the held-out report's TTP sequence
4. Compare predicted next-phase with actual next-phase
5. Metric: Top-1 accuracy, Top-3 accuracy of phase prediction

### 6.4 Comparison with APT-MMF

| Aspect | APT-MMF | Ours |
|--------|---------|------|
| Attribution unit | Report | IoC |
| Features | Attr(64d)+BERT(64d)+N2V(128d) | L1-L4(194d)+L5 TTP(~80d) |
| Model | Multilevel HetGAT | XGBoost |
| Attack path prediction | No | Yes |
| Micro-F1 | 83.21% | ?% |
| Confidence mechanism | No | Yes (threshold) |
| Explainability | Attention weights | SHAP values |

---

## 7. Implementation Order (Recommended)

### Week 1: TTP Extraction
- [ ] Set up NER-BERT-CRF environment
- [ ] Write batch inference script (`run_ner_on_reports.py`)
- [ ] Run NER on 203 reports
- [ ] Entity normalization → `ttp_vocabularies.json`
- [ ] Build IoC → Report → TTP mapping

### Week 2: L5 Features + Retrain
- [ ] Implement `build_ttp_features.py` (TF-IDF multi-hot)
- [ ] Integrate L5 into `build_features.py`
- [ ] Retrain XGBoost with L1+L2+L3+L4+L5
- [ ] Run ablation study (Baseline vs +L5)
- [ ] SHAP analysis on TTP features

### Week 3: Attack Path Prediction
- [ ] Build TTP sequence database from reports
- [ ] Implement TTP transition model per APT
- [ ] Extend `inference.py` with path prediction
- [ ] Leave-one-report-out evaluation
- [ ] Defense recommendation mapping

### Week 4: Evaluation + Writing
- [ ] Complete all ablation experiments
- [ ] Comparison table with APT-MMF
- [ ] Write thesis Chapter 3 (Method) and Chapter 4 (Experiments)
- [ ] Generate architecture diagrams for thesis

### Ongoing: KG Expansion (parallel, depends on VT API quota)
- [ ] Complete Transparent_Tribe KG (resume with `--skip-query`)
- [ ] Decide on additional orgs
- [ ] Rebuild master KG if orgs change

---

## 8. File Structure (New Files)

```
scripts/
  ttp_extraction/
    run_ner_on_reports.py         # Batch NER inference on 203 reports
    run_tram_on_reports.py        # (Optional) TRAM mapping
    normalize_entities.py         # Entity dedup + alias mapping
    build_ioc_ttp_mapping.py      # IoC → Report → TTP mapping
    build_ttp_sequences.py        # TTP sequence extraction per report
    ttp_vocabularies.json         # Normalized entity vocabularies
    ioc_ttp_mapping.json          # Final IoC-level TTP mapping
    ttp_sequences.json            # Per-APT TTP transition data
    {org}/                        # Per-report NER results
      {report_hash}.json
  build_ttp_features.py           # L5 TTP feature extraction
  eval_with_ttp.py                # Ablation: baseline vs +TTP
  predict_attack_path.py          # Attack path prediction logic

NER-BERT-CRF-for-CTI/            # Cloned NER model repo (git submodule or separate)
```

---

## 9. Risk Assessment

| Risk | Impact | Mitigation |
|------|--------|------------|
| NER accuracy too low on our reports | L5 features noisy | Use keyword baseline as fallback |
| Too few reports per org (APT-C-36: 1 report) | TTP features empty for some orgs | Accept or remove org |
| TTP transition model unreliable (small sample) | Path prediction inaccurate | Frame as "preliminary" in thesis |
| VT API quota blocks KG expansion | Can't add new orgs | Focus on existing 16 orgs |
| L5 features don't improve F1 | Main contribution weakened | Emphasize attack path prediction as contribution |
| NER-BERT-CRF env setup issues | Blocked on TTP extraction | Fall back to keyword+regex extraction |

---

## 10. Thesis Story

> **Title (draft):** APT Attribution and Attack Path Prediction via VT-Enriched IoC Knowledge Graph with TTP Context Features
>
> **Core argument:**
> Existing APT attribution methods either operate at the report level (APT-MMF) or use only technical indicators (malware-based methods). We propose a system that:
> 1. Operates at the **IoC level** — directly attributing individual indicators, matching real-world SOC workflows
> 2. Combines **technical features** (VT metadata, graph topology) with **attack context features** (TTP entities from CTI reports)
> 3. Goes beyond attribution to **predict the next attack step**, providing actionable defense recommendations
>
> **Four contributions:**
> - C1: VT-enriched two-layer IoC Knowledge Graph construction method
> - C2: TTP context feature extraction via IoC-Report traceability
> - C3: Multi-layer feature fusion (technical + contextual + topological) for IoC-level attribution
> - C4: Attack path prediction framework based on per-APT TTP transition models
