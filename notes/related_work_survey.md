# APT Attribution Related Work Survey (2020-2025)

> Compiled 2026-04-06. Covers academic papers on APT attribution using TTP analysis, NLP/text mining on CTI reports, IoC-based approaches, knowledge graphs, and malware behavioral analysis.

---

## Table of Contents

1. [Survey / Review Papers](#1-survey--review-papers)
2. [TTP-Based Attribution](#2-ttp-based-attribution)
3. [NLP / Text Mining on CTI Reports](#3-nlp--text-mining-on-cti-reports)
4. [NER for CTI and Attribution](#4-ner-for-cti-and-attribution)
5. [Knowledge Graph Approaches](#5-knowledge-graph-approaches)
6. [Malware-Based Attribution (Behavioral / Binary)](#6-malware-based-attribution-behavioral--binary)
7. [Multi-Signal / Hybrid Approaches](#7-multi-signal--hybrid-approaches)
8. [Datasets](#8-datasets)
9. [Comparison Table](#9-comparison-table)
10. [Key Takeaways for Our Thesis](#10-key-takeaways-for-our-thesis)

---

## 1. Survey / Review Papers

### 1.1 Saha et al. — Comprehensive Survey of APT Attribution (2024/2025)

- **Title:** A Comprehensive Survey of Advanced Persistent Threat Attribution: Taxonomy, Methods, Challenges and Open Research Problems
- **Authors:** Aakanksha Saha et al.
- **Year:** 2024 (arXiv), 2025 (JISA journal version)
- **Venue:** arXiv:2409.11415 / Journal of Information Security and Applications (JISA), Vol. 92, 2025
- **URL:** https://arxiv.org/abs/2409.11415
- **Key Content:**
  - Comprehensive taxonomy of attribution artifacts: malware features, network infrastructure, TTPs, linguistic/cultural indicators
  - Classification of methods: classification-based (supervised ML), clustering-based (unsupervised), similarity-based (match against known profiles)
  - Reviews ~137 papers covering 2010-2024
  - Identifies open challenges: dataset scarcity, label noise, cross-campaign generalization, adversarial evasion
  - Feature categories: malware (opcode, API calls, PE headers, fuzzy hashes), network (C2 infrastructure, DNS), CTI text (NLP extraction), TTP vectors
- **Relevance:** Primary reference for positioning our work. Our campaign contamination finding directly addresses their identified "dataset bias" challenge.

### 1.2 SoK: Automated TTP Extraction from CTI Reports (2025)

- **Title:** SoK: Automated TTP Extraction from CTI Reports -- Are We There Yet?
- **Authors:** Marvin Buchel, Tommaso Paladini, Stefano Longari, Michele Carminati, Stefano Zanero, Hodaya Binyamini, Gal Engelberg, Dan Klein, Giancarlo Guizzardi, Marco Caselli, Andrea Continella, Maarten van Steen, Andreas Peter, Thijs van Ede
- **Year:** 2025
- **Venue:** USENIX Security 2025
- **URL:** https://www.usenix.org/conference/usenixsecurity25/presentation/buechel
- **Key Findings:**
  - Systematizes TTP extraction approaches and evaluates them in unified setting
  - **Traditional NLP outperforms modern embedder-based and generative approaches** in realistic settings
  - Identifies a performance ceiling that existing approaches cannot overcome
  - Inherent ambiguities in TTP ontologies (MITRE ATT&CK) limit extraction quality
  - Need for higher-quality datasets is the bottleneck
- **Relevance:** Validates our choice of NER-based extraction over LLM-based. Supports our finding that TTP features, while better than metadata, still face inherent limitations.

### 1.3 MITRE ATT&CK: State of the Art and Way Forward (2024)

- **Title:** MITRE ATT&CK: State of the Art and Way Forward
- **Year:** 2024
- **Venue:** ACM Computing Surveys
- **URL:** https://dl.acm.org/doi/10.1145/3687300
- **Key Content:** Comprehensive review of ATT&CK framework applications in detection, attribution, and threat assessment.

### 1.4 Expert Insights into APTs (2025)

- **Title:** Expert Insights into Advanced Persistent Threats: Analysis, Attribution, and Challenges
- **Authors:** Aakanksha Saha, Martina Lindorfer, James Mattei, Daniel Votipka, Jorge Blasco, Lorenzo Cavallaro
- **Year:** 2025
- **Venue:** USENIX Security 2025
- **URL:** https://www.usenix.org/conference/usenixsecurity25/presentation/saha
- **Method:** Semi-structured interviews with 15 security practitioners
- **Key Findings:**
  - Practitioners use a three-layer approach: campaign correlation, group attribution, nation-state linkage
  - **TTPs are considered more reliable than IoCs** for attribution, but harder to extract automatically
  - Experts emphasize infrastructure patterns and code reuse over individual indicators
  - Attribution confidence is inherently probabilistic, not binary
- **Relevance:** Strongly supports our multi-signal cascade design (graph overlap for infrastructure, TTP for behavior, metadata as fallback).

---

## 2. TTP-Based Attribution

### 2.1 Kim et al. — Vectorized ATT&CK Matrix (2021)

- **Title:** Automatically Attributing Mobile Threat Actors by Vectorized ATT&CK Matrix and Paired Indicator
- **Authors:** Kyoungmin Kim, Youngsup Shin, Justin Lee, Kyungho Lee
- **Year:** 2021
- **Venue:** Sensors, Vol. 21, No. 19
- **URL:** https://pmc.ncbi.nlm.nih.gov/articles/PMC8513093/
- **Method Category:** TTP analysis + IoC pairing
- **Data Source:** 120 mobile malware samples (88 public + 32 private)
- **Features:** 14 tactic vectors (binary technique presence), IoC pairs (domain registration, geolocation, malware type, victim geolocation)
- **Evaluation:** K-means clustering, precision/recall
- **Key Results:**
  - TTP only: Precision 0.8178, Recall 0.8970
  - TTP + IoC (N=2): **Precision 0.9148, Recall 0.9514**
- **APT Groups:** 12 mobile threat actors
- **Contributions:** First automated mobile-specific attribution; quantifies TTP similarity
- **Limitations:** Small sample (120 malware, 12 actors); mobile-only; requires labeled data

### 2.2 Guru et al. — LLM-Based TTP Attribution (2025)

- **Title:** On Technique Identification and Threat-Actor Attribution using LLMs and Embedding Models
- **Authors:** Kyla Guru, Robert J. Moss, Mykel J. Kochenderfer (Stanford University)
- **Year:** 2025
- **Venue:** arXiv:2505.11547
- **URL:** https://arxiv.org/abs/2505.11547
- **Method Category:** TTP extraction (LLM/embedding) + Bayesian inference
- **Data Source:** 727 documents from MITRE ATT&CK Groups pages + supplementary reports
- **Features:** MITRE ATT&CK techniques/sub-techniques extracted by GPT-4 or vector embedding search
- **Evaluation:** 10-fold CV, 70-20-10 split, ranking metric
- **Key Results:**
  - Random baseline: rank 15.0 (out of 29)
  - Best (HyDE + expert prior): **rank 7.55 +/- 0.21**
  - GPT-4 TTP extraction Jaccard similarity: 39% (vs human annotations)
  - Vector embedding Jaccard: 18%
- **APT Groups:** 29 well-documented actors (140 total examined)
- **Contributions:** First end-to-end pipeline from raw CTI to actor prediction; shows LLMs produce noisy but frequency-correlated TTPs
- **Limitations:** Low Jaccard scores; insufficient for autonomous decision-making; overlapping TTP profiles (e.g., Lazarus, menuPass)

### 2.3 APTer — APT Attribution Framework (2023)

- **Title:** APTer: Towards the Investigation of APT Attribution
- **Authors:** Sachidananda, Patil et al.
- **Year:** 2023
- **Venue:** IEEE Conference (ICCCSP area)
- **URL:** https://ieeexplore.ieee.org/document/10354155/
- **Method Category:** TTP correlation + prediction + attribution
- **Data Source:** Threat alerts from IDS/IPS, SIEM, firewall
- **Features:** TTPs extracted from heterogeneous alerts, mapped to MITRE ATT&CK and Cyber Kill Chain
- **Evaluation:** ML classification on TTP sets
- **Key Results:** Correlates multi-stage APT attacks, predicts next stages, attributes to known groups
- **Contributions:** First to combine alert correlation, stage prediction, and attribution in single framework
- **Limitations:** Requires structured alert data; specific accuracy numbers not widely reported

---

## 3. NLP / Text Mining on CTI Reports

### 3.1 Irshad & Siddiqui — Attack2vec (2022/2023)

- **Title:** Cyber threat attribution using unstructured reports in cyber threat intelligence
- **Authors:** Ehtsham Irshad, Muhammad Ahsan Siddiqui
- **Year:** 2022 (published 2023)
- **Venue:** Egyptian Informatics Journal, Vol. 24, No. 1, pp. 43-59
- **URL:** https://www.sciencedirect.com/science/article/pii/S111086652200069X
- **Method Category:** NLP + ML on CTI reports
- **Data Source:** Unstructured CTI reports from various public sources
- **Features:** Tactics, techniques, tools, malware, target information extracted via NLP; domain-specific embeddings ("Attack2vec")
- **Evaluation:** Standard ML classification metrics
- **Key Results:** **Accuracy 96%, Precision 96.4%, Recall 95.58%, F1 95.75%**
- **Contributions:** Domain-specific embedding model for CTI text
- **Limitations:** Number of APT groups not clearly reported; likely same-campaign contamination in evaluation (random split on report-derived features)

### 3.2 Naveen et al. — Deep Learning on Threat Reports (2020)

- **Title:** Deep Learning for Threat Actor Attribution from Threat Reports
- **Authors:** S. Naveen, Rami Puzis, Kumaresan Angappan
- **Year:** 2020
- **Venue:** 4th International Conference on Computer, Communication and Signal Processing (ICCCSP 2020), IEEE
- **URL:** https://ieeexplore.ieee.org/document/9315219/
- **Method Category:** Deep learning on CTI text
- **Data Source:** Threat intelligence reports (APT-focused)
- **Features:** Text features from threat reports (NLP-processed)
- **Evaluation:** Comparison with traditional ML methods
- **Key Results:** DL architecture outperforms traditional ML approaches for attribution
- **Contributions:** Early application of deep learning to CTI report-based attribution
- **Limitations:** Small dataset; specific accuracy/group numbers not widely available

### 3.3 Abdi et al. — Automated CTI Report Labeling (2023)

- **Title:** Automatically Labeling Cyber Threat Intelligence reports using Natural Language Processing
- **Authors:** Hamza Abdi, Steven Bagley, Steven Furnell, Jamie Twycross
- **Year:** 2023
- **Venue:** ACM Symposium on Document Engineering (DocEng '23)
- **URL:** https://dl.acm.org/doi/abs/10.1145/3573128.3609348
- **Method Category:** NLP (spaCy) for automated labeling
- **Data Source:** 605 English CTI reports from various internet sources
- **Features:** Custom NLP model (spaCy-based) extracts threat actor labels from report text
- **Evaluation:** Classification accuracy on labeled dataset
- **Key Results:** **97% accuracy** in identifying the attributed threat actor within a report
- **Contributions:** Fully automated APT report labeling pipeline; evaluates multiple PDF-to-text libraries
- **Limitations:** Report-level attribution (which actor does the report discuss), not IoC-level; limited to English

### 3.4 Boge et al. — Hybrid DL for Behavior-Based Attribution (2024)

- **Title:** Unveiling Cyber Threat Actors: A Hybrid Deep Learning Approach for Behavior-Based Attribution
- **Authors:** Emirhan Boge, Murat Bilgehan Ertan, Halit Alptekin, Orcun Cetin
- **Year:** 2024
- **Venue:** Digital Threats: Research and Practice (ACM)
- **URL:** https://dl.acm.org/doi/full/10.1145/3676284
- **Method Category:** Hybrid DL (Transformer + CNN) on command sequences
- **Data Source:** Cobalt Strike C2 command logs (Aug 2020 - Oct 2022)
- **Features:** Sequences of commands executed by threat actors; global (Transformer) + local (CNN) contextual features
- **Evaluation:** Train/test split with high/medium/low sample count datasets
- **Key Results:**
  - High-count: **F1 95.11%, Accuracy 95.13%**
  - Medium-count: F1 93.60%, Accuracy 93.77%
  - Low-count: F1 88.95%, Accuracy 89.25%
- **Contributions:** Novel hybrid architecture for behavioral fingerprinting; uses real operator command data
- **Limitations:** Limited to Cobalt Strike operators; may not generalize to actors using different C2 frameworks

---

## 4. NER for CTI and Attribution

### 4.1 AttackER Dataset (2024)

- **Title:** AttackER: Towards Enhancing Cyber-Attack Attribution with a Named Entity Recognition Dataset
- **Authors:** Pritam Deka, Sampath Rajapaksha, Ruby Rani, Amirah Almutairi, Erisa Karafili
- **Year:** 2024
- **Venue:** arXiv:2408.05149 / Springer LNCS 2024
- **URL:** https://arxiv.org/abs/2408.05149
- **Method Category:** NER dataset for attribution
- **Data Source:** 217 documents from Mandiant, Malwarebytes, MITRE, Securelist, Trendmicro
- **Features:** 18 entity types (Attack Pattern, Threat Actor, Malware, Infrastructure, Vulnerability, etc.)
- **Dataset Size:** 2,640 annotated sentences, 7,026 entity instances
- **Evaluation:** Multiple NER models tested
- **Key Results:**
  - spaCy SecureBERT: F1 0.6581
  - Fine-tuned GPT-3.5: **F1 0.8503** (adjusted ground truth)
  - Fine-tuned Llama-2: F1 0.7615
- **Contributions:** First NER dataset specifically designed for cyber-attack attribution; rich annotation with contextual details
- **Limitations:** 217 documents may be small; high variance across entity types

### 4.2 Wang et al. — Explainable APT Attribution via NLP (2021)

- **Title:** Explainable APT Attribution for Malware Using NLP Techniques
- **Authors:** Qinqin Wang, Hanbing Yan, Zhihui Han
- **Year:** 2021
- **Venue:** IEEE QRS 2021 (21st Int. Conf. on Software Quality, Reliability and Security)
- **URL:** https://ieeexplore.ieee.org/document/9724848/
- **Method Category:** NLP (paragraph vectors + BoW) + Random Forest + LIME explainability
- **Data Source:** Malware code features and string features from threat intelligence
- **Features:** Paragraph vectors (function semantics), bag-of-words vectors (behavior reports)
- **Evaluation:** Random Forest classification with LIME interpretation
- **Key Results:** Improved accuracy over baselines (exact numbers require paper access)
- **Contributions:** **First application of model interpretation (LIME) to APT attribution**; combines code and string features
- **Limitations:** Specific accuracy numbers not available from abstracts

---

## 5. Knowledge Graph Approaches

### 5.1 CSKG4APT (2022/2023)

- **Title:** CSKG4APT: A Cybersecurity Knowledge Graph for Advanced Persistent Threat Organization Attribution
- **Authors:** Ren et al.
- **Year:** 2022 (accepted), 2023 (published)
- **Venue:** IEEE Transactions on Knowledge and Data Engineering (TKDE), Vol. 35, No. 6, pp. 5695-
- **DOI:** 10.1109/TKDE.2022.3175719
- **URL:** https://ieeexplore.ieee.org/document/9834133/
- **Method Category:** Knowledge graph construction + attribution reasoning
- **Data Source:** Open-source CTI (OSCTI), real APT attack scenarios
- **Features:** KG ontology with APT entities (malware, tools, infrastructure, TTPs, CVEs)
- **Evaluation:** Attribution accuracy on real APT cases
- **Key Results:** Demonstrated effective attribution using KG reasoning
- **Contributions:** First dedicated APT KG model based on ontology theory; extraction algorithm using DL + expert knowledge; practical attribution with countermeasures
- **Limitations:** Requires expert involvement for KG construction; scalability concerns

### 5.2 AttacKG (2022)

- **Title:** AttacKG: Constructing Technique Knowledge Graph from Cyber Threat Intelligence Reports
- **Authors:** Zhenyuan Li, Jun Zeng et al.
- **Year:** 2022
- **Venue:** ESORICS 2022 (27th European Symposium on Research in Computer Security)
- **URL:** https://arxiv.org/abs/2111.07093
- **Method Category:** KG construction from CTI reports (NLP pipeline)
- **Data Source:** Real-world CTI reports from diverse sources
- **Features:** Attack behavior graphs enhanced into technique knowledge graphs (TKGs); entity/dependency/technique extraction
- **Evaluation:** F1 scores for entity, dependency, technique extraction
- **Key Results:**
  - Entity F1: 0.887
  - Dependency F1: 0.896
  - Technique F1: **0.789**
  - 28,262 attack techniques identified, 8,393 unique IoCs
- **Contributions:** Aggregates CTI across reports; constructs technique-level KGs; outperforms SOTA
- **Limitations:** Technique identification F1 (0.789) leaves room for improvement; focuses on extraction, not end-to-end attribution

### 5.3 APTMalKG / Fine-Grained to Refined (ICCS 2024)

- **Title:** From Fine-Grained to Refined: APT Malware Knowledge Graph Construction and Attribution Analysis Driven by Multi-stage Graph Computation
- **Year:** 2024
- **Venue:** ICCS 2024 (International Conference on Computational Science)
- **URL:** https://link.springer.com/chapter/10.1007/978-3-031-63749-0_6
- **Method Category:** KG + GraphSAGE with domain-specific meta-paths
- **Data Source:** APT malware sandbox reports + expanded intelligence
- **Features:** Static + dynamic malware features, TTPs, location data; multi-stage graph clustering
- **Evaluation:** Multi-class classification accuracy, F1, AUC
- **Key Results:** **Accuracy 91.16%, F1 89.82%, AUC 98.99%**
- **Contributions:** Domain-specific meta-paths integrated into GraphSAGE; progressive graph refinement reduces complexity
- **Limitations:** Specific number of APT groups not confirmed from abstract

### 5.4 AEKG4APT (2025)

- **Title:** AEKG4APT: An AI-Enhanced Knowledge Graph for Advanced Persistent Threats with Large Language Model Analysis
- **Year:** 2025
- **Venue:** ACM Transactions on Intelligent Systems and Technology (TIST)
- **URL:** https://dl.acm.org/doi/10.1145/3735645
- **Method Category:** KG + LLM
- **Data Source:** CTI + public sandboxes
- **Features:** LLM-extracted entities and relations for KG construction
- **Key Results:** LLM more efficient and accurate than traditional DL for CTI extraction
- **Contributions:** Combines LLMs with KG for APT intelligence; novel ontology schema

### 5.5 ThreatInsight (2024)

- **Title:** ThreatInsight: Innovating Early Threat Detection Through Threat-Intelligence-Driven Analysis and Attribution
- **Year:** 2024
- **Venue:** IEEE TKDE, Vol. 2024, No. 12
- **URL:** https://ieeexplore.ieee.org/document/10705917/
- **Method Category:** KG reasoning for threat attribution
- **Data Source:** HoneyPoint-captured IPs + APT Threat Intelligence KG (APT-TI-KG)
- **Features:** Threat data mining, threat feature modeling, fact-based + semantic reasoning
- **Contributions:** Real-time early-stage attribution using KG reasoning

### 5.6 APT Attribution via Heterogeneous GNN (2025)

- **Title:** APT Attribution Using Heterogeneous Graph Neural Networks with Contextual Threat Intelligence
- **Authors:** (Electronics, MDPI)
- **Year:** 2025
- **Venue:** Electronics, Vol. 14, No. 23, Article 4597
- **URL:** https://www.mdpi.com/2079-9292/14/23/4597
- **Method Category:** Heterogeneous GNN (GraphSAGE) + SBERT embeddings
- **Data Source:** APTNotes corpus
- **Features:** Tripartite graph (APT groups -- TTPs -- Cyber Kill Chain stages); TTP nodes embedded with Sentence-BERT
- **Evaluation:** Multi-class classification
- **Key Results:** **Macro-F1 0.84, Accuracy 85%**
- **Contributions:** Integrates procedural context (CKC stages) with semantic TTP embeddings; outperforms DeepOP and APT-MMF baselines
- **Limitations:** Relies on quality of TTP extraction from reports

---

## 6. Malware-Based Attribution (Behavioral / Binary)

### 6.1 Bon-APT (2024)

- **Title:** Bon-APT: Detection, Attribution, and Explainability of APT Malware Using Temporal Segmentation of API Calls
- **Authors:** Shenderovitz, Nissim
- **Year:** 2024
- **Venue:** Computers & Security, Vol. 142, Article 103862
- **URL:** https://www.sciencedirect.com/science/article/abs/pii/S0167404824001639
- **Method Category:** Dynamic analysis + temporal API call segmentation
- **Data Source:** **12,655 APT malware samples from 188 cyber-groups across 17 nations**
- **Features:** Timestamped API calls treated as multivariate time series; temporal segmentation representation
- **Evaluation:** Detection (APT vs benign), attribution (group-level + nation-level)
- **Key Results:** First comprehensive study for attribution to both nations and cyber-groups using temporal API segmentation
- **Contributions:** Largest APT sample collection (12,655 samples, 188 groups); novel temporal segmentation; explainability through API abstraction
- **Limitations:** Requires dynamic analysis (sandbox execution); evasion-aware malware may behave differently

### 6.2 Zhang et al. — Multi-Feature Fusion (2024)

- **Title:** Attribution classification method of APT malware based on multi-feature fusion
- **Authors:** Zhang, Liu et al.
- **Year:** 2024
- **Venue:** PLOS ONE
- **URL:** https://journals.plos.org/plosone/article?id=10.1371/journal.pone.0304066
- **Method Category:** GNN (event behavior graph) + ImageCNTM (opcode images) + fusion
- **Data Source:** APT malware samples (specific count requires paper access)
- **Features:** API instruction-based event behavior graphs (GNN); opcode image patterns (ImageCNTM); multi-feature fusion
- **Evaluation:** Precision, recall, F1
- **Key Results:** **Precision 93.65%, Recall 93.27%, F1 93.57%**
- **Contributions:** Novel combination of behavioral graph features and opcode image features
- **Limitations:** Requires both static and dynamic analysis

### 6.3 APT Attribution via Deep Reinforcement Learning (2024)

- **Title:** Advanced Persistent Threats (APT) Attribution Using Deep Reinforcement Learning
- **Year:** 2024
- **Venue:** Digital Threats: Research and Practice (ACM) / arXiv:2410.11463
- **URL:** https://arxiv.org/abs/2410.11463
- **Method Category:** Deep Reinforcement Learning on malware behavior
- **Data Source:** 3,500+ malware samples from 12 APT groups (Cuckoo Sandbox)
- **Features:** Behavioral data extracted from sandbox analysis
- **Evaluation:** Multi-class classification, comparison with DT/MLP/KNN
- **Key Results:**
  - DRL: **Accuracy 94.12%, Precision 94.22%, Recall 92.07%, F1 94.11%**
  - Decision Tree: 90.56%
  - MLP: 89.49%
  - KNN: 88.05%
- **APT Groups:** 12
- **Contributions:** First DRL application to APT attribution; outperforms traditional ML
- **Limitations:** Only 12 groups; sandbox-based (evasion risk)

### 6.4 Chen & Yan — TCN-GAN (2025)

- **Title:** Research on APT groups malware classification based on TCN-GAN
- **Authors:** Chen, Yan et al.
- **Year:** 2025
- **Venue:** PLOS ONE, Vol. 20, No. 6
- **URL:** https://journals.plos.org/plosone/article?id=10.1371/journal.pone.0323377
- **Method Category:** Temporal Convolutional Network + GAN for data augmentation
- **Data Source:** Public + self-constructed APT malware datasets
- **Features:** Image features + disassembled instruction N-gram features
- **Evaluation:** Classification accuracy/precision
- **Key Results:** **Accuracy 99.8%, Precision 99.8%**
- **Contributions:** GAN-based sample augmentation mitigates class imbalance; TCN captures sequential dependencies
- **Limitations:** 99.8% accuracy suggests possible overfitting or dataset leakage; validation methodology needs scrutiny

---

## 7. Multi-Signal / Hybrid Approaches

### 7.1 APT-MMF (2024)

- **Title:** APT-MMF: An advanced persistent threat actor attribution method based on multimodal and multilevel feature fusion
- **Authors:** Nan Xiao, Bo Lang, Ting Wang, Yikai Chen
- **Year:** 2024
- **Venue:** Computers & Security, Vol. 144, Article 103960
- **URL:** https://www.sciencedirect.com/science/article/abs/pii/S0167404824002657
- **Method Category:** Heterogeneous graph attention network on multimodal features
- **Data Source:** Multisource CTI reports + IoC information
- **Features:**
  - Attribute type features (from IoCs)
  - Natural language text features (from reports)
  - Topological relationship features (from heterogeneous attributed graph)
  - Multilevel attention: IoC type-level, metapath-based neighbor-level, metapath semantic-level
- **Evaluation:** Multi-class attribution classification
- **Key Results:** Reported as **83.2% accuracy** (per our earlier analysis; see `notes/project_aptmmf_comparison.md`)
- **Contributions:** First to fuse three modalities (attribute, text, topology) with multilevel attention for APT attribution
- **Limitations:** Evaluation methodology unclear re: cross-campaign validation; IoC-report graph construction requires specific data format

### 7.2 ADAPT (RAID 2024)

- **Title:** ADAPT it! Automating APT Campaign and Group Attribution by Leveraging and Linking Heterogeneous Files
- **Authors:** Aakanksha Saha et al.
- **Year:** 2024
- **Venue:** RAID 2024 (27th Int. Symposium on Research in Attacks, Intrusions and Defenses)
- **URL:** https://dl.acm.org/doi/10.1145/3678890.3678909
- **Method Category:** Two-level unsupervised clustering (campaign + group)
- **Data Source:** MITRE reference dataset + 6,134 APT samples from 92 threat groups
- **Features:** Heterogeneous file features (executables + documents); linking features across campaigns
- **Evaluation:** Clustering quality on two datasets
- **Key Results:** Highly effective clustering at both campaign and group levels
- **APT Groups:** 92
- **Contributions:** **Two-level attribution** (campaign then group); handles heterogeneous file types; largest evaluated group count (92); open-source (GitHub: SecPriv/adapt)
- **Limitations:** Unsupervised approach requires post-hoc labeling; exact precision/recall numbers require paper access

### 7.3 MLDSJ (2025)

- **Title:** MLDSJ: a multi-level feature joint attribution method for APT group based on threat intelligence
- **Year:** 2025
- **Venue:** Journal on Information Security (Springer)
- **URL:** https://link.springer.com/article/10.1186/s13635-025-00222-6
- **Method Category:** Multi-level feature fusion with Dempster-Shafer evidence theory
- **Data Source:** CTI reports
- **Features:** Three types: attack patterns, textual information, graph topology
- **Evaluation:** ML classification per feature type, then DS combination rule for final attribution
- **Key Results:** DS fusion outperforms single-feature approaches
- **Contributions:** Novel application of Dempster-Shafer theory for feature fusion in APT attribution
- **Limitations:** Exact accuracy numbers require paper access

### 7.4 APT-ATT (2025)

- **Title:** APT-ATT: An efficient APT attribution model based on heterogeneous threat intelligence representation and CTGAN
- **Year:** 2025
- **Venue:** Computer Networks (Elsevier)
- **URL:** https://www.sciencedirect.com/science/article/abs/pii/S1389128625004785
- **Method Category:** N-gram + TF-IDF + CTGAN augmentation + stacking ensemble
- **Data Source:** Two CTI datasets
- **Features:** N-gram + TF-IDF from heterogeneous threat intelligence; chi-square feature selection; CTGAN-generated synthetic samples for class balancing
- **Evaluation:** Multi-class classification
- **Key Results:** **Accuracy 94.91%**
- **Base Learners:** KNN, RF, XGBoost; Meta: Logistic Regression
- **Contributions:** Addresses class imbalance via CTGAN; lightweight stacking ensemble
- **Limitations:** TF-IDF on CTI text may capture campaign-specific rather than actor-specific signals

### 7.5 Irshad — Hybrid Technical and Behavioral Attribution (2025)

- **Title:** Hybrid-Technical and Behavioral Attack Attribution
- **Authors:** Ehtsham Irshad et al.
- **Year:** 2025
- **Venue:** Thesis/Report, CUST
- **URL:** https://cust.edu.pk/wp-content/uploads/2025/03/Ehtsham_Irshad_CS.pdf
- **Method Category:** Hybrid (technical IoC features + behavioral context features)
- **Data Source:** Thai CERT Threat Actor Encyclopedia + CTI reports
- **Features:** Technical features (TTPs, tools, targets) + behavioral features (attacker context, motivations, goals)
- **Contributions:** Demonstrates behavioral features improve attribution over technical-only

---

## 8. Datasets

### 8.1 APT-ClaritySet (2024/2025)

- **Title:** APT-ClaritySet: A Large-Scale, High-Fidelity Labeled Dataset for APT Malware with Alias Normalization and Graph-Based Deduplication
- **Year:** 2024 (arXiv December 2024)
- **URL:** https://arxiv.org/abs/2512.15039
- **Components:**
  - APT-ClaritySet-Full: 34,363 samples, 305 APT groups (2006-2025)
  - APT-ClaritySet-Unique: 25,923 unique samples, 303 groups (after dedup)
  - APT-ClaritySet-FuncReuse: 324,538 function-reuse clusters
- **File Types:** PE (51.6%), documents (24.6%), scripts (7%), mobile (7.7%), archives (4.7%)
- **Quality:** Group-label accuracy 96.43% at 95% confidence
- **Alias Normalization:** Reconciled ~11.22% inconsistent names
- **Graph Dedup:** Reduced statically analyzable executables by 47.55%

### 8.2 dAPTaset (2020)

- **Title:** dAPTaset: A Comprehensive Mapping of APT-Related Data
- **Authors:** Giuseppe Laurenza, Riccardo Lazzeretti
- **Year:** 2020
- **Venue:** Springer LNCS (Computer Security)
- **URL:** https://link.springer.com/chapter/10.1007/978-3-030-42051-2_15
- **Size:** 8,927 samples from 88 APT groups
- **Type:** Binary (PE) samples only

### 8.3 APTClass

- **Authors:** Gray et al.
- **Size:** 11,787 portable executables, 82 APT groups
- **Source:** Threat intelligence report-derived ground truth
- **URL:** GitHub (multiple versions)

### 8.4 Cyber Science Lab APT Malware Dataset

- **URL:** https://cybersciencelab.com/advanced-persistent-threat-apt-malware-dataset/
- **Size:** 3,500+ samples, labeled by APT group

---

## 9. Comparison Table

| Paper | Year | Venue | Method | #Groups | Accuracy/F1 | Eval Method | Cross-Campaign? |
|-------|------|-------|--------|---------|-------------|-------------|-----------------|
| Kim et al. | 2021 | Sensors | TTP vector + IoC | 12 | P:0.91/R:0.95 | K-means | No |
| Irshad & Siddiqui | 2022 | EIJ | NLP (Attack2vec) | ? | 96%/95.75% | ML classification | Unclear |
| Naveen et al. | 2020 | ICCCSP | DL on reports | ? | > baseline | Comparison | No |
| Abdi et al. | 2023 | DocEng | NLP (spaCy) | N/A | 97% | Report labeling | N/A (report-level) |
| Boge et al. | 2024 | DTRAP | Hybrid DL (Transformer+CNN) | ? | 95.11% | Train/test split | No (C2 commands) |
| AttacKG | 2022 | ESORICS | NLP -> TKG | N/A | F1:0.789 (technique) | Extraction eval | N/A (extraction) |
| CSKG4APT | 2023 | IEEE TKDE | KG + reasoning | ? | Effective | Case studies | Unclear |
| APTMalKG | 2024 | ICCS | KG + GraphSAGE | ? | 91.16%/89.82% | Classification | Unclear |
| Zhang et al. | 2024 | PLOS ONE | GNN + ImageCNTM | ? | 93.65%/93.57% | Classification | Unclear |
| DRL Attribution | 2024 | DTRAP | Deep RL | 12 | 94.12%/94.11% | Train/test | Unclear |
| Bon-APT | 2024 | C&S | Temporal API seg. | 188 | Comprehensive | Detection+Attribution | Unclear |
| APT-MMF | 2024 | C&S | Multimodal graph attention | ? | 83.2% | Classification | **No** |
| ADAPT | 2024 | RAID | Unsupervised clustering | 92 | Effective | Clustering metrics | **Yes (by design)** |
| Guru et al. | 2025 | arXiv | LLM + Bayesian | 29 | Rank 7.55/29 | 10-fold CV | Partial |
| GNN+SBERT | 2025 | Electronics | GraphSAGE + SBERT | ? | 85%/F1:0.84 | Classification | Unclear |
| APT-ATT | 2025 | Comp.Net. | TF-IDF + CTGAN + Stacking | ? | 94.91% | Classification | Unclear |
| TCN-GAN | 2025 | PLOS ONE | TCN + GAN augment | ? | 99.8% | Classification | **Unlikely** |
| **Ours** | **2026** | **Thesis** | **Graph overlap + TTP + metadata cascade** | **16** | **100%/25.5% (S1), 52.8%/98.5% (full)** | **Per-report LOO (GroupKFold)** | **Yes** |

---

## 10. Key Takeaways for Our Thesis

### Where We Fit in the Literature

1. **Campaign contamination gap:** Almost no paper explicitly validates cross-campaign generalization. Most use random train/test splits (StratifiedKFold equivalent), which we proved inflates results by 50%+. Only ADAPT explicitly addresses campaign-level separation, and SoK (USENIX 2025) identifies dataset quality as a bottleneck. Our GroupKFold analysis is a direct contribution.

2. **Multi-signal fusion is rare:** APT-MMF and MLDSJ fuse features, but at the feature level (concatenation or attention), not at the decision level. Our confidence-gated cascade (Graph -> TTP -> ML fallback) is architecturally distinct and produces interpretable confidence levels.

3. **Graph overlap for attribution is novel:** No existing paper uses VT-enriched IoC knowledge graph overlap as a deterministic attribution signal. CSKG4APT and APTMalKG use KGs but for ML-based reasoning, not direct neighbor matching. Our finding that clear-winner graph overlap is 100% precise is unique.

4. **TTP cross-campaign validation is new:** We are the first (to our knowledge) to explicitly measure TTP features under GroupKFold and show they provide 2.4x better cross-campaign performance than VT metadata features.

5. **Scale context:** Our KG (66K nodes, 109K edges, 21 APT groups) is moderate. Bon-APT uses 188 groups but only malware samples. APT-ClaritySet has 305 groups. ADAPT evaluates on 92 groups. Our differentiator is depth of analysis (VT enrichment, infrastructure discovery) rather than breadth.

### Papers to Cite in Thesis

**Must-cite (directly comparable or foundational):**
- Saha et al. 2024/2025 survey (taxonomy, defines the field)
- SoK USENIX 2025 (TTP extraction state of the art)
- Expert Insights USENIX 2025 (practitioner perspective)
- APT-MMF 2024 (closest comparable: multimodal attribution)
- ADAPT RAID 2024 (campaign-level separation)
- CSKG4APT 2023 (KG for APT)
- Bon-APT 2024 (largest scale malware attribution)
- Kim et al. 2021 (TTP vectorization)

**Should-cite (relevant methods):**
- AttacKG 2022 (TKG construction)
- AttackER 2024 (NER for attribution)
- Guru et al. 2025 (LLM-based TTP)
- Irshad & Siddiqui 2022 (NLP on CTI)
- Zhang et al. 2024 (multi-feature fusion)
- APTMalKG 2024 (KG + GraphSAGE)
- APT-ATT 2025 (CTGAN augmentation)
- Boge et al. 2024 (behavioral fingerprinting)

**Nice-to-cite (context):**
- MITRE ATT&CK survey 2024 (ACM CSUR)
- dAPTaset 2020, APT-ClaritySet 2024 (datasets)
- Wang et al. 2021 (explainability in attribution)
- TCN-GAN 2025 (data augmentation)
