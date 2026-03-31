#!/usr/bin/env python3
"""
批次 NER 推論 — 對所有 CTI 報告執行 NER-BERT-CRF，提取 TTP 相關實體。

用法：
    uv run python scripts/ttp_extraction/run_ner_on_reports.py
    uv run python scripts/ttp_extraction/run_ner_on_reports.py --org APT28
    uv run python scripts/ttp_extraction/run_ner_on_reports.py --dry-run

輸出：scripts/ttp_extraction/{org}/{report_hash}.json
"""

import argparse
import json
import logging
import os
import re
import sys
import time
from collections import defaultdict
from pathlib import Path

import torch
import torch.nn as nn
from transformers import BertModel, AutoTokenizer

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

# ════════════════════════════════════════════════════════════
# Config
# ════════════════════════════════════════════════════════════

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
NER_MODEL_DIR = PROJECT_ROOT / "NER-BERT-CRF-for-CTI"
CHECKPOINT_PATH = NER_MODEL_DIR / "outputs" / "ner_bert_crf_checkpoint.pt"
ORG_IOCS_DIR = PROJECT_ROOT / "org_iocs"
OUTPUT_DIR = Path(__file__).resolve().parent  # scripts/ttp_extraction/

# 我們要提取的 6 種實體
KEEP_ENTITIES = {"Tool", "Way", "Exp", "Purp", "Idus", "Area"}
# 忽略的實體（label leakage 或無用）
IGNORE_ENTITIES = {"HackOrg", "SecTeam", "Org", "OffAct", "SamFile", "Features", "Time"}

# 有效的 KG 組織
VALID_ORGS = [
    "APT-C-23", "APT-C-36", "APT1", "APT28", "APT29", "APT32",
    "FIN7", "Gamaredon_Group", "Kimsuky", "Lazarus_Group",
    "Magic_Hound", "MuddyWater", "OilRig", "Sandworm_Team",
    "Turla", "Wizard_Spider", "Transparent_Tribe",
]

MAX_SEQ_LENGTH = 512
BERT_MODEL_SCALE = "bert-base-cased"

# Label definitions (must match training)
LABEL_LIST = [
    'X', '[CLS]', '[SEP]', 'O',
    'B-Area', 'B-Exp', 'B-Features', 'B-HackOrg', 'B-Idus', 'B-OffAct',
    'B-Org', 'B-Purp', 'B-SamFile', 'B-SecTeam', 'B-Time', 'B-Tool', 'B-Way',
    'I-Area', 'I-Exp', 'I-Features', 'I-HackOrg', 'I-Idus', 'I-OffAct',
    'I-Org', 'I-Purp', 'I-SamFile', 'I-SecTeam', 'I-Time', 'I-Tool', 'I-Way',
]
LABEL_MAP = {label: i for i, label in enumerate(LABEL_LIST)}


# ════════════════════════════════════════════════════════════
# Model (copied from predict.py with minimal changes)
# ════════════════════════════════════════════════════════════

class BERT_CRF_NER(nn.Module):
    def __init__(self, bert_model, start_label_id, stop_label_id, num_labels, device):
        super().__init__()
        self.hidden_size = 768
        self.start_label_id = start_label_id
        self.stop_label_id = stop_label_id
        self.num_labels = num_labels
        self.device = device
        self.bert = bert_model
        self.dropout = nn.Dropout(0.2)
        self.hidden2label = nn.Linear(self.hidden_size, self.num_labels)
        self.transitions = nn.Parameter(torch.randn(self.num_labels, self.num_labels))
        self.transitions.data[start_label_id, :] = -10000
        self.transitions.data[:, stop_label_id] = -10000
        nn.init.xavier_uniform_(self.hidden2label.weight)
        nn.init.constant_(self.hidden2label.bias, 0.0)

    def _get_bert_features(self, input_ids, segment_ids, input_mask):
        bert_out, _ = self.bert(
            input_ids, token_type_ids=segment_ids,
            attention_mask=input_mask, return_dict=False
        )
        bert_out = self.dropout(bert_out)
        return self.hidden2label(bert_out)

    def _viterbi_decode(self, feats):
        import numpy as np
        T = feats.shape[1]
        batch_size = feats.shape[0]
        log_delta = torch.Tensor(batch_size, 1, self.num_labels).fill_(-10000.).to(self.device)
        log_delta[:, 0, self.start_label_id] = 0
        psi = torch.zeros((batch_size, T, self.num_labels), dtype=torch.long).to(self.device)
        for t in range(1, T):
            log_delta, psi[:, t] = torch.max(self.transitions + log_delta, -1)
            log_delta = (log_delta + feats[:, t]).unsqueeze(1)
        path = torch.zeros((batch_size, T), dtype=torch.long).to(self.device)
        _, path[:, -1] = torch.max(log_delta.squeeze(), -1)
        for t in range(T - 2, -1, -1):
            path[:, t] = psi[:, t + 1].gather(-1, path[:, t + 1].view(-1, 1)).squeeze()
        return path

    def forward(self, input_ids, segment_ids, input_mask):
        bert_feats = self._get_bert_features(input_ids, segment_ids, input_mask)
        label_seq_ids = self._viterbi_decode(bert_feats)
        return label_seq_ids


# ════════════════════════════════════════════════════════════
# NER inference
# ════════════════════════════════════════════════════════════

def load_model(device):
    """載入 BERT-CRF 模型。"""
    logger.info(f"Loading BERT model ({BERT_MODEL_SCALE})...")
    tokenizer = AutoTokenizer.from_pretrained(BERT_MODEL_SCALE, do_lower_case=True)

    bert_model = BertModel.from_pretrained(BERT_MODEL_SCALE)
    start_label_id = LABEL_MAP["[CLS]"]
    stop_label_id = LABEL_MAP["[SEP]"]

    model = BERT_CRF_NER(bert_model, start_label_id, stop_label_id, len(LABEL_LIST), device)

    logger.info(f"Loading checkpoint from {CHECKPOINT_PATH}...")
    checkpoint = torch.load(CHECKPOINT_PATH, map_location="cpu", weights_only=False)
    pretrained_dict = checkpoint["model_state"]
    net_state_dict = model.state_dict()
    pretrained_dict_selected = {k: v for k, v in pretrained_dict.items() if k in net_state_dict}
    net_state_dict.update(pretrained_dict_selected)
    model.load_state_dict(net_state_dict)

    logger.info(f"  Checkpoint epoch={checkpoint['epoch']}, "
                f"valid_acc={checkpoint['valid_acc']:.4f}, "
                f"valid_f1={checkpoint['valid_f1']:.4f}")

    model.to(device)
    model.eval()
    return model, tokenizer


def tokenize_and_predict(model, tokenizer, words, device):
    """對一個 word list 做 NER 預測，回傳 label list。"""
    tokens = ["[CLS]"]
    predict_mask = [0]
    word_map = []  # maps token index -> word index

    for i, w in enumerate(words):
        sub_words = tokenizer.tokenize(w)
        if not sub_words:
            sub_words = ["[UNK]"]
        for j, sw in enumerate(sub_words):
            tokens.append(sw)
            predict_mask.append(1 if j == 0 else 0)
            word_map.append(i)

    # Truncate
    if len(tokens) > MAX_SEQ_LENGTH - 1:
        tokens = tokens[:MAX_SEQ_LENGTH - 1]
        predict_mask = predict_mask[:MAX_SEQ_LENGTH - 1]

    tokens.append("[SEP]")
    predict_mask.append(0)

    input_ids = tokenizer.convert_tokens_to_ids(tokens)
    segment_ids = [0] * len(input_ids)
    input_mask = [1] * len(input_ids)

    # Pad
    pad_len = MAX_SEQ_LENGTH - len(input_ids)
    input_ids += [0] * pad_len
    input_mask += [0] * pad_len
    segment_ids += [0] * pad_len
    predict_mask += [0] * pad_len

    input_ids_t = torch.LongTensor([input_ids]).to(device)
    input_mask_t = torch.LongTensor([input_mask]).to(device)
    segment_ids_t = torch.LongTensor([segment_ids]).to(device)
    predict_mask_np = [predict_mask]

    with torch.no_grad():
        label_seq_ids = model(input_ids_t, segment_ids_t, input_mask_t)

    predicted = label_seq_ids[0].cpu().numpy()
    mask = predict_mask[:len(predicted)]

    # Extract labels for original words only
    labels = []
    for idx, m in enumerate(mask):
        if m == 1:
            labels.append(LABEL_LIST[predicted[idx]])

    return labels


def extract_entities_from_labels(words, labels):
    """從 BIO labels 中提取實體。"""
    entities = defaultdict(list)
    current_entity = None
    current_words = []

    for word, label in zip(words, labels):
        if label.startswith("B-"):
            # Save previous entity
            if current_entity and current_entity in KEEP_ENTITIES:
                entity_text = " ".join(current_words)
                if entity_text not in entities[current_entity]:
                    entities[current_entity].append(entity_text)
            # Start new
            current_entity = label[2:]
            current_words = [word]
        elif label.startswith("I-") and current_entity == label[2:]:
            current_words.append(word)
        else:
            # Save and reset
            if current_entity and current_entity in KEEP_ENTITIES:
                entity_text = " ".join(current_words)
                if entity_text not in entities[current_entity]:
                    entities[current_entity].append(entity_text)
            current_entity = None
            current_words = []

    # Last entity
    if current_entity and current_entity in KEEP_ENTITIES:
        entity_text = " ".join(current_words)
        if entity_text not in entities[current_entity]:
            entities[current_entity].append(entity_text)

    return dict(entities)


def process_report(model, tokenizer, report_text, device):
    """處理一份報告，回傳所有提取的實體。"""
    # Split into sentences (rough split by period/newline)
    sentences = re.split(r'(?<=[.!?])\s+|\n+', report_text)

    all_entities = defaultdict(list)

    for sent in sentences:
        sent = sent.strip()
        if len(sent) < 10:
            continue

        words = sent.split()
        if len(words) < 3:
            continue

        # Truncate very long sentences
        if len(words) > 400:
            words = words[:400]

        try:
            labels = tokenize_and_predict(model, tokenizer, words, device)
            # labels might be shorter than words due to truncation
            min_len = min(len(words), len(labels))
            entities = extract_entities_from_labels(words[:min_len], labels[:min_len])

            for etype, elist in entities.items():
                for e in elist:
                    if e not in all_entities[etype]:
                        all_entities[etype].append(e)
        except Exception as ex:
            # Skip problematic sentences
            continue

    return dict(all_entities)


# ════════════════════════════════════════════════════════════
# Main
# ════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="批次 NER 推論")
    parser.add_argument("--org", help="只處理指定組織")
    parser.add_argument("--dry-run", action="store_true", help="只列出要處理的報告")
    args = parser.parse_args()

    device = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")
    logger.info(f"Device: {device}")

    # Collect reports
    orgs_to_process = [args.org] if args.org else VALID_ORGS
    reports = []  # (org, report_path)
    for org in orgs_to_process:
        src_dir = ORG_IOCS_DIR / org / "sources"
        if not src_dir.exists():
            continue
        for f in sorted(src_dir.glob("*.txt")):
            reports.append((org, f))

    logger.info(f"Found {len(reports)} reports across {len(orgs_to_process)} orgs")

    if args.dry_run:
        for org, rpath in reports:
            print(f"  {org:<25} {rpath.name}")
        return

    # Load model
    model, tokenizer = load_model(device)

    # Process reports
    total_entities = 0
    start_time = time.time()

    for idx, (org, report_path) in enumerate(reports):
        out_dir = OUTPUT_DIR / org
        out_dir.mkdir(parents=True, exist_ok=True)
        out_file = out_dir / f"{report_path.stem}.json"

        # Skip if already processed
        if out_file.exists():
            logger.info(f"[{idx+1}/{len(reports)}] {org}/{report_path.name} — already done, skipping")
            continue

        logger.info(f"[{idx+1}/{len(reports)}] {org}/{report_path.name}")

        try:
            with open(report_path, encoding="utf-8", errors="ignore") as f:
                text = f.read()

            entities = process_report(model, tokenizer, text, device)

            result = {
                "report_file": report_path.name,
                "org": org,
                "entities": entities,
                "entity_counts": {k: len(v) for k, v in entities.items()},
            }

            with open(out_file, "w", encoding="utf-8") as f:
                json.dump(result, f, ensure_ascii=False, indent=2)

            n_ent = sum(len(v) for v in entities.values())
            total_entities += n_ent
            logger.info(f"  → {n_ent} entities: " +
                        ", ".join(f"{k}={len(v)}" for k, v in sorted(entities.items())))

        except Exception as ex:
            logger.error(f"  → Error: {ex}")

    elapsed = time.time() - start_time
    logger.info(f"\nDone! {len(reports)} reports, {total_entities} total entities, {elapsed:.1f}s")


if __name__ == "__main__":
    main()
