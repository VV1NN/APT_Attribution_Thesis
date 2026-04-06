#!/usr/bin/env python3
"""
Phase 4: TTP GroupKFold 評估（Experiment 3）。

主實驗：
- Fold-aware L5（每 fold 用 train-only TF-IDF：Tool/Way/Exp）
- 權重：tfidf * source_reliability_score * exp(-lambda * age_days)
- 新增 consistency features：
  1) source_disagreement_rate
  2) ttp_conflict_entropy
  3) num_independent_sources

比較基線：
- Legacy global L5（舊版全域 features_l5_ttp_matrix.npz）

Leakage 防護：
- GroupKFold 使用 report-connected groups
- 每 fold 強制 assert train/test report 無交集
- Imputer 僅在 train fold 擬合
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import re
import sys
import argparse
import warnings
from collections import defaultdict
from datetime import date
from itertools import combinations
from pathlib import Path
from urllib.parse import unquote, urlparse

import numpy as np
from scipy.sparse import csr_matrix, hstack, load_npz
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.impute import SimpleImputer
from sklearn.metrics import f1_score
from sklearn.model_selection import GroupKFold
from sklearn.preprocessing import LabelEncoder
from xgboost import XGBClassifier

warnings.filterwarnings("ignore")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

FEATURE_DIR = Path("scripts/features")
KG_JSON = Path("knowledge_graphs/master/merged_kg.json")
TTP_MAPPING_PATH = Path("scripts/ttp_extraction/ioc_ttp_mapping.json")
SOURCE_QUALITY_PATH = Path("scripts/ttp_extraction/source_quality_table.json")
TTP_DIR = Path("scripts/ttp_extraction")
OUTPUT = Path("scripts/results/eval_groupkfold_ttp.json")

REF_DATE = date(2026, 4, 6)
AGE_DECAY_LAMBDA = 5e-4
DEFAULT_SOURCE_RELIABILITY = 0.62
TTP_TYPES = ("Tool", "Way", "Exp")

MONTH_MAP = {
    "jan": 1, "january": 1,
    "feb": 2, "february": 2,
    "mar": 3, "march": 3,
    "apr": 4, "april": 4,
    "may": 5,
    "jun": 6, "june": 6,
    "jul": 7, "july": 7,
    "aug": 8, "august": 8,
    "sep": 9, "sept": 9, "september": 9,
    "oct": 10, "october": 10,
    "nov": 11, "november": 11,
    "dec": 12, "december": 12,
}

sys.path.insert(0, str(Path(__file__).parent))
from build_features import load_kg, build_overlap_dict, extract_l3
from split_utils import build_report_connected_groups, assert_no_report_leak


def load_static_features():
    data = np.load(FEATURE_DIR / "features_all.npz", allow_pickle=True)
    with open(FEATURE_DIR / "feature_names.json") as f:
        names = json.load(f)
    return data["X"], data["y"], list(data["node_ids"]), names


def parse_args():
    parser = argparse.ArgumentParser(
        description="TTP GroupKFold evaluation with fold-aware L5 and optional L4 mode"
    )
    parser.add_argument(
        "--l4-mode",
        choices=["off", "transductive"],
        default="off",
        help="off=drop L4 features from static block; transductive=use original L4",
    )
    return parser.parse_args()


def load_legacy_l5_features():
    meta = np.load(FEATURE_DIR / "features_l5_ttp.npz", allow_pickle=True)
    X_l5 = load_npz(FEATURE_DIR / "features_l5_ttp_matrix.npz")
    return X_l5, list(meta["node_ids"]), list(meta["feature_names"])


def load_ioc_ttp_mapping():
    with open(TTP_MAPPING_PATH) as f:
        return json.load(f)


def load_source_quality_table() -> dict[str, float]:
    if not SOURCE_QUALITY_PATH.exists():
        logger.warning(
            f"{SOURCE_QUALITY_PATH} not found; using default "
            f"reliability={DEFAULT_SOURCE_RELIABILITY:.2f}"
        )
        return {}

    data = json.loads(SOURCE_QUALITY_PATH.read_text())
    out = {}
    for domain, info in data.items():
        if isinstance(info, dict):
            score = info.get("reliability_score", DEFAULT_SOURCE_RELIABILITY)
        else:
            score = info
        try:
            out[domain] = float(score)
        except (TypeError, ValueError):
            out[domain] = DEFAULT_SOURCE_RELIABILITY
    return out


def load_has_ioc_reports():
    with open(KG_JSON) as f:
        data = json.load(f)
    node_reports = {}
    for e in data["edges"]:
        if e.get("relationship") != "has_ioc":
            continue
        tgt = e["target"]
        reports = (e.get("attributes") or {}).get("source_reports", [])
        if not reports:
            continue
        if tgt in node_reports:
            node_reports[tgt] = sorted(set(node_reports[tgt]) | set(reports))
        else:
            node_reports[tgt] = sorted(set(reports))
    return node_reports


def balanced_weights(y):
    classes, counts = np.unique(y, return_counts=True)
    n, k = len(y), len(classes)
    w_map = {c: n / (k * cnt) for c, cnt in zip(classes, counts)}
    return np.array([w_map[yi] for yi in y])


def recompute_l3_for_fold(sample_nids, test_idx, adj, overlap_dict_full, org_list):
    test_set = set(sample_nids[i] for i in test_idx)
    fold_dict = {nid: orgs for nid, orgs in overlap_dict_full.items() if nid not in test_set}
    n_features = 7 + len(org_list)
    L3 = np.zeros((len(sample_nids), n_features), dtype=np.float32)
    for i, nid in enumerate(sample_nids):
        L3[i] = extract_l3(nid, adj, fold_dict, org_list, exclude_org=None)
    return L3


def _normalize_token(text: str) -> str:
    text = str(text).strip().lower()
    if not text:
        return ""
    return re.sub(r"\s+", "_", text)


def _url_hash(url: str) -> str:
    return hashlib.sha1(url.encode()).hexdigest()[:10]


def _normalize_host(host: str) -> str:
    host = host.lower().strip().strip(".")
    if host.startswith("www."):
        host = host[4:]
    return host


def _unwrap_archive_url(url: str) -> str:
    parsed = urlparse(url)
    host = _normalize_host(parsed.hostname or parsed.netloc or "")
    if host not in {"web.archive.org", "archive.org"}:
        return url

    m = re.search(r"/web/[^/]+/(.+)$", parsed.path or "")
    if not m:
        return url

    nested = unquote(m.group(1))
    if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:/[^/]", nested) and "://" not in nested:
        nested = nested.replace(":/", "://", 1)
    elif "://" not in nested:
        nested = "https://" + nested.lstrip("/")
    return nested


def extract_source_domain(report_url: str) -> str:
    raw = _unwrap_archive_url(report_url)
    parsed = urlparse(raw)
    host = parsed.hostname or parsed.netloc or ""
    return _normalize_host(host)


def _safe_date(y: int, m: int, d: int) -> date | None:
    try:
        return date(y, m, d)
    except ValueError:
        return None


def extract_report_date(report_url: str) -> date | None:
    m = re.search(r"/web/(\d{8})(?:\d{0,6})", report_url)
    if m:
        ts = m.group(1)
        dt = _safe_date(int(ts[:4]), int(ts[4:6]), int(ts[6:8]))
        if dt is not None:
            return dt

    candidates = [report_url, _unwrap_archive_url(report_url)]
    month_regex = "|".join(sorted(MONTH_MAP.keys(), key=len, reverse=True))

    for text in candidates:
        text_low = text.lower()

        m1 = re.search(r"(20\d{2})[/_-](0?[1-9]|1[0-2])[/_-](0?[1-9]|[12]\d|3[01])", text_low)
        if m1:
            dt = _safe_date(int(m1.group(1)), int(m1.group(2)), int(m1.group(3)))
            if dt is not None:
                return dt

        m2 = re.search(rf"(20\d{{2}})[/_-]({month_regex})[/_-](0?[1-9]|[12]\d|3[01])", text_low)
        if m2:
            dt = _safe_date(int(m2.group(1)), MONTH_MAP[m2.group(2)], int(m2.group(3)))
            if dt is not None:
                return dt

        m3 = re.search(r"(20\d{2})[/_-](0?[1-9]|1[0-2])(?:[/_-]|$)", text_low)
        if m3:
            dt = _safe_date(int(m3.group(1)), int(m3.group(2)), 15)
            if dt is not None:
                return dt

        m4 = re.search(r"(^|[/_-])(20\d{2})(?=$|[/_-])", text_low)
        if m4:
            dt = _safe_date(int(m4.group(2)), 7, 1)
            if dt is not None:
                return dt

    return None


def report_age_days(report_url: str, ref_date: date = REF_DATE) -> int | None:
    dt = extract_report_date(report_url)
    if dt is None:
        return None
    return max((ref_date - dt).days, 0)


def build_report_ttp_index() -> dict[str, set[str]]:
    index: dict[str, set[str]] = {}
    for fpath in sorted(TTP_DIR.glob("*/*.json")):
        stem = fpath.stem
        parts = stem.rsplit("_", 1)
        if len(parts) != 2 or len(parts[1]) != 10:
            continue
        h = parts[1]
        try:
            data = json.loads(fpath.read_text())
        except json.JSONDecodeError:
            continue

        ents = data.get("entities_normalized", {})
        toks = set()
        for etype in TTP_TYPES:
            for ent in ents.get(etype, []):
                tok = _normalize_token(ent)
                if tok:
                    toks.add(f"{etype}:{tok}")
        index[h] = toks
    return index


def build_docs_for_nodes(sample_nids, mapping):
    docs = []
    for nid in sample_nids:
        item = mapping.get(nid, {})
        ents = item.get("entities_normalized", {})
        toks = []
        for etype in TTP_TYPES:
            for ent in ents.get(etype, []):
                tok = _normalize_token(ent)
                if tok:
                    toks.append(f"{etype}:{tok}")
        docs.append(" ".join(toks))
    return docs


def build_node_weights_and_consistency(sample_nids, mapping, source_quality, report_ttp_index):
    n = len(sample_nids)
    node_weights = np.ones(n, dtype=np.float32)
    consistency = np.zeros((n, 3), dtype=np.float32)

    for i, nid in enumerate(sample_nids):
        item = mapping.get(nid, {})
        reports = item.get("reports") or []
        if not reports:
            continue

        report_weights = []
        source_tokens: dict[str, set[str]] = defaultdict(set)

        for url in reports:
            domain = extract_source_domain(url)
            if not domain:
                continue

            rel = float(source_quality.get(domain, DEFAULT_SOURCE_RELIABILITY))
            age_days = report_age_days(url)
            age_factor = math.exp(-AGE_DECAY_LAMBDA * age_days) if age_days is not None else 1.0
            report_weights.append(rel * age_factor)

            h = _url_hash(url)
            source_tokens[domain].update(report_ttp_index.get(h, set()))

        if report_weights:
            node_weights[i] = float(np.mean(report_weights))

        domains = sorted(source_tokens.keys())
        n_src = len(domains)
        consistency[i, 2] = float(n_src)

        if n_src < 2:
            continue

        sets = [source_tokens[d] for d in domains]

        dists = []
        for a, b in combinations(range(n_src), 2):
            A, B = sets[a], sets[b]
            union = A | B
            if not union:
                dists.append(0.0)
            else:
                dists.append(1.0 - len(A & B) / len(union))
        consistency[i, 0] = float(np.mean(dists)) if dists else 0.0

        universe = set().union(*sets)
        if not universe:
            consistency[i, 1] = 0.0
            continue

        entropy_sum = 0.0
        for tok in universe:
            c = sum(1 for s in sets if tok in s)
            p = c / n_src
            if 0.0 < p < 1.0:
                entropy_sum += -(p * math.log(p) + (1.0 - p) * math.log(1.0 - p)) / math.log(2)
        consistency[i, 1] = float(entropy_sum / len(universe))

    return node_weights, consistency


def build_foldaware_l5_matrix(train_idx, docs, node_weights, consistency):
    vectorizer = TfidfVectorizer(
        min_df=1,
        max_df=1.0,
        token_pattern=r"[^\s]+",
        lowercase=False,
    )

    train_docs = [docs[i] for i in train_idx]
    try:
        if not any(doc.strip() for doc in train_docs):
            raise ValueError("all train docs are empty")
        vectorizer.fit(train_docs)
        X_tfidf = vectorizer.transform(docs).tocsr()
    except ValueError:
        X_tfidf = csr_matrix((len(docs), 0), dtype=np.float32)
        vocab_size = 0
    else:
        vocab_size = X_tfidf.shape[1]
        if vocab_size > 0:
            X_tfidf = X_tfidf.multiply(node_weights[:, None])

    X_cons = csr_matrix(consistency, dtype=np.float32)
    X_all = hstack([X_tfidf.astype(np.float32), X_cons], format="csr")
    return X_all, vocab_size


def _to_dense(X):
    if hasattr(X, "toarray"):
        return X.toarray().astype(np.float32)
    return np.asarray(X, dtype=np.float32)


def build_static_block_for_config(config, X_static, L3_fold, l3_start, l3_end):
    idx = config.get("static_idx", [])
    n_samples = X_static.shape[0]
    if not idx:
        return np.empty((n_samples, 0), dtype=np.float32)

    if not config.get("l3_recompute", False):
        return _to_dense(X_static[:, idx])

    non_l3_idx = [i for i in idx if i < l3_start or i >= l3_end]
    l3_local_idx = [i - l3_start for i in idx if l3_start <= i < l3_end]

    parts = []
    if non_l3_idx:
        parts.append(_to_dense(X_static[:, non_l3_idx]))
    if l3_local_idx:
        parts.append(L3_fold[:, l3_local_idx].astype(np.float32))

    if not parts:
        return np.empty((n_samples, 0), dtype=np.float32)
    if len(parts) == 1:
        return parts[0]
    return np.hstack(parts).astype(np.float32)


def apply_l4_mode_to_configs(exp_configs, l4_idx, l4_mode):
    if l4_mode == "transductive":
        return exp_configs

    l4_set = set(l4_idx)
    out = {}
    for name, cfg in exp_configs.items():
        if name == "_meta":
            out[name] = dict(cfg)
            continue
        c = dict(cfg)
        static_idx = c.get("static_idx")
        if static_idx is not None:
            c["static_idx"] = [i for i in static_idx if i not in l4_set]
        out[name] = c
    return out


def run_cv(
    X_static,
    y_enc,
    le,
    sample_nids,
    groups,
    node_reports,
    adj,
    overlap_dict,
    org_list,
    exp_configs,
    legacy_l5_dense,
    docs,
    node_weights,
    consistency,
    l4_mode,
):
    n_classes = len(le.classes_)
    n_samples = len(sample_nids)

    l3_start = exp_configs["_meta"]["l3_start"]
    l3_end = exp_configs["_meta"]["l3_end"]
    configs = {k: v for k, v in exp_configs.items() if k != "_meta"}

    needs_l3_any = any(cfg.get("l3_recompute", False) for cfg in configs.values())
    needs_foldaware_any = any(cfg.get("l5_variant") == "foldaware" for cfg in configs.values())

    state = {
        name: {"y_true": [], "y_pred": [], "n_features": []}
        for name in configs
    }

    gkf = GroupKFold(n_splits=5)
    for fold, (tr, te) in enumerate(gkf.split(X_static, y_enc, groups)):
        leak_stats = assert_no_report_leak(tr, te, sample_nids, node_reports)
        logger.info(
            f"Fold {fold}: leak check PASS "
            f"(train_reports={leak_stats['train_report_count']}, "
            f"test_reports={leak_stats['test_report_count']})"
        )

        L3_fold = None
        if needs_l3_any:
            L3_fold = recompute_l3_for_fold(sample_nids, te, adj, overlap_dict, org_list)

        foldaware_l5_dense = None
        foldaware_vocab = 0
        if needs_foldaware_any:
            X_foldaware_l5, foldaware_vocab = build_foldaware_l5_matrix(
                tr, docs, node_weights, consistency
            )
            foldaware_l5_dense = X_foldaware_l5.toarray().astype(np.float32)
            logger.info(
                f"  Fold {fold}: fold-aware L5 vocab={foldaware_vocab}, "
                f"total_l5_dims={foldaware_l5_dense.shape[1]}"
            )

        for exp_name, cfg in configs.items():
            X_static_block = build_static_block_for_config(
                cfg, X_static, L3_fold, l3_start, l3_end
            )

            l5_variant = cfg.get("l5_variant")
            if l5_variant == "legacy":
                X_l5_block = legacy_l5_dense
            elif l5_variant == "foldaware":
                X_l5_block = foldaware_l5_dense
            else:
                X_l5_block = np.empty((n_samples, 0), dtype=np.float32)

            if X_static_block.shape[1] == 0:
                X_full = X_l5_block
            elif X_l5_block.shape[1] == 0:
                X_full = X_static_block
            else:
                X_full = np.hstack([X_static_block, X_l5_block]).astype(np.float32)

            state[exp_name]["n_features"].append(int(X_full.shape[1]))

            Xtr_raw, Xte_raw = X_full[tr], X_full[te]
            ytr, yte = y_enc[tr], y_enc[te]

            imputer = SimpleImputer(strategy="median")
            Xtr = imputer.fit_transform(Xtr_raw)
            Xte = imputer.transform(Xte_raw)

            train_classes = set(ytr)
            valid_mask = np.array([y in train_classes for y in yte])
            if not valid_mask.all():
                n_skip = int((~valid_mask).sum())
                logger.warning(f"  {exp_name} Fold {fold}: skip {n_skip} unseen-class samples")
                Xte = Xte[valid_mask]
                yte = yte[valid_mask]
                if len(yte) == 0:
                    continue

            fold_classes = sorted(set(ytr))
            class_map = {c: i for i, c in enumerate(fold_classes)}
            inv_map = {i: c for c, i in class_map.items()}
            ytr_re = np.array([class_map[c] for c in ytr])

            clf = XGBClassifier(
                n_estimators=500,
                max_depth=8,
                learning_rate=0.05,
                subsample=0.8,
                colsample_bytree=0.8,
                min_child_weight=3,
                eval_metric="mlogloss",
                random_state=42,
                n_jobs=-1,
                verbosity=0,
            )
            sw = balanced_weights(ytr_re)
            clf.fit(Xtr, ytr_re, sample_weight=sw)

            prob = clf.predict_proba(Xte)
            full_prob = np.zeros((len(yte), n_classes))
            for j in range(prob.shape[1]):
                full_prob[:, inv_map[j]] = prob[:, j]
            pred = np.argmax(full_prob, axis=1)

            state[exp_name]["y_true"].extend(yte.tolist())
            state[exp_name]["y_pred"].extend(pred.tolist())

    results = {}
    for exp_name, cfg in configs.items():
        y_true = np.array(state[exp_name]["y_true"], dtype=int)
        y_pred = np.array(state[exp_name]["y_pred"], dtype=int)
        if len(y_true) == 0:
            results[exp_name] = {
                "micro_f1": 0.0,
                "macro_f1": 0.0,
                "n_samples": 0,
                "n_features": int(np.mean(state[exp_name]["n_features"])) if state[exp_name]["n_features"] else 0,
                "per_class": {},
                "desc": cfg.get("desc", ""),
                "l4_mode": l4_mode,
            }
            continue

        micro = f1_score(y_true, y_pred, average="micro")
        macro = f1_score(y_true, y_pred, average="macro")

        per_class = {}
        for cls_idx in range(n_classes):
            mask = y_true == cls_idx
            if mask.sum() == 0:
                continue
            correct = int((y_pred[mask] == cls_idx).sum())
            total = int(mask.sum())
            per_class[le.classes_[cls_idx]] = {
                "total": total,
                "correct": correct,
                "accuracy": round(correct / total, 4),
            }

        results[exp_name] = {
            "micro_f1": round(micro, 4),
            "macro_f1": round(macro, 4),
            "n_samples": int(len(y_true)),
            "n_features": int(round(np.mean(state[exp_name]["n_features"]))),
            "per_class": per_class,
            "desc": cfg.get("desc", ""),
            "l4_mode": l4_mode,
        }

        logger.info(
            f"  {exp_name}: micro-F1={micro:.4f} macro-F1={macro:.4f} "
            f"(n={len(y_true)}, dims≈{results[exp_name]['n_features']})"
        )

    return results


def main():
    args = parse_args()
    l4_mode = args.l4_mode

    X_static, y, node_ids, names = load_static_features()
    X_legacy_l5, l5_node_ids, l5_names = load_legacy_l5_features()

    if node_ids != l5_node_ids:
        raise RuntimeError("Legacy L5 node_ids order mismatch with features_all.npz")

    X_legacy_l5_dense = X_legacy_l5.toarray().astype(np.float32)

    logger.info(f"Static features: {X_static.shape}")
    logger.info(f"Legacy global L5: {X_legacy_l5_dense.shape}")
    logger.info(f"L4 mode: {l4_mode}")

    mapping = load_ioc_ttp_mapping()
    source_quality = load_source_quality_table()
    report_ttp_index = build_report_ttp_index()
    docs = build_docs_for_nodes(node_ids, mapping)
    node_weights, consistency = build_node_weights_and_consistency(
        node_ids, mapping, source_quality, report_ttp_index
    )

    logger.info(
        f"Prepared fold-aware L5 metadata: docs={len(docs)}, "
        f"report_ttp_index={len(report_ttp_index)}, "
        f"source_quality={len(source_quality)}"
    )

    le = LabelEncoder()
    y_enc = le.fit_transform(y)
    logger.info(f"Classes: {len(le.classes_)} → {list(le.classes_)}")

    n_l1 = len(names["l1"])
    n_l2 = len(names["l2"])
    n_l3 = len(names["l3"])
    n_l4 = len(names["l4"])

    l1_idx = list(range(0, n_l1))
    l2_start = n_l1
    l2_end = l2_start + n_l2
    l2_idx = list(range(l2_start, l2_end))
    l3_start = l2_end
    l3_end = l3_start + n_l3
    l3_idx = list(range(l3_start, l3_end))
    l4_start = l3_end
    l4_end = l4_start + n_l4
    l4_idx = list(range(l4_start, l4_end))

    node_reports = load_has_ioc_reports()
    groups = build_report_connected_groups(node_ids, node_reports)
    n_groups = len(set(groups))
    logger.info(f"Report-connected groups: {n_groups}")

    logger.info("Loading KG for L3 recomputation...")
    nodes, adj, edge_by_node, has_ioc_orgs = load_kg()
    _ = (nodes, edge_by_node)  # keep loaded for parity/debug
    overlap_dict = build_overlap_dict(has_ioc_orgs)
    org_list = names.get("org_list", sorted(le.classes_))

    exp_configs = {
        "_meta": {
            "l3_start": l3_start,
            "l3_end": l3_end,
        },
        "L5_only_legacy_global": {
            "static_idx": [],
            "l5_variant": "legacy",
            "desc": f"Legacy global L5 baseline ({len(l5_names)}d)",
        },
        "L5_only": {
            "static_idx": [],
            "l5_variant": "foldaware",
            "desc": "Fold-aware L5 (Tool/Way/Exp TF-IDF + weighted + consistency)",
        },
        "L1_only": {
            "static_idx": l1_idx,
            "l5_variant": None,
            "desc": f"L1 metadata only ({len(l1_idx)}d) — baseline",
        },
        "L1+L5": {
            "static_idx": l1_idx,
            "l5_variant": "foldaware",
            "desc": "L1 + fold-aware L5",
        },
        "L1+L2+L5": {
            "static_idx": l1_idx + l2_idx,
            "l5_variant": "foldaware",
            "desc": "L1+L2 + fold-aware L5",
        },
        "L3+L5": {
            "static_idx": l3_idx,
            "l5_variant": "foldaware",
            "l3_recompute": True,
            "desc": "L3 + fold-aware L5 (graph+TTP)",
        },
        "L1+L2+L3+L5": {
            "static_idx": l1_idx + l2_idx + l3_idx,
            "l5_variant": "foldaware",
            "l3_recompute": True,
            "desc": "L1+L2+L3 + fold-aware L5",
        },
        "L1+L2+L3+L4+L5": {
            "static_idx": l1_idx + l2_idx + l3_idx + l4_idx,
            "l5_variant": "foldaware",
            "l3_recompute": True,
            "desc": "Full model (L1-L4 + fold-aware L5)",
        },
    }
    exp_configs = apply_l4_mode_to_configs(exp_configs, l4_idx, l4_mode)

    sample_nids = np.array(node_ids)
    results = run_cv(
        X_static=X_static,
        y_enc=y_enc,
        le=le,
        sample_nids=sample_nids,
        groups=groups,
        node_reports=node_reports,
        adj=adj,
        overlap_dict=overlap_dict,
        org_list=org_list,
        exp_configs=exp_configs,
        legacy_l5_dense=X_legacy_l5_dense,
        docs=docs,
        node_weights=node_weights,
        consistency=consistency,
        l4_mode=l4_mode,
    )

    print(f"\n{'='*74}")
    print(f"★ TTP GroupKFold Results (Legacy vs Fold-Aware L5, l4_mode={l4_mode}) ★")
    print(f"{'='*74}")
    print(f"  {'Config':<26} {'Dims':>7} {'micro-F1':>10} {'macro-F1':>10}")
    print(f"  {'-'*26} {'-'*7} {'-'*10} {'-'*10}")
    for name, r in results.items():
        print(f"  {name:<26} {r['n_features']:>7} {r['micro_f1']:>9.1%} {r['macro_f1']:>9.1%}")

    legacy = results.get("L5_only_legacy_global", {})
    foldaware = results.get("L5_only", {})
    print("\n  L5-only comparison:")
    print(
        f"    Legacy global L5: micro={legacy.get('micro_f1', 0):.1%}, "
        f"macro={legacy.get('macro_f1', 0):.1%}"
    )
    print(
        f"    Fold-aware L5:    micro={foldaware.get('micro_f1', 0):.1%}, "
        f"macro={foldaware.get('macro_f1', 0):.1%}"
    )

    output_payload = {
        "metadata": {
            "age_decay_lambda": AGE_DECAY_LAMBDA,
            "ref_date": str(REF_DATE),
            "source_quality_table": str(SOURCE_QUALITY_PATH),
            "group_count": int(n_groups),
            "l4_mode": l4_mode,
            "notes": [
                "Legacy global L5 kept as baseline only",
                "Main experiments use fold-aware train-only TF-IDF (Tool/Way/Exp)",
                "Fold leak check enforced via assert_no_report_leak",
            ],
        },
        "results": results,
    }

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT, "w") as f:
        json.dump(output_payload, f, indent=2, ensure_ascii=False)
    logger.info(f"Saved to {OUTPUT}")


if __name__ == "__main__":
    main()
