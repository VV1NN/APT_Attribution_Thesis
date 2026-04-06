#!/usr/bin/env python3
"""
False-flag robustness evaluation.

Attacks:
1) tool_mimicry     - replace a fraction of Tool tokens with donor-actor common Tool tokens
2) way_mimicry      - replace a fraction of Way tokens
3) source_poisoning - reduce high-reliability source contribution in weighted L5

Strength:
- r = 0.1, 0.3, 0.5

Defenses compared:
- baseline_raw
- weighted_l5
- weighted_l5_calibrated
- weighted_l5_calibrated_abstain
"""

from __future__ import annotations

import hashlib
import json
import math
import pickle
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Dict, List
from urllib.parse import unquote, urlparse

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import f1_score
from sklearn.model_selection import GroupKFold
from xgboost import XGBClassifier

import sys
sys.path.insert(0, str(Path(__file__).parent))
from split_utils import build_report_connected_groups, assert_no_report_leak
sys.path.insert(0, str(Path(__file__).parent / "model"))
from calibration_utils import apply_temperature_to_probs

FEATURE_PATH = Path("scripts/features/features_all.npz")
MAPPING_PATH = Path("scripts/ttp_extraction/ioc_ttp_mapping.json")
SOURCE_QUALITY_PATH = Path("scripts/ttp_extraction/source_quality_table.json")
CALIBRATOR_PATH = Path("scripts/model/calibrator.pkl")
KG_PATH = Path("knowledge_graphs/master/merged_kg.json")
OUTPUT_PATH = Path("scripts/results/eval_false_flag.json")

REF_DATE = date(2026, 4, 6)
LAMBDA_AGE = 5e-4
DEFAULT_REL = 0.62
TTP_TYPES = ("Tool", "Way", "Exp")

ATTACKS = ["tool_mimicry", "way_mimicry", "source_poisoning"]
STRENGTHS = [0.1, 0.3, 0.5]


@dataclass
class DefenseConfig:
    name: str
    weighted_l5: bool
    calibrated: bool
    abstain: bool


DEFENSES = [
    DefenseConfig("baseline_raw", weighted_l5=False, calibrated=False, abstain=False),
    DefenseConfig("weighted_l5", weighted_l5=True, calibrated=False, abstain=False),
    DefenseConfig("weighted_l5_calibrated", weighted_l5=True, calibrated=True, abstain=False),
    DefenseConfig("weighted_l5_calibrated_abstain", weighted_l5=True, calibrated=True, abstain=True),
]


def stable_seed(*parts) -> int:
    s = "::".join(str(p) for p in parts)
    h = hashlib.sha1(s.encode()).hexdigest()[:8]
    return int(h, 16)


def normalize_token(x: str) -> str:
    x = str(x).strip().lower()
    x = re.sub(r"\s+", "_", x)
    return x


def report_hash(url: str) -> str:
    return hashlib.sha1(url.encode()).hexdigest()[:10]


def normalize_host(host: str) -> str:
    host = host.lower().strip().strip(".")
    if host.startswith("www."):
        host = host[4:]
    return host


def unwrap_archive_url(url: str) -> str:
    p = urlparse(url)
    host = normalize_host(p.hostname or p.netloc or "")
    if host not in {"web.archive.org", "archive.org"}:
        return url
    m = re.search(r"/web/[^/]+/(.+)$", p.path or "")
    if not m:
        return url
    nested = unquote(m.group(1))
    if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:/[^/]", nested) and "://" not in nested:
        nested = nested.replace(":/", "://", 1)
    elif "://" not in nested:
        nested = "https://" + nested.lstrip("/")
    return nested


def extract_source_domain(url: str) -> str:
    p = urlparse(unwrap_archive_url(url))
    return normalize_host(p.hostname or p.netloc or "")


def extract_report_date(url: str):
    m = re.search(r"/web/(\d{8})(?:\d{0,6})", url)
    if m:
        ts = m.group(1)
        y, mo, d = int(ts[:4]), int(ts[4:6]), int(ts[6:8])
        try:
            return date(y, mo, d)
        except ValueError:
            return None

    m = re.search(r"(20\d{2})[/_-](0?[1-9]|1[0-2])[/_-](0?[1-9]|[12]\d|3[01])", url)
    if m:
        y, mo, d = int(m.group(1)), int(m.group(2)), int(m.group(3))
        try:
            return date(y, mo, d)
        except ValueError:
            return None
    return None


def report_age_days(url: str) -> int | None:
    dt = extract_report_date(url)
    if dt is None:
        return None
    return max((REF_DATE - dt).days, 0)


def balanced_weights(y):
    classes, counts = np.unique(y, return_counts=True)
    n, k = len(y), len(classes)
    w_map = {c: n / (k * cnt) for c, cnt in zip(classes, counts)}
    return np.array([w_map[yi] for yi in y], dtype=np.float32)


def load_node_reports():
    kg = json.loads(KG_PATH.read_text())
    node_reports = {}
    for e in kg["edges"]:
        if e.get("relationship") != "has_ioc":
            continue
        tgt = e["target"]
        reports = (e.get("attributes") or {}).get("source_reports", [])
        if reports:
            node_reports[tgt] = sorted(set(node_reports.get(tgt, [])) | set(reports))
    return node_reports


def build_clean_docs_and_weights(node_ids, y_labels, mapping, source_quality):
    actor_freq = defaultdict(lambda: {etype: Counter() for etype in TTP_TYPES})

    token_by_nid = {}
    docs = []
    node_weight_clean = np.ones(len(node_ids), dtype=np.float32)
    node_source_records: Dict[str, List[tuple[float, float]]] = {}

    for i, nid in enumerate(node_ids):
        item = mapping.get(nid, {})
        ents = item.get("entities_normalized", {})

        tmap = {}
        all_doc_tokens = []
        for etype in TTP_TYPES:
            toks = [normalize_token(t) for t in ents.get(etype, []) if normalize_token(t)]
            tmap[etype] = toks
            all_doc_tokens.extend(f"{etype}:{t}" for t in toks)
            actor = y_labels[i]
            actor_freq[actor][etype].update(toks)
        token_by_nid[nid] = tmap
        docs.append(" ".join(all_doc_tokens))

        reports = item.get("reports", [])
        recs = []
        for url in reports:
            dom = extract_source_domain(url)
            rel = float(source_quality.get(dom, DEFAULT_REL))
            age = report_age_days(url)
            age_factor = math.exp(-LAMBDA_AGE * age) if age is not None else 1.0
            recs.append((rel, age_factor))
        node_source_records[nid] = recs
        if recs:
            node_weight_clean[i] = float(np.mean([r * a for r, a in recs]))

    actor_top_tokens = defaultdict(dict)
    actors_sorted = sorted(actor_freq.keys())
    for actor in actors_sorted:
        for etype in TTP_TYPES:
            actor_top_tokens[actor][etype] = [
                tok for tok, _ in actor_freq[actor][etype].most_common(60)
            ]

    donor_map = {}
    for idx, actor in enumerate(actors_sorted):
        donor_map[actor] = actors_sorted[(idx + 1) % len(actors_sorted)]

    return docs, token_by_nid, node_weight_clean, node_source_records, actor_top_tokens, donor_map


def build_attacked_doc(nid, actor, attack_name, r, token_by_nid, actor_top_tokens, donor_map):
    if attack_name not in {"tool_mimicry", "way_mimicry"}:
        toks = token_by_nid[nid]
        all_toks = []
        for etype in TTP_TYPES:
            all_toks.extend(f"{etype}:{t}" for t in toks.get(etype, []))
        return " ".join(all_toks)

    target_type = "Tool" if attack_name == "tool_mimicry" else "Way"
    donor_actor = donor_map.get(actor, actor)
    donor_pool = actor_top_tokens.get(donor_actor, {}).get(target_type, [])

    toks_map = {k: list(v) for k, v in token_by_nid[nid].items()}
    orig = toks_map.get(target_type, [])

    if donor_pool and len(orig) > 0 and r > 0:
        k = max(1, int(round(len(orig) * r)))
        k = min(k, len(orig))
        rng = np.random.default_rng(stable_seed(nid, attack_name, r))
        idxs = rng.choice(len(orig), size=k, replace=False)
        for idx in idxs:
            replacement = donor_pool[int(rng.integers(0, len(donor_pool)))]
            orig[idx] = replacement
        toks_map[target_type] = orig

    all_toks = []
    for etype in TTP_TYPES:
        all_toks.extend(f"{etype}:{t}" for t in toks_map.get(etype, []))
    return " ".join(all_toks)


def compute_attacked_weight(nid, attack_name, r, node_source_records):
    recs = node_source_records.get(nid, [])
    if not recs:
        return 1.0
    if attack_name != "source_poisoning":
        return float(np.mean([rel * age for rel, age in recs]))

    vals = []
    for rel, age_factor in recs:
        rel_adj = rel * (1.0 - r) if rel >= 0.8 else rel
        vals.append(rel_adj * age_factor)
    return float(np.mean(vals))


def predict_with_decision(
    probs,
    cfg: DefenseConfig,
    low_conf_thr,
    open_set_thr,
    conflict_margin_thr,
):
    pred = np.argmax(probs, axis=1).astype(np.int32)
    conf = np.max(probs, axis=1)
    part = np.partition(probs, kth=max(probs.shape[1] - 2, 0), axis=1)
    second = part[:, -2] if probs.shape[1] > 1 else np.zeros_like(conf)
    margin = conf - second

    abstain_mask = np.zeros(len(pred), dtype=bool)
    reasons = np.array([""] * len(pred), dtype=object)

    if cfg.abstain:
        mask_open = conf < open_set_thr
        mask_conflict = (margin < conflict_margin_thr) & (~mask_open)
        mask_low = (conf < low_conf_thr) & (~mask_open) & (~mask_conflict)
        abstain_mask = mask_open | mask_conflict | mask_low
        reasons[mask_open] = "open_set"
        reasons[mask_conflict] = "high_conflict"
        reasons[mask_low] = "low_confidence"
        pred = pred.copy()
        pred[abstain_mask] = -1

    return pred, abstain_mask, reasons


def compute_metrics(y_true, y_pred, n_classes):
    labels = list(range(n_classes))
    micro = f1_score(y_true, y_pred, labels=labels, average="micro", zero_division=0)
    macro = f1_score(y_true, y_pred, labels=labels, average="macro", zero_division=0)
    abstain_mask = y_pred == -1
    non_abstain = ~abstain_mask
    wrong_non_abstain = np.logical_and(non_abstain, y_pred != y_true)
    non_abstain_count = int(np.sum(non_abstain))
    wrong_non_abstain_count = int(np.sum(wrong_non_abstain))
    misattr_rate = float(np.mean(wrong_non_abstain))
    conditional_misattr_rate = float(wrong_non_abstain_count / max(non_abstain_count, 1))
    abstain_rate = float(np.mean(abstain_mask))
    return {
        "micro_f1": float(micro),
        "macro_f1": float(macro),
        "abstain_rate": abstain_rate,
        "misattribution_rate": misattr_rate,
        "conditional_misattribution_rate": conditional_misattr_rate,
        "non_abstain_count": non_abstain_count,
        "wrong_non_abstain_count": wrong_non_abstain_count,
    }


def main():
    data = np.load(FEATURE_PATH, allow_pickle=True)
    node_ids = list(data["node_ids"])
    y_labels = data["y"].astype(str).tolist()

    label_to_idx = {lab: i for i, lab in enumerate(sorted(set(y_labels)))}
    y = np.array([label_to_idx[lab] for lab in y_labels], dtype=np.int32)
    n_classes = len(label_to_idx)

    mapping = json.loads(MAPPING_PATH.read_text())
    source_quality_raw = json.loads(SOURCE_QUALITY_PATH.read_text()) if SOURCE_QUALITY_PATH.exists() else {}
    source_quality = {}
    for dom, info in source_quality_raw.items():
        if isinstance(info, dict):
            source_quality[dom] = float(info.get("reliability_score", DEFAULT_REL))
        else:
            source_quality[dom] = float(info)

    calibrator = {}
    if CALIBRATOR_PATH.exists():
        with open(CALIBRATOR_PATH, "rb") as f:
            calibrator = pickle.load(f)
    temperature = float(calibrator.get("temperature", 1.0))

    # Practical clipping to avoid degenerate all-abstain from very high threshold.
    low_conf_thr = float(min(max(calibrator.get("low_confidence_threshold", 0.12), 0.05), 0.12))
    open_set_thr = float(min(max(calibrator.get("open_set_conf_threshold", 0.08), 0.03), 0.09))
    conflict_margin_thr = float(min(max(calibrator.get("conflict_margin_threshold", 0.05), 0.01), 0.08))

    node_reports = load_node_reports()
    groups = build_report_connected_groups(node_ids, node_reports)
    print(f"Report-connected groups: {len(set(groups))}")

    docs_clean, token_by_nid, node_weight_clean, node_source_records, actor_top_tokens, donor_map = (
        build_clean_docs_and_weights(node_ids, y_labels, mapping, source_quality)
    )

    scenario_list = [("clean", 0.0)] + [
        (atk, r) for atk in ATTACKS for r in STRENGTHS
    ]

    agg = {
        cfg.name: {
            f"{atk}@{r:.1f}": {"y_true": [], "y_pred": [], "reason_counts": Counter()}
            for atk, r in scenario_list
        }
        for cfg in DEFENSES
    }

    gkf = GroupKFold(n_splits=5)
    for fold, (tr, te) in enumerate(gkf.split(np.arange(len(y)), y, groups)):
        leak_stats = assert_no_report_leak(tr, te, node_ids, node_reports)
        print(
            f"Fold {fold}: leak PASS (train_reports={leak_stats['train_report_count']}, "
            f"test_reports={leak_stats['test_report_count']})"
        )

        train_docs = [docs_clean[i] for i in tr]
        vectorizer = TfidfVectorizer(
            min_df=1, max_df=1.0, token_pattern=r"[^\s]+", lowercase=False
        )
        vectorizer.fit(train_docs)

        Xtr_base = vectorizer.transform(train_docs).toarray().astype(np.float32)
        ytr = y[tr]
        yte_full = y[te]

        fold_classes = sorted(set(ytr.tolist()))
        class_map = {c: i for i, c in enumerate(fold_classes)}
        inv_map = {i: c for c, i in class_map.items()}
        ytr_re = np.array([class_map[c] for c in ytr], dtype=np.int32)

        train_class_set = set(fold_classes)
        valid_mask = np.array([yy in train_class_set for yy in yte_full], dtype=bool)
        if not np.all(valid_mask):
            n_skip = int((~valid_mask).sum())
            print(f"Fold {fold}: skip {n_skip} unseen-class samples")
        if not np.any(valid_mask):
            continue

        te_valid = te[valid_mask]
        yte = yte_full[valid_mask]

        for cfg in DEFENSES:
            if cfg.weighted_l5:
                Xtr = Xtr_base * node_weight_clean[tr][:, None]
            else:
                Xtr = Xtr_base

            clf = XGBClassifier(
                n_estimators=300,
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
            clf.fit(Xtr, ytr_re, sample_weight=balanced_weights(ytr_re))

            for attack_name, r in scenario_list:
                test_docs = []
                test_weights = []
                for idx in te_valid:
                    nid = node_ids[idx]
                    actor = y_labels[idx]
                    if attack_name == "clean":
                        doc = docs_clean[idx]
                        w = float(node_weight_clean[idx])
                    else:
                        doc = build_attacked_doc(
                            nid, actor, attack_name, r, token_by_nid, actor_top_tokens, donor_map
                        )
                        w = compute_attacked_weight(nid, attack_name, r, node_source_records)
                    test_docs.append(doc)
                    test_weights.append(w)

                Xte_base = vectorizer.transform(test_docs).toarray().astype(np.float32)
                if cfg.weighted_l5:
                    Xte = Xte_base * np.array(test_weights, dtype=np.float32)[:, None]
                else:
                    Xte = Xte_base

                probs_small = clf.predict_proba(Xte)
                probs = np.zeros((len(yte), n_classes), dtype=np.float32)
                for j in range(probs_small.shape[1]):
                    probs[:, inv_map[j]] = probs_small[:, j]
                if cfg.calibrated:
                    probs = apply_temperature_to_probs(probs, temperature=temperature)

                y_pred, abstain_mask, reasons = predict_with_decision(
                    probs,
                    cfg,
                    low_conf_thr=low_conf_thr,
                    open_set_thr=open_set_thr,
                    conflict_margin_thr=conflict_margin_thr,
                )

                key = f"{attack_name}@{r:.1f}"
                agg[cfg.name][key]["y_true"].extend(yte.tolist())
                agg[cfg.name][key]["y_pred"].extend(y_pred.tolist())
                if cfg.abstain:
                    rc = Counter([rr for rr in reasons.tolist() if rr])
                    agg[cfg.name][key]["reason_counts"].update(rc)

    results = {}
    for cfg in DEFENSES:
        cfg_res = {}
        clean_key = "clean@0.0"
        clean_true = np.array(agg[cfg.name][clean_key]["y_true"], dtype=np.int32)
        clean_pred = np.array(agg[cfg.name][clean_key]["y_pred"], dtype=np.int32)
        clean_metrics = compute_metrics(clean_true, clean_pred, n_classes)
        cfg_res[clean_key] = {
            **clean_metrics,
            "delta_micro_f1": 0.0,
            "delta_macro_f1": 0.0,
            "abstain_rate_change": 0.0,
            "reason_counts": dict(agg[cfg.name][clean_key]["reason_counts"]),
        }

        for attack_name in ATTACKS:
            for r in STRENGTHS:
                key = f"{attack_name}@{r:.1f}"
                y_true_arr = np.array(agg[cfg.name][key]["y_true"], dtype=np.int32)
                y_pred_arr = np.array(agg[cfg.name][key]["y_pred"], dtype=np.int32)
                m = compute_metrics(y_true_arr, y_pred_arr, n_classes)
                cfg_res[key] = {
                    **m,
                    "delta_micro_f1": float(m["micro_f1"] - clean_metrics["micro_f1"]),
                    "delta_macro_f1": float(m["macro_f1"] - clean_metrics["macro_f1"]),
                    "abstain_rate_change": float(m["abstain_rate"] - clean_metrics["abstain_rate"]),
                    "reason_counts": dict(agg[cfg.name][key]["reason_counts"]),
                }
        results[cfg.name] = cfg_res

    # Defense rankings.
    defense_rank_utility = []
    defense_rank_safety = []
    defense_rank_risk_aware = []
    for cfg in DEFENSES:
        vals_micro = []
        vals_misattr = []
        vals_abstain = []
        for atk in ATTACKS:
            for r in STRENGTHS:
                m = results[cfg.name][f"{atk}@{r:.1f}"]
                vals_micro.append(m["micro_f1"])
                vals_misattr.append(m["misattribution_rate"])
                vals_abstain.append(m["abstain_rate"])
        avg_micro = float(np.mean(vals_micro))
        avg_mis = float(np.mean(vals_misattr))
        avg_abs = float(np.mean(vals_abstain))
        defense_rank_utility.append((cfg.name, avg_micro))
        defense_rank_safety.append((cfg.name, avg_mis))
        if avg_abs <= 0.4:
            defense_rank_risk_aware.append((cfg.name, avg_micro, avg_abs))
    defense_rank_utility.sort(key=lambda x: x[1], reverse=True)
    defense_rank_safety.sort(key=lambda x: x[1])  # lower misattribution is safer
    defense_rank_risk_aware.sort(key=lambda x: x[1], reverse=True)

    # Per-attack defense ranking.
    attack_wise_defense_ranking = {}
    for atk in ATTACKS:
        rows = []
        for cfg in DEFENSES:
            vals_micro, vals_mis, vals_abs = [], [], []
            for r in STRENGTHS:
                m = results[cfg.name][f"{atk}@{r:.1f}"]
                vals_micro.append(m["micro_f1"])
                vals_mis.append(m["misattribution_rate"])
                vals_abs.append(m["abstain_rate"])
            rows.append(
                {
                    "defense": cfg.name,
                    "avg_micro_f1": float(np.mean(vals_micro)),
                    "avg_misattribution_rate": float(np.mean(vals_mis)),
                    "avg_abstain_rate": float(np.mean(vals_abs)),
                }
            )
        rows.sort(key=lambda x: x["avg_micro_f1"], reverse=True)
        attack_wise_defense_ranking[atk] = rows

    attack_rank = []
    baseline_name = "baseline_raw"
    for atk in ATTACKS:
        deltas = []
        for r in STRENGTHS:
            deltas.append(results[baseline_name][f"{atk}@{r:.1f}"]["delta_micro_f1"])
        attack_rank.append((atk, float(np.mean(deltas))))
    attack_rank.sort(key=lambda x: x[1])  # more negative = more harmful

    payload = {
        "metadata": {
            "attacks": ATTACKS,
            "strengths": STRENGTHS,
            "defenses": [cfg.name for cfg in DEFENSES],
            "temperature": temperature,
            "thresholds_used": {
                "low_confidence": low_conf_thr,
                "open_set": open_set_thr,
                "conflict_margin": conflict_margin_thr,
            },
            "note": "Thresholds clipped to practical range for non-degenerate abstain analysis.",
        },
        "results": results,
        "summary": {
            "defense_rank_utility_by_avg_attacked_micro_f1": defense_rank_utility,
            "defense_rank_safety_by_avg_attacked_misattribution": defense_rank_safety,
            "defense_rank_risk_aware": defense_rank_risk_aware,
            "attack_wise_defense_ranking": attack_wise_defense_ranking,
            "attack_rank_by_baseline_avg_delta_micro_f1": attack_rank,
            "most_harmful_attack": attack_rank[0][0] if attack_rank else None,
            "most_effective_defense": defense_rank_utility[0][0] if defense_rank_utility else None,
        },
    }

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_PATH, "w") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)

    print("\n=== False-Flag Evaluation Summary ===")
    print("\n[Utility Ranking] avg attacked micro-F1 (higher better)")
    for cfg_name, avg_micro in defense_rank_utility:
        print(f"  {cfg_name:<34} {avg_micro:.4f}")
    print("\n[Safety Ranking] avg attacked misattribution (lower better)")
    for cfg_name, avg_mis in defense_rank_safety:
        print(f"  {cfg_name:<34} {avg_mis:.4f}")
    print("\n[Risk-Aware Ranking] avg attacked micro-F1 with abstain<=0.4")
    if defense_rank_risk_aware:
        for cfg_name, avg_micro, avg_abs in defense_rank_risk_aware:
            print(f"  {cfg_name:<34} micro={avg_micro:.4f} abstain={avg_abs:.4f}")
    else:
        print("  (no defense satisfies abstain<=0.4)")

    print("\n[Attack-wise Defense Ranking] by avg micro-F1")
    for atk in ATTACKS:
        print(f"  {atk}:")
        for row in attack_wise_defense_ranking[atk]:
            print(
                f"    {row['defense']:<32} "
                f"micro={row['avg_micro_f1']:.4f} "
                f"misattr={row['avg_misattribution_rate']:.4f} "
                f"abstain={row['avg_abstain_rate']:.4f}"
            )
    print(f"Most harmful attack (baseline delta micro): {payload['summary']['most_harmful_attack']}")
    print(f"Most effective defense: {payload['summary']['most_effective_defense']}")
    print(f"Saved: {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
