#!/usr/bin/env python3
"""
DeepPath 歸因驗證實驗
使用 leave-one-out 方法測試歸因準確性。

實驗設計：
    - 只使用有 vt_relationships 邊且邊數 >= MIN_EDGES 的 prototype
    - 每個 APT 隨機抽取 30% 節點作為 query，剩下 70% 作為 reduced prototype
    - 重複 5 次（不同隨機種子）
    - 評估 Top-1/Top-3 Accuracy、MRR、消融實驗、分數分布
"""

from __future__ import annotations

import json
import logging
import random
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

import numpy as np

# ── cti_predictor 加入 path ────────────────────────────────────────────────
SCRIPT_DIR = Path(__file__).resolve().parent
BASE_DIR = SCRIPT_DIR.parent
sys.path.insert(0, str(BASE_DIR / "cti_predictor"))

from predictor import APTAttributor         # noqa: E402
from similarity import SubgraphSimilarity   # noqa: E402
from evaluator import CTIEvaluator          # noqa: E402

# ── 設定 ──────────────────────────────────────────────────────────────────

PROTOTYPE_DIR = BASE_DIR / "prototype_subgraphs"
OUTPUT_DIR    = BASE_DIR / "output"
RANDOM_SEED   = 42
QUERY_RATIO   = 0.30   # 30% 抽出作為 query
NUM_TRIALS    = 5      # 每個 APT 做 5 次隨機抽樣
MIN_EDGES     = 20     # 最低邊數門檻（排除邊太少的 prototype，如 APT12=0, APT1=5, APT-C-36=16）

logging.basicConfig(
    level=logging.WARNING,   # 主實驗只印 WARNING 以上；詳細 INFO 已在各步驟 print
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)


# ── 工具函式 ──────────────────────────────────────────────────────────────

def load_prototypes_meta() -> dict[str, Path]:
    """
    載入 prototype_subgraphs/ 中所有 JSON，跳過 co_occurrence 邊來源的 prototype。
    回傳 {apt_name: path}。
    """
    result: dict[str, Path] = {}
    for pf in sorted(PROTOTYPE_DIR.glob("*.json")):
        try:
            with open(pf, encoding="utf-8") as f:
                data = json.load(f)
            if data.get("edge_source") == "co_occurrence":
                print(f"  [跳過] {data['apt_name']}（edge_source=co_occurrence，結構不真實）")
                continue
            edge_count = data.get("edge_count", 0)
            if edge_count < MIN_EDGES:
                print(f"  [跳過] {data['apt_name']}（edge_count={edge_count} < {MIN_EDGES}，邊數不足）")
                continue
            apt_name = data["apt_name"]
            result[apt_name] = pf
        except Exception as exc:
            logger.warning("讀取 %s 失敗: %s", pf, exc)
    return result


def split_prototype(
    prototype_path: Path,
    query_ratio: float,
    seed: int,
) -> tuple[dict, dict]:
    """
    將一個 prototype 拆成 query（query_ratio）和 reduced prototype（1 - query_ratio）。

    拆分邏輯：
        - 隨機選 query_ratio 的節點作為 query 節點
        - query 邊：兩端均在 query 節點集合的邊
        - reduced prototype 邊：至少一端在 proto 節點集合的邊（保留較多結構資訊）

    Returns:
        (query_data, reduced_proto_data)  各含 apt_name / nodes / edges
    """
    with open(prototype_path, encoding="utf-8") as f:
        data = json.load(f)

    nodes: list[dict] = data["nodes"]
    edges: list[dict] = data["edges"]
    apt_name: str = data["apt_name"]

    random.seed(seed)

    n_query = max(3, int(len(nodes) * query_ratio))
    query_ids = set(n["id"] for n in random.sample(nodes, min(n_query, len(nodes))))
    proto_ids = set(n["id"] for n in nodes) - query_ids

    query_nodes = [n for n in nodes if n["id"] in query_ids]
    proto_nodes = [n for n in nodes if n["id"] in proto_ids]

    # query 邊：嚴格兩端都在 query 中
    query_edges = [
        e for e in edges
        if e["source"] in query_ids and e["target"] in query_ids
    ]
    # proto 邊：至少一端在 proto 中（寬鬆，保留更多結構）
    proto_edges = [
        e for e in edges
        if e["source"] in proto_ids or e["target"] in proto_ids
    ]

    return (
        {"apt_name": apt_name, "nodes": query_nodes, "edges": query_edges},
        {"apt_name": apt_name, "nodes": proto_nodes, "edges": proto_edges},
    )


def _remove_cooccurrence_prototypes(attributor: APTAttributor) -> None:
    """
    從 APTAttributor 中移除 edge_source=co_occurrence 的 prototype。
    APTAttributor.__init__ 會載入 prototype_dir 內所有 JSON（含 co_occurrence），
    需要在初始化後手動清除，避免污染歸因結果。
    """
    for name in list(attributor.prototypes.keys()):
        proto_path = PROTOTYPE_DIR / f"{name}.json"
        if proto_path.exists():
            with open(proto_path, encoding="utf-8") as f:
                meta = json.load(f)
            if meta.get("edge_source") == "co_occurrence":
                del attributor.prototypes[name]
                logger.debug("已移除 co_occurrence prototype: %s", name)


def _filter_prototype_pool(
    attributor: APTAttributor,
    allowed_apts: set[str],
) -> None:
    """
    從 APTAttributor 中移除不在實驗組的 prototype，避免 pool 污染。
    先移除 co_occurrence，再移除非實驗組的 APT。
    """
    _remove_cooccurrence_prototypes(attributor)
    for name in list(attributor.prototypes.keys()):
        if name not in allowed_apts:
            del attributor.prototypes[name]
            logger.debug("移除非實驗組 prototype: %s", name)


def run_single_attribution(
    target_apt: str,
    query_data: dict,
    reduced_proto: dict,
    all_prototype_paths: dict[str, Path],
    weights: dict | None = None,
    threshold: float = 0.1,
) -> Any:
    """
    對單次 query 執行歸因：
        1. 用 prototype_dir 初始化 APTAttributor
        2. 過濾 prototype pool（只保留實驗組 APT）
        3. 用 reduced_proto 覆蓋 target_apt 的 prototype
        4. 執行 attribute()
    """
    allowed_apts = set(all_prototype_paths.keys())

    attributor = APTAttributor(
        prototype_dir=str(PROTOTYPE_DIR),
        threshold=threshold,
        weights=weights,
    )
    _filter_prototype_pool(attributor, allowed_apts)

    # 用 reduced prototype 覆蓋 target APT
    attributor.prototypes[target_apt] = SubgraphSimilarity._build_graph(
        reduced_proto["nodes"], reduced_proto["edges"]
    )
    result = attributor.attribute(
        query_nodes=query_data["nodes"],
        query_edges=query_data["edges"],
        query_name=f"{target_apt}_trial{query_data.get('_trial', 0)}",
        top_k=len(all_prototype_paths),
    )
    return result


# ── 實驗 1：Leave-One-Out 歸因 ─────────────────────────────────────────────

def experiment_leave_one_out(
    apt_names: list[str],
    prototype_paths: dict[str, Path],
) -> tuple[list, dict[str, str]]:
    """
    執行 Leave-One-Out × NUM_TRIALS 實驗。
    回傳 (all_results, ground_truth)。
    """
    print(f"\n{'='*70}")
    print("  實驗 1：Leave-One-Out 歸因測試")
    print(f"  APT 清單: {apt_names}")
    print(f"  Trials: {NUM_TRIALS}  query_ratio: {QUERY_RATIO}")
    print(f"{'='*70}")

    all_results: list = []
    ground_truth: dict[str, str] = {}

    for trial in range(NUM_TRIALS):
        seed = RANDOM_SEED + trial
        print(f"\n  ── Trial {trial+1}/{NUM_TRIALS}（seed={seed}）──")

        for target_apt in apt_names:
            query_data, reduced_proto = split_prototype(
                prototype_paths[target_apt], QUERY_RATIO, seed
            )
            query_data["_trial"] = trial + 1

            result = run_single_attribution(
                target_apt, query_data, reduced_proto, prototype_paths
            )

            qname = result.query_name
            all_results.append(result)
            ground_truth[qname] = target_apt

            # 單次輸出
            match_str = result.best_match or "Unknown"
            correct_sym = "✓" if result.best_match == target_apt else "✗"
            top_r = result.rankings[0] if result.rankings else {}
            print(
                f"  {correct_sym} query={target_apt:<15s}  "
                f"predicted={match_str:<15s}  "
                f"score={result.best_score:.4f}  "
                f"L1={top_r.get('level1_score',0):.3f}  "
                f"L2={top_r.get('level2_score',0):.3f}  "
                f"L3={top_r.get('level3_score',0):.3f}  "
                f"(query_nodes={len(query_data['nodes'])},"
                f"query_edges={len(query_data['edges'])})"
            )

    return all_results, ground_truth


# ── 實驗 2：消融實驗 ────────────────────────────────────────────────────────

def experiment_ablation(
    apt_names: list[str],
    prototype_paths: dict[str, Path],
) -> list[dict]:
    """
    固定 seed=RANDOM_SEED，測試不同權重組合。
    """
    print(f"\n{'='*70}")
    print("  實驗 2：消融實驗（Ablation Study）")
    print(f"{'='*70}")

    weight_configs = [
        ("L1 only",   {"level1": 1.00, "level2": 0.00, "level3": 0.00}),
        ("L1+L2",     {"level1": 0.55, "level2": 0.45, "level3": 0.00}),
        ("L1+L2+L3",  {"level1": 0.40, "level2": 0.35, "level3": 0.25}),
        ("Equal",     {"level1": 0.33, "level2": 0.33, "level3": 0.34}),
        ("L2 heavy",  {"level1": 0.20, "level2": 0.60, "level3": 0.20}),
    ]

    evaluator = CTIEvaluator()
    ablation_results: list[dict] = []

    for config_name, weights in weight_configs:
        c_results: list = []
        c_gt: dict[str, str] = {}

        for trial in range(NUM_TRIALS):
            seed = RANDOM_SEED + trial
            for target_apt in apt_names:
                query_data, reduced_proto = split_prototype(
                    prototype_paths[target_apt], QUERY_RATIO, seed
                )
                query_data["_trial"] = trial + 1

                result = run_single_attribution(
                    target_apt, query_data, reduced_proto, prototype_paths,
                    weights=weights,
                )
                result_name = f"{target_apt}_trial{trial+1}"
                # 修正 query_name 以匹配 ground_truth key
                result.query_name = result_name
                c_results.append(result)
                c_gt[result_name] = target_apt

        metrics = evaluator.evaluate_attribution(c_results, c_gt)
        row = {
            "config": config_name,
            "weights": weights,
            "top1":    metrics.get("top1_accuracy", 0),
            "top3":    metrics.get("top3_accuracy", 0),
            "mrr":     metrics.get("mean_reciprocal_rank", 0),
        }
        ablation_results.append(row)
        print(
            f"  {config_name:<12s}  "
            f"Top-1={row['top1']:.4f}  "
            f"Top-3={row['top3']:.4f}  "
            f"MRR={row['mrr']:.4f}  "
            f"weights={weights}"
        )

    return ablation_results


# ── 實驗 3：分數分布分析 ────────────────────────────────────────────────────

def experiment_score_distribution(
    all_results: list,
    ground_truth: dict[str, str],
) -> dict:
    """
    統計正確歸因 vs 錯誤歸因的分數分布。
    """
    print(f"\n{'='*70}")
    print("  實驗 3：分數分布（正確 vs 錯誤歸因）")
    print(f"{'='*70}")

    correct_scores: list[float] = []
    wrong_scores: list[float] = []

    for result in all_results:
        true_apt = ground_truth.get(result.query_name)
        if not true_apt:
            continue
        for r in result.rankings:
            if r["apt_name"] == true_apt:
                correct_scores.append(r["overall_score"])
            else:
                wrong_scores.append(r["overall_score"])

    stats: dict = {}
    if correct_scores and wrong_scores:
        stats = {
            "correct_mean": float(np.mean(correct_scores)),
            "correct_std":  float(np.std(correct_scores)),
            "correct_min":  float(np.min(correct_scores)),
            "correct_max":  float(np.max(correct_scores)),
            "wrong_mean":   float(np.mean(wrong_scores)),
            "wrong_std":    float(np.std(wrong_scores)),
            "wrong_min":    float(np.min(wrong_scores)),
            "wrong_max":    float(np.max(wrong_scores)),
            "gap":          float(np.mean(correct_scores) - np.mean(wrong_scores)),
        }
        print(
            f"\n  正確歸因分數  "
            f"mean={stats['correct_mean']:.4f}  "
            f"std={stats['correct_std']:.4f}  "
            f"min={stats['correct_min']:.4f}  "
            f"max={stats['correct_max']:.4f}"
        )
        print(
            f"  錯誤歸因分數  "
            f"mean={stats['wrong_mean']:.4f}  "
            f"std={stats['wrong_std']:.4f}  "
            f"min={stats['wrong_min']:.4f}  "
            f"max={stats['wrong_max']:.4f}"
        )
        gap = stats["gap"]
        print(f"\n  正確/錯誤分數差距 (gap): {gap:.4f}")
        if gap > 0.1:
            print("  → 分數有區分度，系統可行 ✓")
        elif gap > 0.02:
            print("  → 分數有輕微區分度，建議增加更多 prototype ⚠")
        else:
            print("  → ⚠️ 分數區分度不足，需要調整權重或增加資料")

        # 各 APT 正確分數細分
        print("\n  各 APT 正確分數：")
        per_apt_correct: dict[str, list[float]] = defaultdict(list)
        for result in all_results:
            true_apt = ground_truth.get(result.query_name)
            if not true_apt:
                continue
            for r in result.rankings:
                if r["apt_name"] == true_apt:
                    per_apt_correct[true_apt].append(r["overall_score"])
        for apt, scores in sorted(per_apt_correct.items()):
            print(
                f"    {apt:<15s}  mean={np.mean(scores):.4f}  "
                f"std={np.std(scores):.4f}  n={len(scores)}"
            )
    else:
        print("  分數資料不足，無法計算分布")

    return stats


# ── 評估報告 ───────────────────────────────────────────────────────────────

def print_eval_report(
    all_results: list,
    ground_truth: dict[str, str],
) -> dict:
    """
    用 CTIEvaluator 評估並印出完整報告。
    """
    print(f"\n{'='*70}")
    print("  歸因評估結果（彙整）")
    print(f"{'='*70}")

    evaluator = CTIEvaluator()
    metrics = evaluator.evaluate_attribution(all_results, ground_truth)

    if "error" in metrics:
        print(f"  評估失敗: {metrics['error']}")
        return metrics

    print(f"\n  Top-1 Accuracy: {metrics['top1_accuracy']:.4f}")
    print(f"  Top-3 Accuracy: {metrics['top3_accuracy']:.4f}")
    print(f"  Top-5 Accuracy: {metrics['top5_accuracy']:.4f}")
    print(f"  MRR:            {metrics['mean_reciprocal_rank']:.4f}")

    print("\n  各 APT 歸因表現:")
    for apt, stats in sorted(metrics.get("per_apt_results", {}).items()):
        print(
            f"    {apt:<15s}  "
            f"Top-1={stats['top1_accuracy']:.3f}  "
            f"Top-3={stats['top3_accuracy']:.3f}  "
            f"(n={stats['total']})"
        )

    print("\n  混淆矩陣:")
    labels = metrics["confusion_matrix"]["labels"]
    matrix = metrics["confusion_matrix"]["matrix"]
    col_w = max(len(l) for l in labels) + 2
    header = "  真實↓ 預測→  " + "  ".join(f"{l:>{col_w}}" for l in labels)
    print(header)
    for i, row in enumerate(matrix):
        row_str = f"  {labels[i]:<15s}" + "  ".join(f"{v:{col_w}d}" for v in row)
        print(row_str)

    return metrics


# ── 實驗 4：Holdout IoC 歸因 ───────────────────────────────────────────────

def experiment_holdout(
    apt_names: list[str],
    prototype_paths: dict[str, Path],
    holdout_sizes: list[int] | None = None,
) -> list[dict]:
    """
    Holdout IoC 歸因實驗：模擬真實場景。

    設計：
        - 從 APT_A 的完整 prototype 中，隨機抽取 N 個 IoC 建立 query
        - prototype pool 只包含其他 APT 的完整 prototype（不含 APT_A 自己）
        - 目標：看系統能否把這 N 個 IoC 歸因到 APT_A

    與 Leave-One-Out 的差別：
        - query 的 IoC value 直接來自 prototype → L1 有機會 > 0
        - prototype pool 不含 APT_A 本身 → 需要靠 L2/L3 的屬性相似度歸因

    用途：展示 L1 在真實案例中的區分力，並驗證系統的「開放集歸因」能力。
    """
    if holdout_sizes is None:
        holdout_sizes = [5, 10, 20]

    print(f"\n{'='*70}")
    print("  實驗 4：Holdout IoC 歸因（開放集場景）")
    print(f"  APT 清單: {apt_names}")
    print(f"  每次 holdout 抽取 N ∈ {holdout_sizes} 個 IoC，prototype pool 不含自己")
    print(f"{'='*70}")

    evaluator = CTIEvaluator()
    all_holdout_results: list[dict] = []

    for n_holdout in holdout_sizes:
        h_results: list = []
        h_gt: dict[str, str] = {}

        for trial in range(NUM_TRIALS):
            seed = RANDOM_SEED + trial
            random.seed(seed)

            for target_apt in apt_names:
                # 載入完整 prototype
                with open(prototype_paths[target_apt], encoding="utf-8") as f:
                    full_data = json.load(f)
                all_nodes = full_data["nodes"]
                all_edges = full_data["edges"]

                # 隨機抽 n_holdout 個節點作為 query（只抽有 value 的節點）
                valid_nodes = [
                    n for n in all_nodes
                    if n.get("type") not in ("cti", None)
                    and n.get("value")
                ]
                n_sample = min(n_holdout, len(valid_nodes))
                if n_sample < 1:
                    continue
                query_nodes_data = random.sample(valid_nodes, n_sample)
                query_node_ids = {n["id"] for n in query_nodes_data}
                query_edges_data = [
                    e for e in all_edges
                    if e["source"] in query_node_ids and e["target"] in query_node_ids
                ]

                # 建立只含其他實驗組 APT 的 attributor
                allowed_apts = set(apt_names)
                attributor = APTAttributor(
                    prototype_dir=str(PROTOTYPE_DIR),
                    threshold=0.05,   # 極低門檻，確保能輸出排名
                    weights=None,
                )
                _filter_prototype_pool(attributor, allowed_apts)
                # 移除 target APT 自己（模擬「未知 APT」場景）
                if target_apt in attributor.prototypes:
                    del attributor.prototypes[target_apt]

                if not attributor.prototypes:
                    continue

                query_name = f"holdout_{target_apt}_N{n_holdout}_t{trial+1}"
                result = attributor.attribute(
                    query_nodes=query_nodes_data,
                    query_edges=query_edges_data,
                    query_name=query_name,
                    top_k=len(apt_names) - 1,
                )
                h_results.append(result)
                h_gt[query_name] = target_apt

                # 單次印出 L1 分數（這個實驗的重點）
                top_r = result.rankings[0] if result.rankings else {}
                match_str = result.best_match or "Unknown"
                correct_sym = "✓" if result.best_match == target_apt else "✗"
                # 注意：因為 prototype pool 不含 target_apt，
                # top-1 若能匹配到正確 APT 代表有其他 APT 的 prototype 恰好相似
                # 這裡的「正確」定義是：best_match 恰好是 target_apt（不太可能）
                # 更有意義的是看 L1 分數（有無 IoC 共享）
                print(
                    f"  N={n_holdout:2d}  t={trial+1}  {target_apt:<15s}  "
                    f"best={match_str:<15s}  "
                    f"L1={top_r.get('level1_score',0):.3f}  "
                    f"L2={top_r.get('level2_score',0):.3f}  "
                    f"L3={top_r.get('level3_score',0):.3f}  "
                    f"score={result.best_score:.4f}"
                )

        # 統計這個 N 值的 L1 分數分布
        l1_scores = [r.rankings[0]["level1_score"] for r in h_results if r.rankings]
        l2_scores = [r.rankings[0]["level2_score"] for r in h_results if r.rankings]
        if l1_scores:
            row = {
                "n_holdout":  n_holdout,
                "l1_mean":    float(np.mean(l1_scores)),
                "l1_nonzero": sum(1 for s in l1_scores if s > 0),
                "l1_total":   len(l1_scores),
                "l2_mean":    float(np.mean(l2_scores)),
            }
            all_holdout_results.append(row)
            print(
                f"\n  [N={n_holdout}] L1 mean={row['l1_mean']:.4f}  "
                f"非零次數={row['l1_nonzero']}/{row['l1_total']}  "
                f"L2 mean={row['l2_mean']:.4f}\n"
            )

    # 摘要
    print(f"\n  Holdout 實驗摘要（L1 是否有訊號）：")
    print(f"  {'N':>4}  {'L1 mean':>8}  {'L1 非零':>8}  {'L2 mean':>8}")
    for row in all_holdout_results:
        print(
            f"  {row['n_holdout']:>4}  {row['l1_mean']:>8.4f}  "
            f"  {row['l1_nonzero']:>3}/{row['l1_total']:<3}  "
            f"{row['l2_mean']:>8.4f}"
        )

    return all_holdout_results


# ── 主程式 ─────────────────────────────────────────────────────────────────

def main() -> None:
    print("\n" + "╔" + "═"*68 + "╗")
    print("║  DeepPath 第一輪歸因驗證實驗" + " "*40 + "║")
    print("╚" + "═"*68 + "╝")

    # 載入有效 prototype
    print("\n載入 prototype...")
    prototype_paths = load_prototypes_meta()
    apt_names = sorted(prototype_paths.keys())

    if len(apt_names) < 2:
        print("需要至少 2 個有 vt_relationships 邊的 prototype。")
        sys.exit(1)

    print(f"有效 prototype（{len(apt_names)} 個）: {apt_names}")

    # 印出各 prototype 基本資訊
    print("\n  各 prototype 大小：")
    for apt in apt_names:
        with open(prototype_paths[apt], encoding="utf-8") as f:
            d = json.load(f)
        print(
            f"    {apt:<15s}  nodes={d['node_count']:4d}  "
            f"edges={d['edge_count']:4d}  "
            f"edge_source={d['edge_source']}"
        )

    # 確認 prototype pool（驗證不含非實驗組 APT）
    print(f"\n  實驗組 prototype pool: {apt_names}")

    # ── 實驗 1 ────────────────────────────────────────────────────────────
    all_results, ground_truth = experiment_leave_one_out(apt_names, prototype_paths)

    # ── 評估 ──────────────────────────────────────────────────────────────
    metrics = print_eval_report(all_results, ground_truth)

    # ── 實驗 2 ────────────────────────────────────────────────────────────
    ablation = experiment_ablation(apt_names, prototype_paths)

    # ── 實驗 3 ────────────────────────────────────────────────────────────
    score_stats = experiment_score_distribution(all_results, ground_truth)

    # ── 實驗 4 ────────────────────────────────────────────────────────────
    holdout_stats = experiment_holdout(apt_names, prototype_paths)

    # ── 儲存結果 ──────────────────────────────────────────────────────────
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    output = {
        "experiment_config": {
            "num_trials":   NUM_TRIALS,
            "query_ratio":  QUERY_RATIO,
            "apt_names":    apt_names,
            "random_seed":  RANDOM_SEED,
        },
        "metrics":            metrics if "error" not in metrics else {},
        "ablation_results":   ablation,
        "score_distribution": score_stats,
        "holdout_results":    holdout_stats,
    }
    out_path = OUTPUT_DIR / "validation_results.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=2, default=str)
    print(f"\n結果已儲存至: {out_path}")
    print()


if __name__ == "__main__":
    main()
