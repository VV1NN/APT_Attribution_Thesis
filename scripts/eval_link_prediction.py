#!/usr/bin/env python3
"""Evaluation harness for link prediction.

Implements type-constrained filtered ranking with MRR, Hits@1, Hits@10.
Reports per-relation and aggregate metrics.

Usage:
    from eval_link_prediction import LinkPredictionEvaluator
    evaluator = LinkPredictionEvaluator(split_data, type_node_ids)
    results = evaluator.evaluate(score_fn)
"""

from __future__ import annotations

import json
import time
from collections import defaultdict
from pathlib import Path

import numpy as np

SPLITS_DIR = Path(__file__).resolve().parent / "splits"


class LinkPredictionEvaluator:
    """Type-constrained filtered ranking evaluator."""

    def __init__(
        self,
        split_data: dict,
        type_node_ids: dict[str, list[str]],
    ):
        """
        Args:
            split_data: Output from build_splits.py (protocol_A_random.json etc.)
            type_node_ids: node_type → list of node IDs
        """
        self.train_triples = [tuple(t) for t in split_data["train"]]
        self.valid_triples = [tuple(t) for t in split_data["valid"]]
        self.test_triples = [tuple(t) for t in split_data["test"]]
        self.rel_tail_types = split_data["relation_tail_types"]

        # Build positive set for filtering
        all_triples = self.train_triples + self.valid_triples + self.test_triples
        self.positive_set: set[tuple[str, str, str]] = set(all_triples)

        # Type constraint: relation → list of candidate tail IDs
        self.rel_candidates: dict[str, list[str]] = {}
        for rel, tail_type in self.rel_tail_types.items():
            if tail_type in type_node_ids:
                self.rel_candidates[rel] = type_node_ids[tail_type]
            else:
                self.rel_candidates[rel] = []

        # Node ID → index within candidate list (for fast lookup)
        self.rel_cand_idx: dict[str, dict[str, int]] = {}
        for rel, cands in self.rel_candidates.items():
            self.rel_cand_idx[rel] = {nid: i for i, nid in enumerate(cands)}

    def evaluate(
        self,
        score_fn,
        split: str = "test",
        max_edges: int | None = None,
        verbose: bool = True,
    ) -> dict:
        """Evaluate a scoring function.

        Args:
            score_fn: Callable(head_id, relation, candidate_tail_ids) → np.ndarray of scores
                      Returns a score for each candidate tail.
            split: "test" or "valid"
            max_edges: Limit evaluation to first N edges (for debugging)
            verbose: Print progress

        Returns:
            Dict with per-relation and aggregate metrics.
        """
        triples = self.test_triples if split == "test" else self.valid_triples
        if max_edges:
            triples = triples[:max_edges]

        per_rel_ranks: dict[str, list[int]] = defaultdict(list)
        all_ranks: list[int] = []
        skipped = 0
        t0 = time.time()

        for i, (head, rel, tail) in enumerate(triples):
            candidates = self.rel_candidates.get(rel, [])
            if not candidates:
                skipped += 1
                continue

            # Check tail is in candidate set
            if tail not in self.rel_cand_idx.get(rel, {}):
                skipped += 1
                continue

            # Score all candidates
            scores = score_fn(head, rel, candidates)

            # Filtered ranking: set scores of known positives to -inf
            # (except the target itself)
            for j, cand in enumerate(candidates):
                if cand != tail and (head, rel, cand) in self.positive_set:
                    scores[j] = -np.inf

            # Rank (descending score)
            target_idx = self.rel_cand_idx[rel][tail]
            target_score = scores[target_idx]
            # Rank = number of candidates with strictly higher score + 1
            rank = int(np.sum(scores > target_score)) + 1

            per_rel_ranks[rel].append(rank)
            all_ranks.append(rank)

            if verbose and (i + 1) % 500 == 0:
                elapsed = time.time() - t0
                print(f"  [{i+1}/{len(triples)}] {elapsed:.1f}s elapsed, avg MRR so far: {np.mean(1.0 / np.array(all_ranks)):.4f}")

        elapsed = time.time() - t0

        # Compute metrics
        results = {
            "split": split,
            "total_evaluated": len(all_ranks),
            "skipped": skipped,
            "elapsed_seconds": round(elapsed, 1),
        }

        if all_ranks:
            ranks_arr = np.array(all_ranks, dtype=np.float64)
            results["aggregate"] = {
                "MRR": round(float(np.mean(1.0 / ranks_arr)), 6),
                "Hits@1": round(float(np.mean(ranks_arr <= 1)), 6),
                "Hits@3": round(float(np.mean(ranks_arr <= 3)), 6),
                "Hits@10": round(float(np.mean(ranks_arr <= 10)), 6),
                "mean_rank": round(float(np.mean(ranks_arr)), 2),
                "median_rank": round(float(np.median(ranks_arr)), 2),
            }

        results["per_relation"] = {}
        for rel in sorted(per_rel_ranks.keys()):
            ranks = np.array(per_rel_ranks[rel], dtype=np.float64)
            n_cands = len(self.rel_candidates.get(rel, []))
            results["per_relation"][rel] = {
                "count": len(ranks),
                "candidate_pool_size": n_cands,
                "MRR": round(float(np.mean(1.0 / ranks)), 6),
                "Hits@1": round(float(np.mean(ranks <= 1)), 6),
                "Hits@3": round(float(np.mean(ranks <= 3)), 6),
                "Hits@10": round(float(np.mean(ranks <= 10)), 6),
                "mean_rank": round(float(np.mean(ranks)), 2),
                "median_rank": round(float(np.median(ranks)), 2),
            }

        return results


def load_split(name: str) -> dict:
    """Load a split file."""
    path = SPLITS_DIR / f"{name}.json"
    with open(path) as f:
        return json.load(f)


def load_type_node_ids() -> dict[str, list[str]]:
    """Load type → node ID mapping."""
    path = SPLITS_DIR / "type_node_ids.json"
    with open(path) as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# Convenience: run evaluation with a score function and print results
# ---------------------------------------------------------------------------

def print_results(results: dict) -> None:
    """Pretty-print evaluation results."""
    print(f"\n{'='*65}")
    print(f"  Link Prediction Results ({results['split']})")
    print(f"  Evaluated: {results['total_evaluated']:,} edges | Skipped: {results['skipped']} | Time: {results['elapsed_seconds']}s")
    print(f"{'='*65}")

    if "aggregate" in results:
        agg = results["aggregate"]
        print(f"\n  Aggregate:")
        print(f"    MRR:       {agg['MRR']:.4f}")
        print(f"    Hits@1:    {agg['Hits@1']:.4f}")
        print(f"    Hits@3:    {agg['Hits@3']:.4f}")
        print(f"    Hits@10:   {agg['Hits@10']:.4f}")
        print(f"    Mean Rank: {agg['mean_rank']:.1f}")

    print(f"\n  Per-Relation:")
    print(f"  {'Relation':<25s} {'Count':>6s} {'Pool':>7s} {'MRR':>7s} {'H@1':>6s} {'H@10':>6s} {'MeanR':>8s}")
    print(f"  {'-'*25} {'-'*6} {'-'*7} {'-'*7} {'-'*6} {'-'*6} {'-'*8}")
    for rel, m in sorted(results["per_relation"].items(), key=lambda x: -x[1]["MRR"]):
        print(
            f"  {rel:<25s} {m['count']:>6d} {m['candidate_pool_size']:>7d} "
            f"{m['MRR']:>7.4f} {m['Hits@1']:>6.3f} {m['Hits@10']:>6.3f} {m['mean_rank']:>8.1f}"
        )
    print()
