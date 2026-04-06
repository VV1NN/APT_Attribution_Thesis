#!/usr/bin/env python3
"""Non-neural baselines + KGE for link prediction signal verification.

Baselines:
  1. Random      — random scores
  2. Degree      — score = target node degree (popularity)
  3. DistMult    — learnable bilinear KGE
  4. ComplEx     — complex-valued KGE

Usage:
    uv run python scripts/baselines_link_prediction.py [--protocol A_random] [--epochs 100] [--dim 128]
"""

from __future__ import annotations

import argparse
import json
import time
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim

from eval_link_prediction import (
    LinkPredictionEvaluator,
    load_split,
    load_type_node_ids,
    print_results,
)

SCRIPTS = Path(__file__).resolve().parent
RESULTS_DIR = SCRIPTS / "results"


# ---------------------------------------------------------------------------
# Index builder
# ---------------------------------------------------------------------------

class TripleIndex:
    """Maps string node IDs and relations to integer indices."""

    def __init__(self, triples: list[tuple[str, str, str]]):
        nodes: set[str] = set()
        rels: set[str] = set()
        for h, r, t in triples:
            nodes.add(h)
            nodes.add(t)
            rels.add(r)
        self.node2idx = {n: i for i, n in enumerate(sorted(nodes))}
        self.idx2node = {i: n for n, i in self.node2idx.items()}
        self.rel2idx = {r: i for i, r in enumerate(sorted(rels))}
        self.idx2rel = {i: r for r, i in self.rel2idx.items()}
        self.n_nodes = len(self.node2idx)
        self.n_rels = len(self.rel2idx)

    def triples_to_tensor(self, triples: list[tuple[str, str, str]]) -> torch.LongTensor:
        """Convert triples to (N, 3) tensor of [head_idx, rel_idx, tail_idx]."""
        arr = []
        for h, r, t in triples:
            hi = self.node2idx.get(h)
            ri = self.rel2idx.get(r)
            ti = self.node2idx.get(t)
            if hi is not None and ri is not None and ti is not None:
                arr.append([hi, ri, ti])
        return torch.LongTensor(arr)


# ---------------------------------------------------------------------------
# Baseline 1: Random
# ---------------------------------------------------------------------------

def random_score_fn(head: str, rel: str, candidates: list[str]) -> np.ndarray:
    """Random scores."""
    return np.random.randn(len(candidates))


# ---------------------------------------------------------------------------
# Baseline 2: Degree
# ---------------------------------------------------------------------------

class DegreeScorer:
    """Score = target node in-degree (popularity)."""

    def __init__(self, triples: list[tuple[str, str, str]]):
        self.degree: Counter[str] = Counter()
        for h, r, t in triples:
            self.degree[t] += 1
            self.degree[h] += 1

    def __call__(self, head: str, rel: str, candidates: list[str]) -> np.ndarray:
        return np.array([self.degree.get(c, 0) for c in candidates], dtype=np.float64)


# ---------------------------------------------------------------------------
# KGE: DistMult
# ---------------------------------------------------------------------------

class DistMult(nn.Module):
    def __init__(self, n_nodes: int, n_rels: int, dim: int):
        super().__init__()
        self.node_emb = nn.Embedding(n_nodes, dim)
        self.rel_emb = nn.Embedding(n_rels, dim)
        nn.init.xavier_uniform_(self.node_emb.weight)
        nn.init.xavier_uniform_(self.rel_emb.weight)

    def forward(self, h_idx: torch.Tensor, r_idx: torch.Tensor, t_idx: torch.Tensor) -> torch.Tensor:
        h = self.node_emb(h_idx)
        r = self.rel_emb(r_idx)
        t = self.node_emb(t_idx)
        return (h * r * t).sum(dim=-1)


# ---------------------------------------------------------------------------
# KGE: ComplEx
# ---------------------------------------------------------------------------

class ComplEx(nn.Module):
    def __init__(self, n_nodes: int, n_rels: int, dim: int):
        super().__init__()
        self.re_node = nn.Embedding(n_nodes, dim)
        self.im_node = nn.Embedding(n_nodes, dim)
        self.re_rel = nn.Embedding(n_rels, dim)
        self.im_rel = nn.Embedding(n_rels, dim)
        for emb in [self.re_node, self.im_node, self.re_rel, self.im_rel]:
            nn.init.xavier_uniform_(emb.weight)

    def forward(self, h_idx: torch.Tensor, r_idx: torch.Tensor, t_idx: torch.Tensor) -> torch.Tensor:
        h_re, h_im = self.re_node(h_idx), self.im_node(h_idx)
        r_re, r_im = self.re_rel(r_idx), self.im_rel(r_idx)
        t_re, t_im = self.re_node(t_idx), self.im_node(t_idx)
        return (
            (h_re * r_re * t_re).sum(-1)
            + (h_im * r_re * t_im).sum(-1)
            + (h_re * r_im * t_im).sum(-1)
            - (h_im * r_im * t_re).sum(-1)
        )


# ---------------------------------------------------------------------------
# Training loop for KGE
# ---------------------------------------------------------------------------

def train_kge(
    model: nn.Module,
    index: TripleIndex,
    train_tensor: torch.LongTensor,
    valid_tensor: torch.LongTensor | None = None,
    epochs: int = 100,
    batch_size: int = 4096,
    lr: float = 0.001,
    neg_ratio: int = 10,
    device: str = "cpu",
) -> list[float]:
    """Train KGE with negative sampling + binary cross-entropy."""
    model = model.to(device)
    train_tensor = train_tensor.to(device)
    optimizer = optim.Adam(model.parameters(), lr=lr)
    n_nodes = index.n_nodes
    losses = []

    for epoch in range(epochs):
        model.train()
        perm = torch.randperm(train_tensor.size(0), device=device)
        epoch_loss = 0.0
        n_batches = 0

        for start in range(0, train_tensor.size(0), batch_size):
            batch = train_tensor[perm[start : start + batch_size]]
            h, r, t = batch[:, 0], batch[:, 1], batch[:, 2]

            # Positive scores
            pos_scores = model(h, r, t)

            # Negative sampling (corrupt tail, type-unconstrained for simplicity)
            neg_t = torch.randint(0, n_nodes, (len(batch) * neg_ratio,), device=device)
            neg_h = h.repeat(neg_ratio)
            neg_r = r.repeat(neg_ratio)
            neg_scores = model(neg_h, neg_r, neg_t)

            # BCE loss
            pos_labels = torch.ones_like(pos_scores)
            neg_labels = torch.zeros_like(neg_scores)
            scores = torch.cat([pos_scores, neg_scores])
            labels = torch.cat([pos_labels, neg_labels])
            loss = nn.functional.binary_cross_entropy_with_logits(scores, labels)

            optimizer.zero_grad()
            loss.backward()
            optimizer.step()

            epoch_loss += loss.item()
            n_batches += 1

        avg_loss = epoch_loss / max(n_batches, 1)
        losses.append(avg_loss)

        if (epoch + 1) % 10 == 0 or epoch == 0:
            print(f"  Epoch {epoch+1:3d}/{epochs} | Loss: {avg_loss:.4f}")

    return losses


def make_kge_score_fn(model: nn.Module, index: TripleIndex, device: str = "cpu"):
    """Create a score function compatible with the evaluator."""
    model.eval()

    def score_fn(head: str, rel: str, candidates: list[str]) -> np.ndarray:
        h_idx = index.node2idx.get(head)
        r_idx = index.rel2idx.get(rel)
        if h_idx is None or r_idx is None:
            return np.zeros(len(candidates))

        # Map candidates to indices (unknown nodes get score -inf)
        cand_indices = []
        valid_mask = []
        for c in candidates:
            ci = index.node2idx.get(c)
            if ci is not None:
                cand_indices.append(ci)
                valid_mask.append(True)
            else:
                cand_indices.append(0)  # placeholder
                valid_mask.append(False)

        with torch.no_grad():
            h_t = torch.full((len(candidates),), h_idx, dtype=torch.long, device=device)
            r_t = torch.full((len(candidates),), r_idx, dtype=torch.long, device=device)
            t_t = torch.tensor(cand_indices, dtype=torch.long, device=device)
            scores = model(h_t, r_t, t_t).cpu().numpy()

        # Set invalid candidates to -inf
        for i, valid in enumerate(valid_mask):
            if not valid:
                scores[i] = -np.inf

        return scores

    return score_fn


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--protocol", default="protocol_A_random", help="Split protocol name")
    parser.add_argument("--epochs", type=int, default=100, help="KGE training epochs")
    parser.add_argument("--dim", type=int, default=128, help="Embedding dimension")
    parser.add_argument("--lr", type=float, default=0.001)
    parser.add_argument("--batch-size", type=int, default=4096)
    parser.add_argument("--max-eval", type=int, default=None, help="Limit eval edges (debug)")
    args = parser.parse_args()

    # Load data
    split_data = load_split(args.protocol)
    type_node_ids = load_type_node_ids()
    evaluator = LinkPredictionEvaluator(split_data, type_node_ids)

    all_triples = (
        [tuple(t) for t in split_data["train"]]
        + [tuple(t) for t in split_data["valid"]]
        + [tuple(t) for t in split_data["test"]]
    )
    train_triples = [tuple(t) for t in split_data["train"]]
    index = TripleIndex(all_triples)
    train_tensor = index.triples_to_tensor(train_triples)

    print(f"Protocol: {args.protocol}")
    print(f"Nodes: {index.n_nodes:,} | Rels: {index.n_rels} | Train triples: {train_tensor.size(0):,}")

    device = "mps" if torch.backends.mps.is_available() else "cuda" if torch.cuda.is_available() else "cpu"
    print(f"Device: {device}")

    all_results = {}

    # --- Baseline 1: Random ---
    print("\n" + "=" * 60)
    print("  BASELINE: Random")
    print("=" * 60)
    results_random = evaluator.evaluate(random_score_fn, max_edges=args.max_eval)
    print_results(results_random)
    all_results["random"] = results_random

    # --- Baseline 2: Degree ---
    print("\n" + "=" * 60)
    print("  BASELINE: Degree")
    print("=" * 60)
    degree_scorer = DegreeScorer(train_triples)
    results_degree = evaluator.evaluate(degree_scorer, max_edges=args.max_eval)
    print_results(results_degree)
    all_results["degree"] = results_degree

    # --- DistMult ---
    print("\n" + "=" * 60)
    print(f"  KGE: DistMult (dim={args.dim}, epochs={args.epochs})")
    print("=" * 60)
    distmult = DistMult(index.n_nodes, index.n_rels, args.dim)
    train_kge(distmult, index, train_tensor, epochs=args.epochs, batch_size=args.batch_size, lr=args.lr, device=device)
    distmult_score_fn = make_kge_score_fn(distmult, index, device=device)
    results_distmult = evaluator.evaluate(distmult_score_fn, max_edges=args.max_eval)
    print_results(results_distmult)
    all_results["distmult"] = results_distmult

    # --- ComplEx ---
    print("\n" + "=" * 60)
    print(f"  KGE: ComplEx (dim={args.dim}, epochs={args.epochs})")
    print("=" * 60)
    complex_model = ComplEx(index.n_nodes, index.n_rels, args.dim)
    train_kge(complex_model, index, train_tensor, epochs=args.epochs, batch_size=args.batch_size, lr=args.lr, device=device)
    complex_score_fn = make_kge_score_fn(complex_model, index, device=device)
    results_complex = evaluator.evaluate(complex_score_fn, max_edges=args.max_eval)
    print_results(results_complex)
    all_results["complex"] = results_complex

    # --- Save results ---
    RESULTS_DIR.mkdir(exist_ok=True)
    out_path = RESULTS_DIR / f"lp_baselines_{args.protocol}.json"
    # Simplify for JSON serialization
    summary = {}
    for name, res in all_results.items():
        summary[name] = {
            "aggregate": res.get("aggregate", {}),
            "per_relation": res.get("per_relation", {}),
            "total_evaluated": res.get("total_evaluated", 0),
            "elapsed_seconds": res.get("elapsed_seconds", 0),
        }
    with open(out_path, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\nResults saved to {out_path}")


if __name__ == "__main__":
    main()
