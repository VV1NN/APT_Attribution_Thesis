#!/usr/bin/env python3
"""R-GCN encoder + DistMult/ComplEx decoder for link prediction.

Uses node features from VT metadata (type_tag, detection_ratio, registrar, etc.)
projected per-type into a shared embedding space, then 2-layer R-GCN with basis
decomposition, decoded via DistMult or ComplEx scoring.

Usage:
    uv run python scripts/rgcn_link_prediction.py --protocol protocol_A_random --epochs 100 --dim 128
    uv run python scripts/rgcn_link_prediction.py --decoder complex --epochs 150 --dim 128
"""

from __future__ import annotations

import argparse
import json
import math
import time
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import RGCNConv

from eval_link_prediction import (
    LinkPredictionEvaluator,
    load_split,
    load_type_node_ids,
    print_results,
)

SCRIPTS = Path(__file__).resolve().parent
KG_PATH = SCRIPTS.parent / "knowledge_graphs" / "master" / "merged_kg.json"
RESULTS_DIR = SCRIPTS / "results"

# ---------------------------------------------------------------------------
# Node Feature Builder
# ---------------------------------------------------------------------------

# Top-K categorical values (rest → "OTHER")
TOP_K_TYPE_TAG = 30
TOP_K_TLD = 50
TOP_K_REGISTRAR = 50
TOP_K_COUNTRY = 50
TOP_K_ASN = 100


def _build_vocab(values: list, top_k: int) -> dict[str, int]:
    """Build categorical vocab: top-K values → idx, rest → 0 (OTHER)."""
    counts = Counter(v for v in values if v is not None)
    top = [v for v, _ in counts.most_common(top_k)]
    vocab = {"__OTHER__": 0}
    for i, v in enumerate(top):
        vocab[v] = i + 1
    return vocab


def _encode_cat(val, vocab: dict[str, int]) -> int:
    if val is None:
        return 0
    return vocab.get(val, 0)


def _encode_year(datestr: str | None) -> float:
    """Extract year from ISO date string, normalize to [0, 1]."""
    if not datestr:
        return 0.0
    try:
        year = int(datestr[:4])
        # Normalize: 2000=0.0, 2026=1.0
        return max(0.0, min(1.0, (year - 2000) / 26.0))
    except (ValueError, TypeError):
        return 0.0


class NodeFeatureBuilder:
    """Builds per-type feature tensors from KG node attributes."""

    def __init__(self, nodes: list[dict], node2idx: dict[str, int]):
        self.nodes = nodes
        self.node2idx = node2idx
        self.n_nodes = len(nodes)

        # Separate by type
        self.type_nodes: dict[str, list[dict]] = defaultdict(list)
        for n in nodes:
            self.type_nodes[n["type"]].append(n)

        # Build vocabularies from training data
        self._build_vocabs()

    def _build_vocabs(self):
        """Build categorical vocabularies."""
        # File: type_tag
        file_type_tags = [n["attributes"].get("type_tag") for n in self.type_nodes["file"]
                          if n.get("vt_found")]
        self.vocab_type_tag = _build_vocab(file_type_tags, TOP_K_TYPE_TAG)

        # Domain: tld, registrar
        domain_tlds = [n["attributes"].get("tld") for n in self.type_nodes["domain"]
                       if n.get("vt_found")]
        self.vocab_tld = _build_vocab(domain_tlds, TOP_K_TLD)

        domain_registrars = [n["attributes"].get("registrar") for n in self.type_nodes["domain"]
                             if n.get("vt_found")]
        self.vocab_registrar = _build_vocab(domain_registrars, TOP_K_REGISTRAR)

        # IP: country, asn
        ip_countries = [n["attributes"].get("country") for n in self.type_nodes["ip"]
                        if n.get("vt_found")]
        self.vocab_country = _build_vocab(ip_countries, TOP_K_COUNTRY)

        ip_asns = [str(n["attributes"].get("asn")) for n in self.type_nodes["ip"]
                   if n.get("vt_found") and n["attributes"].get("asn") is not None]
        self.vocab_asn = _build_vocab(ip_asns, TOP_K_ASN)

    def file_feature_dim(self) -> int:
        """detection_ratio(1) + malicious(1) + log_size(1) + type_tag(|V|) + year(1)"""
        return 3 + len(self.vocab_type_tag) + 1

    def domain_feature_dim(self) -> int:
        """detection_ratio(1) + malicious(1) + tld(|V|) + registrar(|V|) + year(1)"""
        return 2 + len(self.vocab_tld) + len(self.vocab_registrar) + 1

    def ip_feature_dim(self) -> int:
        """detection_ratio(1) + malicious(1) + country(|V|) + asn(|V|)"""
        return 2 + len(self.vocab_country) + len(self.vocab_asn)

    def build_file_features(self) -> tuple[torch.Tensor, list[int]]:
        """Return (feature_matrix, global_indices) for file nodes."""
        indices = []
        feats = []
        for n in self.type_nodes["file"]:
            idx = self.node2idx[n["id"]]
            indices.append(idx)
            a = n.get("attributes", {})
            vt = n.get("vt_found", False)

            # Numerical
            det_ratio = float(a.get("detection_ratio", 0)) if vt else 0.0
            malicious = min(float(a.get("malicious", 0)) / 80.0, 1.0) if vt else 0.0
            size = a.get("size")
            log_size = math.log1p(size) / 25.0 if size else 0.0  # log(5GB)≈22

            # Categorical: type_tag one-hot
            tt_idx = _encode_cat(a.get("type_tag"), self.vocab_type_tag) if vt else 0
            tt_onehot = [0.0] * len(self.vocab_type_tag)
            tt_onehot[tt_idx] = 1.0

            # Year
            year = _encode_year(a.get("creation_time")) if vt else 0.0

            feats.append([det_ratio, malicious, log_size] + tt_onehot + [year])

        return torch.tensor(feats, dtype=torch.float32), indices

    def build_domain_features(self) -> tuple[torch.Tensor, list[int]]:
        """Return (feature_matrix, global_indices) for domain nodes."""
        indices = []
        feats = []
        for n in self.type_nodes["domain"]:
            idx = self.node2idx[n["id"]]
            indices.append(idx)
            a = n.get("attributes", {})
            vt = n.get("vt_found", False)

            det_ratio = float(a.get("detection_ratio", 0)) if vt else 0.0
            malicious = min(float(a.get("malicious", 0)) / 80.0, 1.0) if vt else 0.0

            tld_idx = _encode_cat(a.get("tld"), self.vocab_tld) if vt else 0
            tld_oh = [0.0] * len(self.vocab_tld)
            tld_oh[tld_idx] = 1.0

            reg_idx = _encode_cat(a.get("registrar"), self.vocab_registrar) if vt else 0
            reg_oh = [0.0] * len(self.vocab_registrar)
            reg_oh[reg_idx] = 1.0

            year = _encode_year(a.get("creation_date")) if vt else 0.0

            feats.append([det_ratio, malicious] + tld_oh + reg_oh + [year])

        return torch.tensor(feats, dtype=torch.float32), indices

    def build_ip_features(self) -> tuple[torch.Tensor, list[int]]:
        """Return (feature_matrix, global_indices) for IP nodes."""
        indices = []
        feats = []
        for n in self.type_nodes["ip"]:
            idx = self.node2idx[n["id"]]
            indices.append(idx)
            a = n.get("attributes", {})
            vt = n.get("vt_found", False)

            det_ratio = float(a.get("detection_ratio", 0)) if vt else 0.0
            malicious = min(float(a.get("malicious", 0)) / 80.0, 1.0) if vt else 0.0

            country_idx = _encode_cat(a.get("country"), self.vocab_country) if vt else 0
            country_oh = [0.0] * len(self.vocab_country)
            country_oh[country_idx] = 1.0

            asn_val = str(a.get("asn")) if a.get("asn") is not None else None
            asn_idx = _encode_cat(asn_val, self.vocab_asn) if vt else 0
            asn_oh = [0.0] * len(self.vocab_asn)
            asn_oh[asn_idx] = 1.0

            feats.append([det_ratio, malicious] + country_oh + asn_oh)

        return torch.tensor(feats, dtype=torch.float32), indices


# ---------------------------------------------------------------------------
# R-GCN Encoder
# ---------------------------------------------------------------------------

class RGCNEncoder(nn.Module):
    """2-layer R-GCN with per-type input projection + basis decomposition.

    Stores raw features as buffers and rebuilds the initial embedding on every
    forward call so the computation graph is fresh each time.
    """

    def __init__(
        self,
        n_nodes: int,
        hidden_dim: int,
        n_relations: int,
        file_feat_dim: int,
        domain_feat_dim: int,
        ip_feat_dim: int,
        n_bases: int = 4,
        dropout: float = 0.2,
    ):
        super().__init__()
        self.n_nodes = n_nodes
        self.hidden_dim = hidden_dim

        # Per-type input projections
        self.proj_file = nn.Linear(file_feat_dim, hidden_dim)
        self.proj_domain = nn.Linear(domain_feat_dim, hidden_dim)
        self.proj_ip = nn.Linear(ip_feat_dim, hidden_dim)
        # Fallback embedding for apt/email (no VT features)
        self.fallback_emb = nn.Embedding(n_nodes, hidden_dim)

        # R-GCN layers
        self.conv1 = RGCNConv(hidden_dim, hidden_dim, num_relations=n_relations, num_bases=n_bases)
        self.conv2 = RGCNConv(hidden_dim, hidden_dim, num_relations=n_relations, num_bases=n_bases)

        self.dropout = nn.Dropout(dropout)
        self.layer_norm1 = nn.LayerNorm(hidden_dim)
        self.layer_norm2 = nn.LayerNorm(hidden_dim)

        # Will be set by set_node_features()
        self._file_feats: torch.Tensor | None = None
        self._file_idx: torch.LongTensor | None = None
        self._domain_feats: torch.Tensor | None = None
        self._domain_idx: torch.LongTensor | None = None
        self._ip_feats: torch.Tensor | None = None
        self._ip_idx: torch.LongTensor | None = None

    def set_node_features(
        self,
        file_feats: torch.Tensor, file_idx: list[int],
        domain_feats: torch.Tensor, domain_idx: list[int],
        ip_feats: torch.Tensor, ip_idx: list[int],
        device: torch.device,
    ):
        """Store raw per-type features as non-parameter tensors."""
        self._file_feats = file_feats.to(device)
        self._file_idx = torch.tensor(file_idx, dtype=torch.long, device=device)
        self._domain_feats = domain_feats.to(device)
        self._domain_idx = torch.tensor(domain_idx, dtype=torch.long, device=device)
        self._ip_feats = ip_feats.to(device)
        self._ip_idx = torch.tensor(ip_idx, dtype=torch.long, device=device)

    def _build_x(self) -> torch.Tensor:
        """Build initial node embeddings (fresh computation graph each call)."""
        x = self.fallback_emb.weight.clone()

        if self._file_feats is not None and len(self._file_idx) > 0:
            x[self._file_idx] = self.proj_file(self._file_feats)
        if self._domain_feats is not None and len(self._domain_idx) > 0:
            x[self._domain_idx] = self.proj_domain(self._domain_feats)
        if self._ip_feats is not None and len(self._ip_idx) > 0:
            x[self._ip_idx] = self.proj_ip(self._ip_feats)

        return x

    def forward(
        self,
        edge_index: torch.LongTensor,
        edge_type: torch.LongTensor,
    ) -> torch.Tensor:
        """Build initial embeddings then run 2-layer R-GCN."""
        x = self._build_x()

        # Layer 1
        h = self.conv1(x, edge_index, edge_type)
        h = self.layer_norm1(h)
        h = F.relu(h)
        h = self.dropout(h)

        # Layer 2
        h = self.conv2(h, edge_index, edge_type)
        h = self.layer_norm2(h)

        return h


# ---------------------------------------------------------------------------
# Decoders
# ---------------------------------------------------------------------------

class DistMultDecoder(nn.Module):
    def __init__(self, n_rels: int, dim: int):
        super().__init__()
        self.rel_emb = nn.Embedding(n_rels, dim)
        nn.init.xavier_uniform_(self.rel_emb.weight)

    def forward(self, h_emb: torch.Tensor, r_idx: torch.Tensor, t_emb: torch.Tensor) -> torch.Tensor:
        r = self.rel_emb(r_idx)
        return (h_emb * r * t_emb).sum(dim=-1)


class ComplExDecoder(nn.Module):
    def __init__(self, n_rels: int, dim: int):
        super().__init__()
        # ComplEx uses complex-valued embeddings
        # Split node embedding into real/imag halves
        self.re_rel = nn.Embedding(n_rels, dim // 2)
        self.im_rel = nn.Embedding(n_rels, dim // 2)
        nn.init.xavier_uniform_(self.re_rel.weight)
        nn.init.xavier_uniform_(self.im_rel.weight)

    def forward(self, h_emb: torch.Tensor, r_idx: torch.Tensor, t_emb: torch.Tensor) -> torch.Tensor:
        half = h_emb.size(-1) // 2
        h_re, h_im = h_emb[..., :half], h_emb[..., half:]
        t_re, t_im = t_emb[..., :half], t_emb[..., half:]
        r_re = self.re_rel(r_idx)
        r_im = self.im_rel(r_idx)
        return (
            (h_re * r_re * t_re).sum(-1)
            + (h_im * r_re * t_im).sum(-1)
            + (h_re * r_im * t_im).sum(-1)
            - (h_im * r_im * t_re).sum(-1)
        )


# ---------------------------------------------------------------------------
# Full Model
# ---------------------------------------------------------------------------

class RGCNLinkPredictor(nn.Module):
    def __init__(self, encoder: RGCNEncoder, decoder: nn.Module):
        super().__init__()
        self.encoder = encoder
        self.decoder = decoder

    def encode(self, edge_index, edge_type):
        return self.encoder(edge_index, edge_type)

    def decode(self, node_emb, h_idx, r_idx, t_idx):
        h_emb = node_emb[h_idx]
        t_emb = node_emb[t_idx]
        return self.decoder(h_emb, r_idx, t_emb)


# ---------------------------------------------------------------------------
# Graph Builder (PyG format)
# ---------------------------------------------------------------------------

def build_pyg_graph(
    train_triples: list[tuple[str, str, str]],
    node2idx: dict[str, int],
    rel2idx: dict[str, int],
) -> tuple[torch.LongTensor, torch.LongTensor]:
    """Build edge_index (2, E) and edge_type (E,) from triples.

    Adds reverse edges (relation r → r + n_rels) for undirected message passing.
    """
    n_rels = len(rel2idx)
    src, dst, etypes = [], [], []
    for h, r, t in train_triples:
        hi = node2idx.get(h)
        ri = rel2idx.get(r)
        ti = node2idx.get(t)
        if hi is not None and ri is not None and ti is not None:
            # Forward edge
            src.append(hi)
            dst.append(ti)
            etypes.append(ri)
            # Reverse edge (separate relation type)
            src.append(ti)
            dst.append(hi)
            etypes.append(ri + n_rels)

    edge_index = torch.tensor([src, dst], dtype=torch.long)
    edge_type = torch.tensor(etypes, dtype=torch.long)
    return edge_index, edge_type


# ---------------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------------

def train_epoch(
    model: RGCNLinkPredictor,
    edge_index: torch.LongTensor,
    edge_type: torch.LongTensor,
    train_tensor: torch.LongTensor,
    n_nodes: int,
    neg_ratio: int = 10,
    batch_size: int = 4096,
    optimizer: torch.optim.Optimizer = None,
    device: torch.device = None,
) -> float:
    model.train()

    perm = torch.randperm(train_tensor.size(0), device=device)
    total_loss = 0.0
    n_batches = 0

    for start in range(0, train_tensor.size(0), batch_size):
        batch = train_tensor[perm[start:start + batch_size]]
        h, r, t = batch[:, 0], batch[:, 1], batch[:, 2]

        # Re-encode each batch (graph is freed after backward)
        node_emb = model.encode(edge_index, edge_type)

        # Positive scores
        pos_scores = model.decode(node_emb, h, r, t)

        # Negative sampling (corrupt tail)
        neg_t = torch.randint(0, n_nodes, (len(batch) * neg_ratio,), device=device)
        neg_h = h.repeat(neg_ratio)
        neg_r = r.repeat(neg_ratio)
        neg_scores = model.decode(node_emb, neg_h, neg_r, neg_t)

        # BCE loss
        scores = torch.cat([pos_scores, neg_scores])
        labels = torch.cat([
            torch.ones(len(batch), device=device),
            torch.zeros(len(batch) * neg_ratio, device=device),
        ])
        loss = F.binary_cross_entropy_with_logits(scores, labels)

        optimizer.zero_grad()
        loss.backward()
        # Gradient clipping for stability
        torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
        optimizer.step()

        total_loss += loss.item()
        n_batches += 1

    return total_loss / max(n_batches, 1)


@torch.no_grad()
def make_rgcn_score_fn(
    model: RGCNLinkPredictor,
    edge_index: torch.LongTensor,
    edge_type: torch.LongTensor,
    node2idx: dict[str, int],
    rel2idx: dict[str, int],
    device: torch.device,
):
    """Create a score function compatible with LinkPredictionEvaluator."""
    model.eval()
    node_emb = model.encode(edge_index, edge_type)

    def score_fn(head: str, rel: str, candidates: list[str]) -> np.ndarray:
        h_idx = node2idx.get(head)
        r_idx = rel2idx.get(rel)
        if h_idx is None or r_idx is None:
            return np.zeros(len(candidates))

        cand_indices = []
        valid_mask = []
        for c in candidates:
            ci = node2idx.get(c)
            if ci is not None:
                cand_indices.append(ci)
                valid_mask.append(True)
            else:
                cand_indices.append(0)
                valid_mask.append(False)

        h_t = torch.full((len(candidates),), h_idx, dtype=torch.long, device=device)
        r_t = torch.full((len(candidates),), r_idx, dtype=torch.long, device=device)
        t_t = torch.tensor(cand_indices, dtype=torch.long, device=device)

        scores = model.decode(node_emb, h_t, r_t, t_t).detach().cpu().numpy()
        for i, valid in enumerate(valid_mask):
            if not valid:
                scores[i] = -np.inf
        return scores

    return score_fn


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="R-GCN Link Prediction")
    parser.add_argument("--protocol", default="protocol_A_random")
    parser.add_argument("--epochs", type=int, default=100)
    parser.add_argument("--dim", type=int, default=128, help="Hidden dimension")
    parser.add_argument("--lr", type=float, default=0.001)
    parser.add_argument("--batch-size", type=int, default=4096)
    parser.add_argument("--n-bases", type=int, default=4, help="R-GCN basis decomposition")
    parser.add_argument("--neg-ratio", type=int, default=10)
    parser.add_argument("--dropout", type=float, default=0.2)
    parser.add_argument("--decoder", choices=["distmult", "complex"], default="distmult")
    parser.add_argument("--max-eval", type=int, default=None)
    parser.add_argument("--patience", type=int, default=15, help="Early stopping patience")
    args = parser.parse_args()

    device = torch.device(
        "mps" if torch.backends.mps.is_available()
        else "cuda" if torch.cuda.is_available()
        else "cpu"
    )
    print(f"Device: {device}")

    # ---- Load KG ----
    print("Loading KG ...")
    with open(KG_PATH) as f:
        kg = json.load(f)
    nodes = kg["nodes"]
    node2idx = {n["id"]: i for i, n in enumerate(nodes)}
    n_nodes = len(nodes)

    # ---- Load splits ----
    split_data = load_split(args.protocol)
    type_node_ids = load_type_node_ids()

    train_triples = [tuple(t) for t in split_data["train"]]
    all_triples = (
        train_triples
        + [tuple(t) for t in split_data["valid"]]
        + [tuple(t) for t in split_data["test"]]
    )

    # Build relation index
    all_rels = sorted({r for _, r, _ in all_triples})
    rel2idx = {r: i for i, r in enumerate(all_rels)}
    n_rels = len(rel2idx)
    print(f"Nodes: {n_nodes:,} | Relations: {n_rels} | Train: {len(train_triples):,}")

    # ---- Build graph (with reverse edges) ----
    edge_index, edge_type = build_pyg_graph(train_triples, node2idx, rel2idx)
    n_rels_with_rev = n_rels * 2  # forward + reverse
    edge_index = edge_index.to(device)
    edge_type = edge_type.to(device)
    print(f"Message-passing edges: {edge_index.size(1):,} (incl. reverse)")

    # ---- Build node features ----
    print("Building node features ...")
    feat_builder = NodeFeatureBuilder(nodes, node2idx)
    file_feats, file_idx = feat_builder.build_file_features()
    domain_feats, domain_idx = feat_builder.build_domain_features()
    ip_feats, ip_idx = feat_builder.build_ip_features()
    print(f"  File: {file_feats.shape} | Domain: {domain_feats.shape} | IP: {ip_feats.shape}")

    # ---- Build model ----
    encoder = RGCNEncoder(
        n_nodes=n_nodes,
        hidden_dim=args.dim,
        n_relations=n_rels_with_rev,
        file_feat_dim=feat_builder.file_feature_dim(),
        domain_feat_dim=feat_builder.domain_feature_dim(),
        ip_feat_dim=feat_builder.ip_feature_dim(),
        n_bases=args.n_bases,
        dropout=args.dropout,
    )

    if args.decoder == "distmult":
        decoder = DistMultDecoder(n_rels, args.dim)
    else:
        decoder = ComplExDecoder(n_rels, args.dim)

    model = RGCNLinkPredictor(encoder, decoder).to(device)
    n_params = sum(p.numel() for p in model.parameters() if p.requires_grad)
    print(f"Model params: {n_params:,} | Decoder: {args.decoder}")

    # ---- Build training triples tensor ----
    train_arr = []
    for h, r, t in train_triples:
        hi = node2idx.get(h)
        ri = rel2idx.get(r)
        ti = node2idx.get(t)
        if hi is not None and ri is not None and ti is not None:
            train_arr.append([hi, ri, ti])
    train_tensor = torch.LongTensor(train_arr).to(device)
    print(f"Train triples (indexed): {train_tensor.size(0):,}")

    # ---- Set node features on encoder ----
    encoder.set_node_features(
        file_feats, file_idx,
        domain_feats, domain_idx,
        ip_feats, ip_idx,
        device,
    )

    # ---- Training ----
    optimizer = torch.optim.Adam(model.parameters(), lr=args.lr)
    best_loss = float("inf")
    patience_counter = 0
    best_state = None

    print(f"\nTraining R-GCN ({args.epochs} epochs, patience={args.patience}) ...")
    t0 = time.time()

    for epoch in range(args.epochs):
        loss = train_epoch(
            model, edge_index, edge_type, train_tensor,
            n_nodes=n_nodes, neg_ratio=args.neg_ratio,
            batch_size=args.batch_size, optimizer=optimizer, device=device,
        )

        if (epoch + 1) % 10 == 0 or epoch == 0:
            elapsed = time.time() - t0
            print(f"  Epoch {epoch+1:3d}/{args.epochs} | Loss: {loss:.4f} | {elapsed:.0f}s")

        # Early stopping on training loss
        if loss < best_loss - 1e-4:
            best_loss = loss
            patience_counter = 0
            best_state = {k: v.cpu().clone() for k, v in model.state_dict().items()}
        else:
            patience_counter += 1
            if patience_counter >= args.patience:
                print(f"  Early stopping at epoch {epoch+1} (patience={args.patience})")
                break

    train_time = time.time() - t0
    print(f"Training done in {train_time:.1f}s")

    # Load best model
    if best_state:
        model.load_state_dict({k: v.to(device) for k, v in best_state.items()})

    # ---- Evaluation ----
    print("\nEvaluating ...")
    evaluator = LinkPredictionEvaluator(split_data, type_node_ids)
    score_fn = make_rgcn_score_fn(model, edge_index, edge_type, node2idx, rel2idx, device)
    results = evaluator.evaluate(score_fn, max_edges=args.max_eval)
    print_results(results)

    # ---- Save results ----
    RESULTS_DIR.mkdir(exist_ok=True)
    out_path = RESULTS_DIR / f"lp_rgcn_{args.decoder}_{args.protocol}.json"
    summary = {
        "model": f"rgcn_{args.decoder}",
        "protocol": args.protocol,
        "config": {
            "dim": args.dim,
            "n_bases": args.n_bases,
            "decoder": args.decoder,
            "epochs_trained": epoch + 1,
            "lr": args.lr,
            "neg_ratio": args.neg_ratio,
            "dropout": args.dropout,
            "n_params": n_params,
            "train_time_sec": round(train_time, 1),
        },
        "aggregate": results.get("aggregate", {}),
        "per_relation": results.get("per_relation", {}),
        "total_evaluated": results.get("total_evaluated", 0),
        "elapsed_seconds": results.get("elapsed_seconds", 0),
    }
    with open(out_path, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\nResults saved to {out_path}")


if __name__ == "__main__":
    main()
