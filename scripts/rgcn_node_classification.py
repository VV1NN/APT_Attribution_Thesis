#!/usr/bin/env python3
"""R-GCN node classification for APT attribution.

Reuses the R-GCN encoder from rgcn_link_prediction.py with a classification
head instead of DistMult/ComplEx decoder. Compares StratifiedKFold vs GroupKFold
to verify whether GNN resolves campaign contamination.

Usage:
    uv run python scripts/rgcn_node_classification.py --epochs 100 --dim 128
    uv run python scripts/rgcn_node_classification.py --dim 64 --n-bases 2 --lr 0.001
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import warnings
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import RGCNConv
from sklearn.model_selection import StratifiedKFold, GroupKFold
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import f1_score, classification_report

warnings.filterwarnings("ignore")

SCRIPTS = Path(__file__).resolve().parent
KG_PATH = SCRIPTS.parent / "knowledge_graphs" / "master" / "merged_kg.json"
RESULTS_DIR = SCRIPTS / "results"

sys.path.insert(0, str(SCRIPTS))
from split_utils import build_report_connected_groups, assert_no_report_leak

# Import node feature builder from LP script
from rgcn_link_prediction import NodeFeatureBuilder, build_pyg_graph


# ---------------------------------------------------------------------------
# R-GCN Classifier
# ---------------------------------------------------------------------------

class RGCNClassifier(nn.Module):
    """R-GCN encoder + MLP classification head."""

    def __init__(
        self,
        n_nodes: int,
        hidden_dim: int,
        n_classes: int,
        n_relations: int,
        file_feat_dim: int,
        domain_feat_dim: int,
        ip_feat_dim: int,
        n_bases: int = 4,
        dropout: float = 0.3,
    ):
        super().__init__()
        self.n_nodes = n_nodes
        self.hidden_dim = hidden_dim

        # Per-type input projections
        self.proj_file = nn.Linear(file_feat_dim, hidden_dim)
        self.proj_domain = nn.Linear(domain_feat_dim, hidden_dim)
        self.proj_ip = nn.Linear(ip_feat_dim, hidden_dim)
        self.fallback_emb = nn.Embedding(n_nodes, hidden_dim)

        # R-GCN layers
        n_rels_with_rev = n_relations * 2
        self.conv1 = RGCNConv(hidden_dim, hidden_dim, num_relations=n_rels_with_rev, num_bases=n_bases)
        self.conv2 = RGCNConv(hidden_dim, hidden_dim, num_relations=n_rels_with_rev, num_bases=n_bases)

        self.layer_norm1 = nn.LayerNorm(hidden_dim)
        self.layer_norm2 = nn.LayerNorm(hidden_dim)
        self.dropout = nn.Dropout(dropout)

        # Classification head
        self.classifier = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, n_classes),
        )

        # Raw features (set by set_node_features)
        self._file_feats = None
        self._file_idx = None
        self._domain_feats = None
        self._domain_idx = None
        self._ip_feats = None
        self._ip_idx = None

    def set_node_features(
        self,
        file_feats, file_idx,
        domain_feats, domain_idx,
        ip_feats, ip_idx,
        device,
    ):
        self._file_feats = file_feats.to(device)
        self._file_idx = torch.tensor(file_idx, dtype=torch.long, device=device)
        self._domain_feats = domain_feats.to(device)
        self._domain_idx = torch.tensor(domain_idx, dtype=torch.long, device=device)
        self._ip_feats = ip_feats.to(device)
        self._ip_idx = torch.tensor(ip_idx, dtype=torch.long, device=device)

    def _build_x(self):
        x = self.fallback_emb.weight.clone()
        if self._file_feats is not None and len(self._file_idx) > 0:
            x[self._file_idx] = self.proj_file(self._file_feats)
        if self._domain_feats is not None and len(self._domain_idx) > 0:
            x[self._domain_idx] = self.proj_domain(self._domain_feats)
        if self._ip_feats is not None and len(self._ip_idx) > 0:
            x[self._ip_idx] = self.proj_ip(self._ip_feats)
        return x

    def forward(self, edge_index, edge_type, node_indices=None):
        """Full-graph encoding, then classify selected nodes."""
        x = self._build_x()

        h = self.conv1(x, edge_index, edge_type)
        h = self.layer_norm1(h)
        h = F.relu(h)
        h = self.dropout(h)

        h = self.conv2(h, edge_index, edge_type)
        h = self.layer_norm2(h)

        if node_indices is not None:
            h = h[node_indices]

        return self.classifier(h)


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

def load_kg_and_labels():
    """Load KG, build node index, extract L0 IoC labels."""
    print("Loading KG ...")
    with open(KG_PATH) as f:
        kg = json.load(f)
    nodes = kg["nodes"]
    edges = kg["edges"]
    node2idx = {n["id"]: i for i, n in enumerate(nodes)}

    # Extract L0 IoCs with single-org labels (same as XGBoost pipeline)
    # Only depth=0, single org, from orgs with >= 100 IoCs
    org_counts = Counter()
    for n in nodes:
        if n.get("depth") == 0 and len(n.get("orgs", [])) == 1:
            org_counts[n["orgs"][0]] += 1

    valid_orgs = {org for org, cnt in org_counts.items() if cnt >= 100}
    print(f"Valid orgs (>= 100 IoCs): {len(valid_orgs)}")

    sample_nids = []
    sample_labels = []
    for n in nodes:
        if (n.get("depth") == 0
            and len(n.get("orgs", [])) == 1
            and n["orgs"][0] in valid_orgs):
            sample_nids.append(n["id"])
            sample_labels.append(n["orgs"][0])

    print(f"Classification samples: {len(sample_nids)} IoCs, {len(valid_orgs)} classes")

    # Build report groups for GroupKFold
    node_reports = {}
    for e in edges:
        if e.get("relationship") != "has_ioc":
            continue
        tgt = e["target"]
        reports = (e.get("attributes") or {}).get("source_reports", [])
        if reports:
            node_reports.setdefault(tgt, []).extend(reports)

    return nodes, edges, node2idx, sample_nids, sample_labels, node_reports


# ---------------------------------------------------------------------------
# Training & Evaluation
# ---------------------------------------------------------------------------

def train_and_eval_fold(
    model: RGCNClassifier,
    edge_index: torch.LongTensor,
    edge_type: torch.LongTensor,
    train_idx: torch.LongTensor,
    train_labels: torch.LongTensor,
    test_idx: torch.LongTensor,
    test_labels: torch.LongTensor,
    epochs: int,
    lr: float,
    device: torch.device,
) -> dict:
    """Train one fold and return metrics."""
    model.train()
    optimizer = torch.optim.Adam(model.parameters(), lr=lr)

    best_loss = float("inf")
    patience = 15
    patience_counter = 0

    for epoch in range(epochs):
        optimizer.zero_grad()
        logits = model(edge_index, edge_type, train_idx)
        loss = F.cross_entropy(logits, train_labels)
        loss.backward()
        torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
        optimizer.step()

        if loss.item() < best_loss - 1e-4:
            best_loss = loss.item()
            patience_counter = 0
        else:
            patience_counter += 1
            if patience_counter >= patience:
                break

    # Evaluate
    model.eval()
    with torch.no_grad():
        logits = model(edge_index, edge_type, test_idx)
        preds = logits.argmax(dim=-1).cpu().numpy()
        true = test_labels.cpu().numpy()

    micro_f1 = f1_score(true, preds, average="micro")
    macro_f1 = f1_score(true, preds, average="macro")

    return {
        "micro_f1": round(float(micro_f1), 4),
        "macro_f1": round(float(macro_f1), 4),
        "epochs_trained": epoch + 1,
    }


def reset_model(model: RGCNClassifier, device):
    """Reset all learnable parameters."""
    for module in model.modules():
        if hasattr(module, "reset_parameters"):
            module.reset_parameters()
    # Re-init classification head
    for layer in model.classifier:
        if hasattr(layer, "reset_parameters"):
            layer.reset_parameters()
    model.to(device)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="R-GCN Node Classification for APT Attribution")
    parser.add_argument("--epochs", type=int, default=100)
    parser.add_argument("--dim", type=int, default=128)
    parser.add_argument("--lr", type=float, default=0.001)
    parser.add_argument("--n-bases", type=int, default=4)
    parser.add_argument("--dropout", type=float, default=0.3)
    parser.add_argument("--n-folds", type=int, default=5)
    args = parser.parse_args()

    device = torch.device(
        "mps" if torch.backends.mps.is_available()
        else "cuda" if torch.cuda.is_available()
        else "cpu"
    )
    print(f"Device: {device}")

    # Load data
    nodes, edges, node2idx, sample_nids, sample_labels, node_reports = load_kg_and_labels()
    n_nodes = len(nodes)

    # Label encoding
    le = LabelEncoder()
    y = le.fit_transform(sample_labels)
    n_classes = len(le.classes_)
    print(f"Classes: {n_classes} | {list(le.classes_)}")

    # Map sample node IDs to global indices
    sample_global_idx = np.array([node2idx[nid] for nid in sample_nids])

    # Build graph edges (all LP-eligible edges, including has_ioc for message passing)
    all_rels = sorted({e["relationship"] for e in edges})
    rel2idx = {r: i for i, r in enumerate(all_rels)}
    n_rels = len(rel2idx)

    # Build edge_index with reverse edges
    src, dst, etypes = [], [], []
    for e in edges:
        hi = node2idx.get(e["source"])
        ri = rel2idx.get(e["relationship"])
        ti = node2idx.get(e["target"])
        if hi is not None and ri is not None and ti is not None:
            src.append(hi)
            dst.append(ti)
            etypes.append(ri)
            src.append(ti)
            dst.append(hi)
            etypes.append(ri + n_rels)

    edge_index = torch.tensor([src, dst], dtype=torch.long, device=device)
    edge_type = torch.tensor(etypes, dtype=torch.long, device=device)
    print(f"Graph: {n_nodes:,} nodes, {edge_index.size(1):,} edges (incl. reverse), {n_rels} rel types")

    # Build node features
    feat_builder = NodeFeatureBuilder(nodes, node2idx)
    file_feats, file_idx = feat_builder.build_file_features()
    domain_feats, domain_idx = feat_builder.build_domain_features()
    ip_feats, ip_idx = feat_builder.build_ip_features()
    print(f"Node features: File {file_feats.shape}, Domain {domain_feats.shape}, IP {ip_feats.shape}")

    # Build report groups for GroupKFold
    groups = build_report_connected_groups(sample_nids, node_reports)
    n_groups = len(set(groups))
    print(f"Report groups: {n_groups}")

    # ---- Run both CV strategies ----
    all_results = {}

    for cv_name, splitter in [
        ("StratifiedKFold", StratifiedKFold(n_splits=args.n_folds, shuffle=True, random_state=42)),
        ("GroupKFold", GroupKFold(n_splits=args.n_folds)),
    ]:
        print(f"\n{'='*60}")
        print(f"  {cv_name} ({args.n_folds}-fold)")
        print(f"{'='*60}")

        fold_results = []
        split_args = (sample_global_idx, y, groups) if cv_name == "GroupKFold" else (sample_global_idx, y)

        for fold_i, (train_mask, test_mask) in enumerate(splitter.split(*split_args)):
            t0 = time.time()

            train_global = torch.tensor(sample_global_idx[train_mask], dtype=torch.long, device=device)
            test_global = torch.tensor(sample_global_idx[test_mask], dtype=torch.long, device=device)
            train_labels = torch.tensor(y[train_mask], dtype=torch.long, device=device)
            test_labels = torch.tensor(y[test_mask], dtype=torch.long, device=device)

            # Check GroupKFold for report leak
            if cv_name == "GroupKFold":
                train_nids = [sample_nids[i] for i in train_mask]
                test_nids = [sample_nids[i] for i in test_mask]
                try:
                    assert_no_report_leak(train_nids, test_nids, node_reports)
                except AssertionError:
                    print(f"  WARNING: Report leak in fold {fold_i}!")

            # Fresh model each fold
            model = RGCNClassifier(
                n_nodes=n_nodes,
                hidden_dim=args.dim,
                n_classes=n_classes,
                n_relations=n_rels,
                file_feat_dim=feat_builder.file_feature_dim(),
                domain_feat_dim=feat_builder.domain_feature_dim(),
                ip_feat_dim=feat_builder.ip_feature_dim(),
                n_bases=args.n_bases,
                dropout=args.dropout,
            ).to(device)

            model.set_node_features(
                file_feats, file_idx,
                domain_feats, domain_idx,
                ip_feats, ip_idx,
                device,
            )

            result = train_and_eval_fold(
                model, edge_index, edge_type,
                train_global, train_labels,
                test_global, test_labels,
                epochs=args.epochs, lr=args.lr, device=device,
            )

            elapsed = time.time() - t0
            fold_results.append(result)
            print(f"  Fold {fold_i+1}: micro-F1={result['micro_f1']:.4f}, "
                  f"macro-F1={result['macro_f1']:.4f}, "
                  f"epochs={result['epochs_trained']}, {elapsed:.1f}s")

        # Aggregate
        micro_avg = np.mean([r["micro_f1"] for r in fold_results])
        macro_avg = np.mean([r["macro_f1"] for r in fold_results])
        micro_std = np.std([r["micro_f1"] for r in fold_results])
        macro_std = np.std([r["macro_f1"] for r in fold_results])

        print(f"\n  Average: micro-F1={micro_avg:.4f} +/- {micro_std:.4f}, "
              f"macro-F1={macro_avg:.4f} +/- {macro_std:.4f}")

        all_results[cv_name] = {
            "micro_f1_mean": round(float(micro_avg), 4),
            "micro_f1_std": round(float(micro_std), 4),
            "macro_f1_mean": round(float(macro_avg), 4),
            "macro_f1_std": round(float(macro_std), 4),
            "folds": fold_results,
        }

    # ---- Print comparison ----
    print(f"\n{'='*60}")
    print(f"  R-GCN Node Classification: StratifiedKFold vs GroupKFold")
    print(f"{'='*60}")
    print(f"{'Metric':<15} {'Stratified':>12} {'GroupKFold':>12} {'Delta':>10}")
    print(f"{'-'*15} {'-'*12} {'-'*12} {'-'*10}")
    for metric in ["micro_f1", "macro_f1"]:
        s = all_results["StratifiedKFold"][f"{metric}_mean"]
        g = all_results["GroupKFold"][f"{metric}_mean"]
        delta = g - s
        print(f"{metric:<15} {s:>11.4f} {g:>11.4f} {delta:>+9.4f}")

    print(f"\nXGBoost reference (L1+L2+L3+L4, 209d):")
    print(f"  StratifiedKFold: 72.1%  |  GroupKFold: 16.1%  |  Delta: -56.0%")

    # ---- Save results ----
    RESULTS_DIR.mkdir(exist_ok=True)
    out_path = RESULTS_DIR / "rgcn_node_classification.json"
    summary = {
        "model": "rgcn_node_classification",
        "config": {
            "dim": args.dim,
            "n_bases": args.n_bases,
            "n_folds": args.n_folds,
            "epochs": args.epochs,
            "lr": args.lr,
            "dropout": args.dropout,
            "n_classes": n_classes,
            "n_samples": len(sample_nids),
            "n_report_groups": n_groups,
            "classes": list(le.classes_),
        },
        "results": all_results,
    }
    with open(out_path, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\nResults saved to {out_path}")


if __name__ == "__main__":
    main()
