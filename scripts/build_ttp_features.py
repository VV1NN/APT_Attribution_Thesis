#!/usr/bin/env python3
"""
Phase 3: L5 TTP Feature Construction。

對 6 種 entity type 分別建 TF-IDF vocabulary，
每個 IoC → 6 個 TF-IDF sparse vector → concatenate。
預設不做 SVD（避免 transductive leakage）。

輸入：scripts/ttp_extraction/ioc_ttp_mapping.json
輸出：scripts/features/features_l5_ttp.npz + ttp_vocabularies.json
"""

import argparse
import json
import logging
import numpy as np
from pathlib import Path
from scipy.sparse import csr_matrix, hstack, save_npz, load_npz
from sklearn.feature_extraction.text import TfidfVectorizer

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

MAPPING_PATH = Path("scripts/ttp_extraction/ioc_ttp_mapping.json")
FEATURE_DIR = Path("scripts/features")
L5_OUTPUT = FEATURE_DIR / "features_l5_ttp.npz"
VOCAB_OUTPUT = FEATURE_DIR / "ttp_vocabularies.json"

ENTITY_TYPES = ["Tool", "Way", "Exp", "Purp", "Idus", "Area"]


def load_ioc_ttp_mapping():
    with open(MAPPING_PATH) as f:
        return json.load(f)


def load_existing_node_ids():
    """Load node_ids from existing features_all.npz to ensure alignment."""
    feat_path = FEATURE_DIR / "features_all.npz"
    if feat_path.exists():
        data = np.load(feat_path, allow_pickle=True)
        return list(data["node_ids"])
    return None


def build_l5_features(mapping, node_ids, min_df=2, max_df_ratio=0.8):
    """Build TF-IDF features for each entity type, concatenate.

    Args:
        mapping: IoC-TTP mapping dict
        node_ids: ordered list of IoC node_ids (must match features_all.npz)
        min_df: minimum document frequency for TF-IDF vocabulary
        max_df_ratio: maximum document frequency ratio

    Returns:
        X_l5: sparse matrix (n_samples, n_features)
        feature_names: list of feature names
        vocab_info: dict of vocabulary info per entity type
    """
    n_samples = len(node_ids)
    sparse_blocks = []
    feature_names = []
    vocab_info = {}

    for etype in ENTITY_TYPES:
        # Build "documents" for TF-IDF: each IoC's entities as a space-separated string
        docs = []
        for nid in node_ids:
            ioc_data = mapping.get(nid, {})
            entities = ioc_data.get("entities_normalized", {}).get(etype, [])
            # Join entities as a single document
            # Multi-word entities: replace spaces with underscores so TF-IDF treats them as single tokens
            tokens = [e.replace(" ", "_") for e in entities]
            docs.append(" ".join(tokens))

        # Check if there's enough data
        non_empty = sum(1 for d in docs if d.strip())
        if non_empty < min_df:
            logger.warning(f"  {etype}: only {non_empty} non-empty docs, skipping")
            continue

        # Build TF-IDF
        vectorizer = TfidfVectorizer(
            min_df=min_df,
            max_df=max_df_ratio,
            token_pattern=r"[^\s]+",  # any non-whitespace token
            lowercase=False,  # already lowercased in normalization
        )

        try:
            X_type = vectorizer.fit_transform(docs)
        except ValueError as e:
            logger.warning(f"  {etype}: TF-IDF failed: {e}")
            continue

        terms = vectorizer.get_feature_names_out()
        idf = vectorizer.idf_

        sparse_blocks.append(X_type)
        type_names = [f"ttp_{etype}_{t}" for t in terms]
        feature_names.extend(type_names)

        vocab_info[etype] = {
            "n_terms": len(terms),
            "n_docs_with_data": non_empty,
            "top_idf": sorted(
                zip(terms.tolist(), idf.tolist()), key=lambda x: -x[1]
            )[:20],
            "top_freq": sorted(
                zip(terms.tolist(), idf.tolist()), key=lambda x: x[1]
            )[:10],
        }

        logger.info(
            f"  {etype}: {len(terms)} terms, {non_empty} docs with data, "
            f"sparsity {1 - X_type.nnz / (X_type.shape[0] * X_type.shape[1]):.3f}"
        )

    if not sparse_blocks:
        logger.error("No TF-IDF features built!")
        return None, [], {}

    # Concatenate all entity type matrices
    X_l5 = hstack(sparse_blocks, format="csr")
    logger.info(
        f"L5 total: {X_l5.shape[1]} features, "
        f"shape={X_l5.shape}, nnz={X_l5.nnz}"
    )

    return X_l5, feature_names, vocab_info


def main():
    parser = argparse.ArgumentParser(description="Build L5 TTP features")
    parser.add_argument("--min-df", type=int, default=2, help="Min doc frequency")
    parser.add_argument("--max-df", type=float, default=0.8, help="Max doc frequency ratio")
    parser.add_argument("--stats", action="store_true", help="Only print stats of existing output")
    args = parser.parse_args()

    if args.stats:
        if L5_OUTPUT.exists():
            data = np.load(L5_OUTPUT, allow_pickle=True)
            X = load_npz(FEATURE_DIR / "features_l5_ttp_matrix.npz")
            node_ids = data["node_ids"]
            feat_names = data["feature_names"]
            print(f"L5 features: {X.shape}, nnz={X.nnz}")
            print(f"Node IDs: {len(node_ids)}")
            print(f"Feature names: {len(feat_names)}")
            print(f"Sample features: {feat_names[:20]}")
        else:
            print("No L5 features found. Run without --stats first.")
        return

    logger.info("Loading IoC-TTP mapping...")
    mapping = load_ioc_ttp_mapping()
    logger.info(f"  {len(mapping)} IoCs with TTP data")

    # Load node_ids from existing features
    node_ids = load_existing_node_ids()
    if node_ids is None:
        logger.error("features_all.npz not found — cannot determine IoC ordering")
        return

    logger.info(f"  {len(node_ids)} IoCs in feature matrix")

    # Check coverage
    in_mapping = sum(1 for nid in node_ids if nid in mapping)
    logger.info(f"  {in_mapping}/{len(node_ids)} ({in_mapping/len(node_ids)*100:.1f}%) have TTP mapping")

    # Build features
    logger.info("Building TF-IDF features...")
    X_l5, feature_names, vocab_info = build_l5_features(
        mapping, node_ids, min_df=args.min_df, max_df_ratio=args.max_df
    )

    if X_l5 is None:
        return

    # Save
    FEATURE_DIR.mkdir(parents=True, exist_ok=True)

    # Save sparse matrix separately (scipy format)
    save_npz(FEATURE_DIR / "features_l5_ttp_matrix.npz", X_l5)

    # Save metadata
    np.savez(
        L5_OUTPUT,
        node_ids=np.array(node_ids, dtype=object),
        feature_names=np.array(feature_names, dtype=object),
    )

    # Save vocabulary info
    with open(VOCAB_OUTPUT, "w") as f:
        json.dump(vocab_info, f, indent=2, ensure_ascii=False)

    logger.info(f"Saved sparse matrix to {FEATURE_DIR / 'features_l5_ttp_matrix.npz'}")
    logger.info(f"Saved metadata to {L5_OUTPUT}")
    logger.info(f"Saved vocabularies to {VOCAB_OUTPUT}")

    # Print summary
    print(f"\n{'='*60}")
    print("L5 TTP Feature Summary")
    print(f"{'='*60}")
    print(f"  Samples: {X_l5.shape[0]:,}")
    print(f"  Features: {X_l5.shape[1]:,}")
    print(f"  Non-zero: {X_l5.nnz:,} ({X_l5.nnz / (X_l5.shape[0] * X_l5.shape[1]) * 100:.2f}%)")
    print(f"  IoCs with TTP data: {in_mapping:,}/{len(node_ids):,}")

    print(f"\n  Per entity type:")
    print(f"  {'Type':<8} {'Terms':>6} {'Docs':>6} {'Top-5 IDF terms'}")
    print(f"  {'-'*8} {'-'*6} {'-'*6} {'-'*40}")
    for etype in ENTITY_TYPES:
        info = vocab_info.get(etype)
        if not info:
            print(f"  {etype:<8} {'—':>6} {'—':>6}")
            continue
        top5 = ", ".join(t[0] for t in info["top_idf"][:5])
        print(f"  {etype:<8} {info['n_terms']:>6} {info['n_docs_with_data']:>6} {top5}")


if __name__ == "__main__":
    main()
