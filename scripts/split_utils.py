#!/usr/bin/env python3
"""Utilities for report-aware dataset splitting."""

from __future__ import annotations

from typing import Iterable

import numpy as np


class _DSU:
    def __init__(self, n: int):
        self.parent = list(range(n))
        self.rank = [0] * n

    def find(self, x: int) -> int:
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: int, b: int) -> None:
        ra = self.find(a)
        rb = self.find(b)
        if ra == rb:
            return
        if self.rank[ra] < self.rank[rb]:
            self.parent[ra] = rb
        elif self.rank[ra] > self.rank[rb]:
            self.parent[rb] = ra
        else:
            self.parent[rb] = ra
            self.rank[ra] += 1


def build_report_connected_groups(sample_nids, node_reports) -> np.ndarray:
    """
    Build group ids with report-connected components.

    Rule:
    - If two IoCs share any report URL, they must be in the same group.
    - Connectivity is transitive (connected components over report-sharing graph).
    """
    sample_nids = list(sample_nids)
    n = len(sample_nids)
    dsu = _DSU(n)
    report_owner: dict[str, int] = {}

    for i, nid in enumerate(sample_nids):
        reports = node_reports.get(nid, [])
        if not reports:
            continue
        for report in set(reports):
            owner = report_owner.get(report)
            if owner is None:
                report_owner[report] = i
            else:
                dsu.union(i, owner)

    root_to_gid: dict[int, int] = {}
    next_gid = 0
    groups = np.zeros(n, dtype=np.int32)
    for i in range(n):
        root = dsu.find(i)
        gid = root_to_gid.get(root)
        if gid is None:
            gid = next_gid
            root_to_gid[root] = gid
            next_gid += 1
        groups[i] = gid
    return groups


def _collect_reports(indices: Iterable[int], sample_nids, node_reports) -> set[str]:
    reports: set[str] = set()
    for idx in indices:
        nid = sample_nids[int(idx)]
        reports.update(node_reports.get(nid, []))
    return reports


def assert_no_report_leak(train_idx, test_idx, sample_nids, node_reports):
    """
    Assert train/test splits share zero reports.
    Raises AssertionError when any report appears in both splits.
    """
    sample_nids = list(sample_nids)
    train_reports = _collect_reports(train_idx, sample_nids, node_reports)
    test_reports = _collect_reports(test_idx, sample_nids, node_reports)
    shared = train_reports & test_reports
    if shared:
        preview = sorted(shared)[:5]
        raise AssertionError(
            f"Report leakage detected: {len(shared)} shared reports; examples={preview}"
        )
    return {
        "train_report_count": len(train_reports),
        "test_report_count": len(test_reports),
        "shared_report_count": 0,
    }

