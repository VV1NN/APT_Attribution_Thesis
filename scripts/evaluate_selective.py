#!/usr/bin/env python3
"""Evaluate selective classification: coverage-risk curve and AURC."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR / "model"))

from calibration_utils import coverage_risk_curve_from_confidence, aurc

CALIB_DATA_PATH = SCRIPT_DIR / "model/calibration_data.npz"
OUTPUT_PATH = SCRIPT_DIR / "results/evaluate_selective.json"


def summarize_on_grid(conf: np.ndarray, correct: np.ndarray, coverages: list[float]):
    order = np.argsort(conf)[::-1]
    corr = correct[order].astype(np.float32)
    n = len(corr)
    rows = []
    for c in coverages:
        k = max(1, int(round(c * n)))
        acc = float(np.mean(corr[:k]))
        rows.append(
            {
                "coverage": float(k / n),
                "risk": float(1.0 - acc),
                "accuracy": acc,
                "n_selected": int(k),
            }
        )
    return rows


def main():
    if not CALIB_DATA_PATH.exists():
        raise FileNotFoundError(
            f"{CALIB_DATA_PATH} not found. Run: uv run python scripts/model/calibrate_probs.py"
        )

    d = np.load(CALIB_DATA_PATH, allow_pickle=True)
    conf_raw = d["confidence_raw"].astype(np.float32)
    conf_cal = d["confidence_calibrated"].astype(np.float32)
    correct_raw = d["correct_raw"].astype(np.int32)
    correct_cal = d["correct_calibrated"].astype(np.int32)

    cov_raw, risk_raw = coverage_risk_curve_from_confidence(conf_raw, correct_raw)
    cov_cal, risk_cal = coverage_risk_curve_from_confidence(conf_cal, correct_cal)

    aurc_raw = aurc(cov_raw, risk_raw)
    aurc_cal = aurc(cov_cal, risk_cal)

    cov_grid = [0.1, 0.2, 0.3, 0.5, 0.7, 0.9, 1.0]
    grid_raw = summarize_on_grid(conf_raw, correct_raw, cov_grid)
    grid_cal = summarize_on_grid(conf_cal, correct_cal, cov_grid)

    payload = {
        "n_samples": int(len(conf_raw)),
        "aurc": {
            "raw": float(aurc_raw),
            "calibrated": float(aurc_cal),
            "delta": float(aurc_cal - aurc_raw),
        },
        "coverage_risk_curve": {
            "raw": {
                "coverage": cov_raw.tolist(),
                "risk": risk_raw.tolist(),
            },
            "calibrated": {
                "coverage": cov_cal.tolist(),
                "risk": risk_cal.tolist(),
            },
        },
        "grid_summary": {
            "raw": grid_raw,
            "calibrated": grid_cal,
        },
    }

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_PATH, "w") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)

    print("Selective evaluation complete")
    print(f"  Samples: {len(conf_raw)}")
    print(f"  AURC raw:        {aurc_raw:.6f}")
    print(f"  AURC calibrated: {aurc_cal:.6f}")
    print(f"  Delta:           {aurc_cal - aurc_raw:+.6f}")
    print(f"  Saved: {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
