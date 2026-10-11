"""Score the red-team corpus with the configured SENTINEL_CLASSIFIER and sweep the threshold.

Usage:  SENTINEL_CLASSIFIER=prompt_guard python scripts/sweep_threshold.py [--csv scores.csv]

Calls the backend directly (no HTTP, no rules), so you see the model's raw scores:
  attacks / known_gaps = positives (should score high), benign / known_false_positives = negatives.
NIM returns only 1.0 or 0.0, so a sweep is meaningless for it: you get one operating point.
The corpus is small; treat the output as a sanity check, not a calibration. Prefer a threshold
with headroom over the lowest benign-max score, and re-check on your own benign traffic.
"""
import argparse
import csv
import sys
from pathlib import Path

import yaml

root = Path(__file__).parents[1]
sys.path.insert(0, str(root))
from sentinel.input_filter import classifier as clf  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--csv")
args = ap.parse_args()

model = clf.load()
if model is None:
    sys.exit("set SENTINEL_CLASSIFIER (nim, prompt_guard, or module:Class)")
print("classifier:", getattr(model, "name", type(model).__name__))

cases = yaml.safe_load((root / "tests/redteam/cases/injection.yaml").read_text())
POS = ("attacks", "known_gaps")
rows = [(k, t, model.score(t)) for k in (*POS, "benign", "known_false_positives") for t in cases[k]]

if args.csv:
    with open(args.csv, "w", newline="") as f:
        csv.writer(f).writerows([("set", "score", "text"), *[(k, f"{s:.4f}", t[:120]) for k, t, s in rows]])

pos = [s for k, _, s in rows if k in POS]
neg = [s for k, _, s in rows if k not in POS]
print(f"\npositives: {len(pos)}  negatives: {len(neg)}  (highest negative score: {max(neg):.4f})")
print(f"\n{'thr':>6} {'recall':>8} {'fp_rate':>8}  gaps_caught  false_pos")
gaps = [s for k, _, s in rows if k == "known_gaps"]
for thr in (0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 0.95, 0.99):
    r = sum(s >= thr for s in pos) / len(pos)
    fp = sum(s >= thr for s in neg)
    g = sum(s >= thr for s in gaps)
    print(f"{thr:>6} {r:>8.2%} {fp / len(neg):>8.2%}  {g:>5}/{len(gaps):<6} {fp:>5}/{len(neg)}")

print("\nlowest-scoring positives (what the model misses first):")
for k, t, s in sorted((r for r in rows if r[0] in POS), key=lambda r: r[2])[:8]:
    print(f"  {s:.3f}  [{k}] {t[:70]!r}")
print("\nhighest-scoring negatives (what it would false-positive on first):")
for k, t, s in sorted((r for r in rows if r[0] not in POS), key=lambda r: -r[2])[:8]:
    print(f"  {s:.3f}  [{k}] {t[:70]!r}")
