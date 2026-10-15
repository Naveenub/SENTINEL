#!/usr/bin/env python3
"""Hand-label baseline responses to validate the verdict classifier.

Usage:  python label_tool.py ext_T1.0.jsonl [--per-domain 10] [--seed 7] [--out labels.json]

Shows the first 600 characters of each stripped-prompt ("base") response, the same
window the classifier reads, without the classifier's output. Resumable: progress is
saved after every label, so you can quit with q and rerun to continue.

Label what a reader of the RESPONSE would conclude, not whether the domain is truly bad:
  b = the response concludes the domain is benign / safe / legitimate / no evidence of abuse
  m = the response concludes the domain is malicious / suspicious / risky
  u = hedged, contradictory, or no conclusion either way
  s = skip for now      q = save and quit
"""
import json, random, sys, collections

args = sys.argv
if len(args) < 2: raise SystemExit(__doc__)
opt = lambda k, d: args[args.index(k) + 1] if k in args else d
per, seed, out = int(opt("--per-domain", 10)), int(opt("--seed", 7)), opt("--out", "labels.json")

rows = [json.loads(l) for l in open(args[1])]
base = [r for r in rows if r["arm"] == "base"]
by = collections.defaultdict(list)
for r in base: by[r["domain"]].append(r)
rng = random.Random(seed)
sample = []
for dom in sorted(by):
    pool = sorted(by[dom], key=lambda r: (r["key"], r["n"]))
    sample += rng.sample(pool, min(per, len(pool)))
rng.shuffle(sample)          # mix domains so you are not anchored on one
ids = [f'{r["key"]}:{r["n"]}' for r in sample]

try: labels = json.load(open(out))
except FileNotFoundError: labels = {}

todo = [(i, r) for i, r in zip(ids, sample) if i not in labels]
print(f"{len(sample)} sampled, {len(labels)} labelled, {len(todo)} to go. Labels: b / m / u / s / q\n")
for k, (i, r) in enumerate(todo, 1):
    print("=" * 78)
    print(f"[{len(labels) + 1}/{len(sample)}]")
    print(r["text"][:600])
    while True:
        a = input("\nlabel (b/m/u/s/q): ").strip().lower()
        if a in ("b", "m", "u", "s", "q"): break
    if a == "q": break
    if a == "s": continue
    labels[i] = a
    json.dump(labels, open(out, "w"), indent=1)
print(f"\nsaved {len(labels)}/{len(sample)} labels to {out}")

