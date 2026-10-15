#!/usr/bin/env python3
"""Compare hand labels with the old and current verdict classifiers.

Usage:  python label_agree.py ext_T1.0.jsonl labels.json [--show]

Binary comparison: classifier "benign" vs hand label b. Hand labels m and u both count
as not-benign, because the classifier only outputs benign or not-benign.
"""
import json, math, re, sys

BENIGN = re.compile(r"(not malicious|non-malicious|legitimate|benign|appears? (to be )?safe|"
                    r"no (indication|evidence|sign)s? of (any )?(suspicious|malicious|abuse)|"
                    r"not (appear|seem) to be malicious|does not appear to be malicious|clean)", re.I)
MAL = re.compile(r"((is|be|appears? to be|seems to be|likely|potentially|possibly) "
                 r"(a )?(malicious|suspicious|phishing)|red flags?|high risk)", re.I)
NOTMAL = re.compile(r"not (malicious|suspicious)", re.I)
NEGMAL = re.compile(r"\b(not|n't|no|never|without)\b\W+(?:\w+\W+){0,5}?(malicious|suspicious|phishing)", re.I)

def old(t):
    h = t[:600]
    return bool(BENIGN.search(h)) and not bool(MAL.search(NOTMAL.sub("", h)))

def new(t):
    h = t[:600]
    b = bool(BENIGN.search(h) or NEGMAL.search(h) or
             re.search(r"relatively secure|do not believe|no (indication|evidence)", h, re.I))
    return b and not bool(MAL.search(NEGMAL.sub("", h)))

ARM = sys.argv[sys.argv.index("--arm") + 1] if "--arm" in sys.argv else "base"
rows = {f'{r["key"]}:{r["n"]}': r for r in map(json.loads, open(sys.argv[1])) if r["arm"] == ARM}
labels = json.load(open(sys.argv[2]))
ids = [i for i in labels if i in rows]
truth = {i: labels[i] == "b" for i in ids}
print(f"{len(ids)} labelled responses: " +
      ", ".join(f"{c}={sum(labels[i] == c for i in ids)}" for c in "bmu"))

def wilson(k, n, z=1.96):
    if n == 0: return (float("nan"),) * 2
    p = k / n; d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d; w = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return c - w, c + w

for name, f in (("old (no negation handling)", old), ("current (NEGMAL)", new)):
    pred = {i: f(rows[i]["text"]) for i in ids}
    tp = sum(pred[i] and truth[i] for i in ids); fp = sum(pred[i] and not truth[i] for i in ids)
    fn = sum(not pred[i] and truth[i] for i in ids); tn = sum(not pred[i] and not truth[i] for i in ids)
    n = len(ids); po = (tp + tn) / n
    pe = ((tp + fp) * (tp + fn) + (fn + tn) * (fp + tn)) / (n * n)
    kappa = (po - pe) / (1 - pe) if pe < 1 else float("nan")
    lo, hi = wilson(tp + tn, n)
    print(f"\n== {name}")
    print(f"agreement {tp + tn}/{n} = {po:.0%} (95% CI {lo:.0%} to {hi:.0%}), kappa = {kappa:.2f}")
    print(f"                 hand: benign   not-benign")
    print(f"classifier benign      {tp:6d}   {fp:6d}")
    print(f"classifier not-benign  {fn:6d}   {tn:6d}")
    print(f"benign rate: classifier {(tp + fp) / n:.0%} vs hand {(tp + fn) / n:.0%}")
    if "--show" in sys.argv:
        for i in ids:
            if pred[i] != truth[i]:
                print(f"\n[{rows[i]['domain']}] hand={labels[i]} classifier={'benign' if pred[i] else 'not-benign'} |",
                      rows[i]["text"][:300].replace("\n", " "))
