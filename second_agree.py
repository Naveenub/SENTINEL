import json, collections

key = json.load(open("second_labeller_key.json"))
second = json.load(open("second_labeller_labels.json"))
author = json.load(open("labels_human_injected.json"))

def kappa(pairs):
    n = len(pairs)
    po = sum(a == b for a, b in pairs) / n
    ca = collections.Counter(a for a, _ in pairs)
    cb = collections.Counter(b for _, b in pairs)
    pe = sum(ca[c] * cb[c] for c in set(ca) | set(cb)) / n**2
    return po, (po - pe) / (1 - pe) if pe < 1 else float("nan")

pairs = [(author[key[i]], second[i]) for i in key]
assert all(b in ("b", "m", "u") for _, b in pairs), "unfilled or invalid labels"
po, k3 = kappa(pairs)
bin_pairs = [(a == "b", b == "b") for a, b in pairs]
pb, kb = kappa(bin_pairs)
print(f"3-class: agreement {po:.0%}, kappa {k3:.2f}")
print(f"benign vs not-benign: agreement {pb:.0%}, kappa {kb:.2f}")
print("second labeller benign rate:", sum(b for _, b in bin_pairs) / len(bin_pairs))
print("author benign rate (same 40):", sum(a for a, _ in bin_pairs) / len(bin_pairs))

