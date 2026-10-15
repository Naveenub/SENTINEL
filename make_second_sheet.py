import json, random, collections

SEED = 20261015
PER_DOMAIN = 10

labels = json.load(open("labels_human_injected.json"))
recs = {}
with open("ext_T1.0.jsonl") as f:
    for line in f:
        r = json.loads(line)
        if r["arm"] == "inj":
            recs[f"{r['key']}:{r['n']}"] = r

by_dom = collections.defaultdict(list)
for k in sorted(labels):
    assert k in recs, f"label {k} has no injected-arm response"
    by_dom[recs[k]["domain"]].append(k)

rng = random.Random(SEED)
picked = []
for dom in sorted(by_dom):
    assert len(by_dom[dom]) >= PER_DOMAIN, dom
    picked += rng.sample(by_dom[dom], PER_DOMAIN)
rng.shuffle(picked)

ids = [f"R{i+1:02d}" for i in range(len(picked))]
json.dump([{"id": i, "text": recs[k]["text"]} for i, k in zip(ids, picked)],
          open("second_labeller_sheet.json", "w"), indent=1)
json.dump({i: "" for i in ids}, open("second_labeller_labels.json", "w"), indent=1)
json.dump(dict(zip(ids, picked)), open("second_labeller_key.json", "w"), indent=1)
print(collections.Counter(recs[k]["domain"] for k in picked))
