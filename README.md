```
 ____  _____ _   _ _____ ___ _   _ _____ _
/ ___|| ____| \ | |_   _|_ _| \ | | ____| |
\___ \|  _| |  \| | | |  | ||  \| |  _| | |
 ___) | |___| |\  | | |  | || |\  | |___| |___
|____/|_____|_| \_| |_| |___|_| \_|_____|_____|

        host defense for AI agents (Linux)
```

# SENTINEL

A defense gateway that sits between **untrusted input**, the **model**, and **tools**. Every prompt, tool call, and output passes through five layers before anything touches the outside world.

> **Status:** all five layers are built and tested: 69 tests plus a red-team corpus (11 documented detection gaps tracked as strict expected-failures). promptfoo was run against the live gateway (8/8). CI is written but has not been run on GitHub yet.
>
> It is a **decision API**: your agent runtime calls `/v1/scan` before content reaches the model, `/v1/tool/authorize` before any tool runs, or `/v1/tool/run` to have SENTINEL run a tool end to end (authorize, sandbox, scan output, audit). It does not proxy model traffic.
>
> **Not yet verified against a real container runtime:** the sandbox command line is unit-tested and the runner fails closed without Docker, but I could not execute real containers or gVisor in the build environment. Run the smoke test under "Sandbox" below on your host before trusting L3.

---

## Architecture

```
   untrusted input (docs, web pages, tool outputs, user prompts)
                         │
                         ▼
        ┌────────────────────────────────┐
        │  L1  INPUT FILTER              │  classifier + rules
        │  injection / jailbreak /       │  tag external content as
        │  hidden-instruction detection  │  UNTRUSTED DATA
        └───────────────┬────────────────┘
                        ▼
                 ┌─────────────┐
                 │    MODEL    │
                 └──────┬──────┘
                        │ proposed tool call
                        ▼
        ┌────────────────────────────────┐
        │  L2  TOOL POLICY ENGINE        │  deny-by-default allowlist
        │  schema validation, rate       │  per agent (YAML / OPA)
        │  limits, human approval        │  approve: shell, payments,
        └───────────────┬────────────────┘  email, deletes
                        ▼
        ┌────────────────────────────────┐
        │  L3  SANDBOX                   │  gVisor / Firecracker
        │  no ambient creds, egress      │  read-only FS
        │  allowlist, read-only FS       │
        └───────────────┬────────────────┘
                        ▼
        ┌────────────────────────────────┐
        │  L4  SECRETS & DATA CONTROL    │  short-lived scoped tokens
        │  tokens never in prompt        │  output scan: keys, PII,
        │  output scanning               │  exfil patterns
        └───────────────┬────────────────┘
                        ▼
                  tool result ──► back through L1 (as untrusted)

 ═══════════════════════════════════════════════════════════════
  L5  AUDIT & DETECTION  (spans every layer above)
  signed, append-only, hash-chained log of every prompt, tool
  call, and decision. Alerts: odd tool sequences, spikes, new domains.
 ═══════════════════════════════════════════════════════════════
```

| Layer | Purpose | Status |
|---|---|---|
| L1 Input filter | Detect injection, jailbreaks, hidden instructions; tag external content untrusted | Built |
| L2 Tool policy | Deny-by-default, schema validation, rate limits, human approval | Built |
| L3 Sandbox | Containers/microVMs, no ambient creds, egress allowlist, read-only FS | Built (verify on your host) |
| L4 Secrets & data | Short-lived scoped tokens, output scanning | Built |
| L5 Audit | Signed hash-chained log + anomaly alerts | Built |

**Stack:** Python / FastAPI proxy · YAML or OPA policy · gVisor / Firecracker · SQLite / Postgres · garak / promptfoo

---

## Repo structure

```
sentinel/
├── README.md
├── pyproject.toml                 # deps + packaging
├── .env.example                   # required keys + optional settings
├── sentinel/
│   ├── main.py                    # FastAPI app factory + endpoints, admin-token guard
│   ├── models.py                  # pydantic request/response types
│   ├── pipeline.py                # ties L1 + L2 together, writes every decision to L5
│   ├── input_filter/              # L1
│   │   ├── rules.py               # injection regexes + hidden-unicode detection
│   │   ├── tagger.py              # wraps external content as <untrusted> data
│   │   └── classifier.py          # pluggable ML backend (NeMo Guardrails, Llama Guard, ...)
│   ├── policy/                    # L2
│   │   ├── engine.py              # allowlist, JSON-schema args, host allowlist, rate limit, approval
│   │   └── hosts.py               # extracts URL hosts from tool args (parsed, not regexed)
│   ├── sandbox/                   # L3
│   │   ├── runner.py              # hardened docker run (gVisor-ready), fails closed
│   │   └── egress.py              # allowlisting HTTPS CONNECT proxy (blocks IP literals, private IPs)
│   ├── secrets/                   # L4
│   │   ├── broker.py              # short-lived scoped signed tokens, injected into sandbox env only
│   │   └── scanner.py             # output scan: credentials withheld, PII/exfil redacted
│   └── audit/                     # L5
│       ├── log.py                 # hash-chained, HMAC-signed, append-only SQLite log
│       ├── detect.py              # anomaly rules: spikes, new domains, unusual sequences, ...
│       └── alerts.py              # alert sinks: log, webhook
├── policies/
│   ├── agents.yaml                # per-agent tool allowlists, schemas, limits, approvals, sandbox, secrets
│   └── egress.yaml                # hosts sandboxes may reach through the proxy
├── scripts/
│   ├── approve.py                 # CLI: list / approve / deny pending actions
│   └── verify_log.py              # CLI: verify audit chain offline
├── tests/
│   ├── unit/                      # test_core.py, test_l3_l4.py, test_l5.py
│   └── redteam/
│       ├── cases/injection.yaml   # attacks, benign text, known gaps, known false positives
│       ├── test_injection_corpus.py
│       └── promptfooconfig.yaml   # same attacks through the live gateway via promptfoo
└── .github/workflows/ci.yml       # pytest, then gateway + promptfoo
```

---

## How to use

### 1. Install

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env     # then set SENTINEL_AUDIT_KEY and SENTINEL_ADMIN_TOKEN
```

The gateway refuses to start without both values. Keep the admin token away from agents: it is what approves destructive actions.

### 2. Define what each agent may do

Edit `policies/agents.yaml`. Anything not listed is denied, and every tool must have a JSON Schema.

```yaml
agents:
  research-bot:
    tools:
      shell:
        schema: { type: object, properties: { cmd: { type: string, maxLength: 200 } }, required: [cmd], additionalProperties: false }
        rate_limit: 5/min
        approval: required
```

### 3. Run

```bash
set -a; source .env; set +a
uvicorn --factory sentinel.main:create_app --host 127.0.0.1 --port 8080
```

### 4. Call it from your agent runtime

```python
import httpx
G = "http://127.0.0.1:8080"

# L1: scan everything before it enters the model context
r = httpx.post(f"{G}/v1/scan", json={"agent": "research-bot", "items": [
    {"source": "external", "ref": "https://example.com", "text": page_text}]}).json()
if r["verdict"] == "block":
    ...                              # drop it, do not send to the model
context = r["tagged"]                # external text comes back wrapped in <untrusted>...</untrusted>

# L2: authorize every tool call before running it
d = httpx.post(f"{G}/v1/tool/authorize", json={"agent": "research-bot", "tool": "shell", "args": {"cmd": "ls"}}).json()
# d["decision"] is "allow" | "deny" | "pending"
```

Tell your model in its system prompt that text inside `<untrusted>` is data and never instructions.

### 5. Let SENTINEL run the tool (L3 + L4)

For tools with a `sandbox:` block in `policies/agents.yaml`, call `/v1/tool/run`. SENTINEL authorizes, mints a short-lived scoped token (if the tool lists `secrets`), runs the tool in a container, scans the output, audits everything, and returns the output already wrapped as `<untrusted>`.

```python
r = httpx.post(f"{G}/v1/tool/run", json={"agent": "research-bot", "tool": "summarize_report",
                                         "args": {"text": report}}).json()
# r["output"] is None if it was withheld (credentials, or injection in the output); see r["findings"]
```

- Tool args arrive on the container's stdin as JSON. The token arrives as the `SENTINEL_TOKEN` env var only. It is never in the prompt, the response, the process arguments, or the audit log.
- Containers run read-only, as `nobody`, all capabilities dropped, memory/CPU/PID limits, **no network** by default.
- Credentials found in output (cloud keys, private keys, JWTs, the issued token) withhold the whole output. Emails, card numbers, markdown-image exfil links and large base64 blobs are redacted.
- No Docker found means the call is denied. It never runs on the host.

**gVisor:** set `SENTINEL_SANDBOX_RUNTIME=runsc` (after installing and registering runsc with Docker).

**Allowlisted network access:** set `network: proxy` on the tool, then:

```bash
docker network create --internal sentinel-egress
python -m sentinel.sandbox.egress --listen 0.0.0.0:3128 --allowlist policies/egress.yaml   # run so it is reachable from that network and the internet
export SENTINEL_EGRESS_NETWORK=sentinel-egress SENTINEL_EGRESS_PROXY=http://<proxy-host>:3128
```

The proxy is the only exit. It allows HTTPS to listed hosts only and refuses IP literals and anything resolving to a private or metadata address.

**Smoke test on your host** (confirms Docker, hardening flags, and no-network actually work):

```bash
docker run --rm --network none --read-only --cap-drop ALL --user 65534:65534 python:3.12-slim \
  python -c "import socket; socket.create_connection(('1.1.1.1',443),2)"    # must fail
```

### 6. Approve destructive actions

A `pending` decision returns an `approval_id`. A human approves it, then the agent re-submits the **same** call with that id. Approvals are single-use and bound to the exact arguments.

```bash
export SENTINEL_ADMIN_TOKEN=...
python scripts/approve.py list
python scripts/approve.py approve <approval_id>     # or: deny
```

### 7. Verify the audit log

```bash
python scripts/verify_log.py          # prints OK or TAMPERED at entry id N
curl -H "X-Sentinel-Admin-Token: $SENTINEL_ADMIN_TOKEN" http://127.0.0.1:8080/v1/audit/verify
```

Prompts are logged as SHA-256 + length by default. Set `SENTINEL_LOG_CONTENT=1` to log raw text.

### 8. Plug in an ML classifier (NVIDIA NeMo Guardrails, Llama Guard, LLM Guard)

Write a class with `score(text) -> float` and set `SENTINEL_CLASSIFIER=my_pkg.backend:MyClass`. Scores at or above `SENTINEL_CLASSIFIER_THRESHOLD` count as a high-severity finding. The built-in rules always run too.

### 9. Test

```bash
pytest
```

### 10. Alerts (L5)

Every audit event is watched. Alerts are written back into the signed log as `alert` entries, logged, and optionally POSTed to a webhook (`SENTINEL_ALERT_WEBHOOK`).

| Rule | Fires when |
|---|---|
| `deny_spike` | many denied calls from one agent in a minute |
| `call_spike` | too many tool calls in a minute |
| `tool_after_blocked_input` | an agent requests a tool right after its input was blocked as an injection |
| `output_withheld` | a tool's output was withheld (credentials or injection in output) |
| `new_domain` | first request to a host, after the agent's learning period |
| `unusual_sequence` | a tool-to-tool transition never seen before, after the learning period |

```bash
curl -H "X-Sentinel-Admin-Token: $SENTINEL_ADMIN_TOKEN" http://127.0.0.1:8080/v1/alerts
```

Denied calls never teach the baseline, and baselines are rebuilt from the audit log on restart.

For tools that fetch URLs, add `allowed_hosts` in `policies/agents.yaml` (see `fetch_docs`). Every URL in the args must point at a listed host; IP literals (like cloud metadata addresses) and `allowed.com@evil.com` tricks are denied. The plain `web_fetch` example is deliberately permissive.

### 11. Red-team suite

```bash
pytest tests/redteam -rfEX            # corpus: attacks, benign text, known gaps
```

Current results on the bundled corpus (written by the same author as the rules, so treat it as a regression suite, not an independent benchmark): 16/16 attacks blocked, 10/10 benign allowed, **9 evasions undetected** (paraphrase, base64, Spanish, leetspeak, Cyrillic homoglyph, indirect task hijack, persona reset, authority claim) and **2 false positives** (a log line starting with `System:`, and a sentence about ignoring README instructions). Gaps are strict expected-failures: when you fix one, the suite fails until you move it to `attacks`.

```bash
python -m uvicorn --factory sentinel.main:create_app --port 8080 &
npx promptfoo@0.124.0 eval -c tests/redteam/promptfooconfig.yaml --no-cache
```

CI (`.github/workflows/ci.yml`) runs both.

---

## Integrations and standards

| Area | Approach |
|---|---|
| NVIDIA NeMo Guardrails / Jailbreak Detect NIM | Plug in via the classifier hook (L1) |
| promptfoo | Wired in (HTTP provider against the live gateway); run for real, 8/8 |
| garak | Not wired. It targets LLM endpoints, so it fits once SENTINEL proxies model traffic |
| OPA | Planned alternative to YAML for L2 |
| Regulated-industry expectations | Fail-closed defaults, separation of duties (agents cannot approve), single-use bound approvals, tamper-evident audit, content hashed in logs by default |

Known limits: alerts **notify, they do not block** (a deny/approve decision is still L2's job). Per-tool `allowed_hosts` checks URLs inside args only, not bare hostnames. Detector learning periods are call-count based. The rule-based L1 misses paraphrase, encoded, foreign-language and homoglyph attacks (see the red-team corpus) and has known false positives; use the classifier hook for those. Tokens are stateless bearer tokens (no revocation before expiry, capped at 5 minutes) and services must trust the SENTINEL key. The egress proxy is HTTPS-only. Credential detection is pattern-based, so unknown formats can slip through. HMAC signing is symmetric and tail truncation of the log is not detectable from the file alone (anchor `head` off-box for stronger guarantees). Approvals are in-memory and lost on restart. Agent-facing endpoints have no auth, so bind to localhost or put them behind your own network controls.

---

## Roadmap

| When | Deliverable |
|---|---|
| Done | L1 input filter, L2 policy engine, L3 sandbox, L4 secrets and output scanning, L5 audit log |
| Done | L5 anomaly detection and alerts; red-team corpus + promptfoo + CI workflow |
| Next | Ship a real classifier backend (NeMo Guardrails / Llama Guard) to close the corpus gaps; OPA policy option; proxy model traffic (then garak); token revocation |

## Design principles

- **Deny by default.** No allowlist entry, no execution.
- **External content is data, never instructions.**
- **No ambient credentials.** Tokens are short-lived, scoped, and never in the prompt.
- **Everything is logged,** and the log is tamper-evident.
