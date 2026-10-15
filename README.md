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

> [!WARNING]
> **Do not expose SENTINEL beyond localhost without agent auth *and* TLS.** With auth off (the default) every agent-facing endpoint trusts any caller that can reach the port. With auth on, tokens are bearer secrets sent in cleartext unless you terminate TLS. On startup SENTINEL logs a boxed warning if it detects a non-loopback bind (`--host 0.0.0.0` etc.); see section 15.

> **Status:** all five layers are built and tested: the suite reports 281 passed, 1 skipped and 42 xfailed (the skipped test is the OPA integration test, which runs when the `opa` binary is on PATH). That includes a 64-case red-team corpus (36 attacks blocked, 28 benign allowed). The corpus also pins **25 known detection gaps and 17 known false positives** of the rule layer as strict expected failures (section 11), so the rules alone are not complete. promptfoo was run against the live gateway (8/8). CI is written but has not been run on GitHub yet.
>
> Prompt Guard 2 (86M) has been measured on the red-team corpus (CPU, threshold 0.8): it catches 12 of the 25 known rule gaps (multilingual overrides, template spoofs, DAN-style, prompt extraction) and adds one benign false positive (the README-advice exemption). It misses instruction-shaped attacks without jailbreak phrasing (tool calls, file reads, exfiltration). Scores are near-binary, so the threshold has little effect between 0.2 and 0.9. The English-only 22M model is weaker (3 of 25 at 0.8, no new benign false positive) and is not recommended. The NIM backend remains unmeasured.
>
> It is a **decision API**: your agent runtime calls `/v1/scan` before content reaches the model, `/v1/tool/authorize` before any tool runs, or `/v1/tool/run` to have SENTINEL run a tool end to end (authorize, sandbox, scan output, audit). Optionally it also fronts your model endpoint (OpenAI-compatible or Anthropic Messages, see section 14), so prompts and completions are screened without agent-side changes.
>
> **OPA** is tested against a real OPA server (`opa test` plus integration tests). **garak:** a small baseline was run (garak 0.17, `llama3.2:1b` via Ollama on CPU, Prompt Guard 2 86M at 0.8, refusal block mode, `--generations 1`, probes `dan.Dan_11_0` and `promptinject.HijackHateHumans`). `AttackRogueString` attack success fell from 44.53% direct (142/256 ok) to 1.56% through SENTINEL (252/256 ok). `dan.Dan_11_0` is a single prompt: `dan.DAN` passed both ways. `MitigationBypass` failed 1/1 both ways, but in the proxy run the reply was the gateway's `[SENTINEL] blocked: input_blocked` message (the prompt was blocked), which that detector does not recognise as a refusal, so the proxy fail is a scoring artifact. To make blocks score as refusals in garak, the refusal text would need to contain refusal phrasing. This is a 1B model and two probes, not a full garak profile; `encoding` and `latentinjection` were not run. The model proxy is tested against fake upstreams and driven end to end by the official `anthropic` SDK, but not against a live provider.
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
        │  L3  SANDBOX                   │  Docker, gVisor-ready
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
| L3 Sandbox | Hardened Docker containers (gVisor via `runsc`), no ambient creds, egress allowlist, read-only FS | Built (verify on your host) |
| L4 Secrets & data | Short-lived scoped tokens, output scanning | Built |
| L5 Audit | Signed hash-chained log + anomaly alerts | Built |

**Stack:** Python / FastAPI proxy · YAML or OPA policy · Docker (+ gVisor `runsc`) · SQLite · garak / promptfoo

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
│   ├── netwarn.py                 # startup warning when the bind address is non-loopback
│   ├── limits.py                  # SQLite-backed rate-limit counters, auth lockout, agent quarantine
│   ├── serve.py                   # `python -m sentinel` launcher with built-in TLS
│   ├── __main__.py                # entry point for `python -m sentinel`
│   ├── pipeline.py                # ties L1 + L2 together, writes every decision to L5
│   ├── input_filter/              # L1
│   │   ├── rules.py               # injection regexes (EN/ES/FR/DE/IT/RU), homoglyph + leetspeak folding, base64/hex/ROT13 
│   │   │                          # decoding, hidden-unicode detection
│   │   ├── tagger.py              # wraps external content as <untrusted> data
│   │   ├── classifier.py          # backend loader + ensemble (SENTINEL_CLASSIFIER)
│   │   └── backends/
│   │       ├── nim.py             # NVIDIA NemoGuard JailbreakDetect NIM client
│   │       ├── prompt_guard.py    # Meta Llama Prompt Guard 2 (local, via transformers)
│   │       └── chunking.py        # overlapping windows; oversize input raises, never truncates
│   ├── auth.py                    # optional per-agent tokens for the agent-facing endpoints
│   ├── policy/                    # L2
│   │   ├── engine.py              # allowlist, JSON-schema args, host allowlist, rate limit, approval, preflight
│   │   ├── approvals.py           # SQLite-backed human-approval records (TTL, pending cap)
│   │   ├── opa.py                 # OPA REST client (fail closed); optional backend
│   │   └── hosts.py               # extracts URL hosts from tool args (parsed, not regexed)
│   ├── sandbox/                   # L3
│   │   ├── runner.py              # hardened docker run (gVisor-ready), fails closed
│   │   └── egress.py              # allowlisting HTTPS CONNECT proxy (blocks IP literals, private IPs)
│   ├── secrets/                   # L4
│   │   ├── broker.py              # short-lived scoped signed tokens, injected into sandbox env only
│   │   ├── revocation.py          # persistent jti denylist + per-agent kill switch
│   │   └── scanner.py             # output scan: credentials withheld, PII/exfil redacted
│   ├── proxy/
│   │   ├── model.py               # model proxy core: scan in, scan out, preflight tool calls, audit
│   │   ├── formats.py             # wire formats: OpenAI chat-completions, Anthropic Messages
│   │   └── openai.py              # earlier OpenAI-only proxy; not imported anywhere, superseded by model.py
│   └── audit/                     # L5
│       ├── log.py                 # hash-chained, HMAC-signed, append-only SQLite log
│       ├── detect.py              # anomaly rules: spikes, new domains, unusual sequences, ...
│       └── alerts.py              # alert sinks: log, webhook
├── policies/
│   ├── agents.yaml                # per-agent tool allowlists, schemas, limits, approvals, sandbox, secrets
│   ├── opa/                       # sentinel.rego + data.json + tests, used when SENTINEL_POLICY_BACKEND=opa
│   └── egress.yaml                # hosts sandboxes may reach through the proxy
├── scripts/
│   ├── approve.py                 # CLI: list / approve / deny pending actions
│   ├── eval_classifier.py         # measure rules + classifier on the red-team corpus
│   ├── garak_scan.sh              # garak against the model directly vs through SENTINEL
│   ├── sweep_threshold.py         # score the red-team corpus with the configured classifier and sweep the threshold
│   ├── sandbox_smoke.py           # L3 smoke test: drives the real Sandbox runner on a host with Docker (optionally gVisor)
│   ├── verify_log.py              # CLI: verify audit chain offline
│   └── verify_thinking_loop.py    # live check: extended-thinking tool loop + redacted_thinking: strip (needs a real Anthropic upstream)
├── tests/
│   ├── unit/                      # test_core, test_l3_l4, test_l5, test_classifier, test_opa, test_approvals,
│   │                              # test_revocation, test_agent_auth, test_netwarn, test_rules_false_positives,
│   │                              # test_limits, test_quarantine, test_proxy, test_proxy_anthropic, test_proxy_stream
│   └── redteam/
│       ├── cases/injection.yaml   # attacks (36), benign text (28), known gaps (25) and known false positives (17)
│       ├── test_injection_corpus.py
│       └── promptfooconfig.yaml   # same attacks through the live gateway via promptfoo
├── docs/
│   └── injection_eval.md          # study: does injected text move a small local model's verdict (section 17)
├── baseline.py, extend.py, forced.py, forced2.py, forced2_rep.py, noise_control.py   # study runners (section 17)
├── analyze_ext.py, analyze_v2.py, analyze_v3.py, domain_summary.py, strict.py        # study analysis
├── label_tool.py, label_agree.py, make_second_sheet.py, second_agree.py              # hand-labelling and agreement
├── *.jsonl, labels_*.json, baseline_result.txt                                       # study data and labels
└── .github/workflows/ci.yml       # opa test, pytest, then gateway + promptfoo
```

The root-level scripts and data files belong to the injection study in section 17. They are not part of the gateway and the `sentinel` package does not import them.

---

## How to use

### 1. Install

Requires Python 3.10+.

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env     # then set SENTINEL_AUDIT_KEY and SENTINEL_ADMIN_TOKEN
```

The gateway refuses to start without both values. Keep the admin token away from agents: it is what approves destructive actions.

### 2. Define what each agent may do

Edit `policies/agents.yaml` (or point `SENTINEL_POLICY` at another file). Anything not listed is denied, and every tool must have a JSON Schema.

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

> [!WARNING]
> Keep `--host 127.0.0.1`. Binding to `0.0.0.0` or any non-loopback address makes the gateway reachable from the network and triggers a startup warning (best effort: read from `SENTINEL_BIND_HOST`, `--host`, then `UVICORN_HOST`; under gunicorn or other launchers set `SENTINEL_BIND_HOST` yourself). Silence it with `SENTINEL_ACK_NONLOOPBACK=1` only after auth and TLS are in place.

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

**Endpoint reference**

| Endpoint | Auth | Purpose |
|---|---|---|
| `POST /v1/scan` | agent token (if auth on) | L1 scan of items before they reach the model |
| `POST /v1/tool/authorize` | agent token | L2 decision: `allow`, `deny` or `pending` |
| `POST /v1/tool/run` | agent token | authorize, sandbox, scan output, audit (sections 5, 13) |
| `POST /v1/chat/completions`, `POST /v1/messages` | agent token | model proxy on the gateway root, agent from `X-Sentinel-Agent` or the token (section 14) |
| `POST /proxy/{agent}/v1/chat/completions`, `POST /proxy/{agent}/v1/messages` | agent token | model proxy with the agent in the path |
| `GET /healthz` | any agent token or admin token | liveness, returns `{"ok": true}` |
| `GET /v1/status` | admin | active classifier, fail mode, policy backend, whether the model proxy is mounted |
| `GET /v1/approvals`, `POST /v1/approvals/{id}/approve`, `POST /v1/approvals/{id}/deny` | admin | human approval queue (section 6) |
| `GET /v1/alerts` | admin | recent alerts (section 10) |
| `GET /v1/quarantine` | admin | agents currently quarantined (section 10) |
| `POST /v1/agents/{agent}/release` | admin | lift an agent's quarantine |
| `GET /v1/audit/verify` | admin | verify the audit chain (section 7) |
| `POST /v1/tokens/{jti}/revoke`, `POST /v1/agents/{agent}/revoke-tokens` | admin | token revocation (section 13) |
| `POST /v1/token/verify` | verifier token | services check a token and scope, including revocation (section 13) |

The model proxy routes exist only when `SENTINEL_UPSTREAM_URL` is set. "Admin" means the `X-Sentinel-Admin-Token` header; "verifier" means `X-Sentinel-Verifier-Token`.

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

**Smoke test on your host** (confirms Docker, hardening flags, and no-network actually work). `scripts/sandbox_smoke.py` drives the same `Sandbox` runner SENTINEL uses and checks no network and no DNS, read-only root, `/tmp` noexec, non-root user, dropped capabilities, `no-new-privileges`, memory and PID limits, timeout kill, secret passed by env only (never in the `docker` argv), host env not visible, and stdin args. It exits 0 only if every check passes:

```bash
python scripts/sandbox_smoke.py                                   # plain Docker (runc)
SENTINEL_SANDBOX_RUNTIME=runsc python scripts/sandbox_smoke.py   # gVisor
python scripts/sandbox_smoke.py --image python:3.12-slim          # choose the test image
```

Or the one-line version of the network check:

```bash
docker run --rm --network none --read-only --cap-drop ALL --user 65534:65534 python:3.12-slim \
  python -c "import socket; socket.create_connection(('1.1.1.1',443),2)"    # must fail
```

### 6. Approve destructive actions

A `pending` decision returns an `approval_id`. A human approves it, then the agent re-submits the **same** call with that id. Approvals are single-use and bound to the exact arguments.

Approvals are **persisted in SQLite** (`SENTINEL_APPROVAL_DB`, default the audit DB), so pending requests and grants survive a restart. A pending request expires `SENTINEL_APPROVAL_TTL` seconds (default 86400) after it was created, and a decided one that long after the decision; an expired id is simply denied when the agent re-submits. At most `SENTINEL_APPROVAL_MAX_PENDING` (default 1000) requests can be pending; beyond that new ones are denied (`too many pending approvals`). The tool arguments are stored in plaintext **only while the request is pending** (the approver has to see them) and are cleared when it is approved or denied, so protect the DB file like the audit DB. Rate-limit counters and auth lockout are persisted too (`SENTINEL_LIMITS_DB`, default the audit DB).

```bash
export SENTINEL_ADMIN_TOKEN=...
python scripts/approve.py list               # SENTINEL_URL overrides the default http://127.0.0.1:8080
python scripts/approve.py approve <approval_id>     # or: deny
```

### 7. Verify the audit log

```bash
python scripts/verify_log.py          # prints OK or TAMPERED at entry id N (optional arg: path to the audit DB; needs SENTINEL_AUDIT_KEY)
curl -H "X-Sentinel-Admin-Token: $SENTINEL_ADMIN_TOKEN" http://127.0.0.1:8080/v1/audit/verify
```

Prompts are logged as SHA-256 + length by default. Set `SENTINEL_LOG_CONTENT=1` to log raw text.

### 8. ML classifier backends (L1)

The rules are pattern-based. They cover English, Spanish, French, German, Italian and Russian override phrasings, a set of paraphrase and persona patterns, homoglyph and leetspeak folding, and base64, hex and ROT13 payloads, all exercised by the red-team corpus. Anything outside those patterns (novel paraphrase, other languages, other encodings) will get through, and the corpus lists 25 such known gaps, so add a model with `SENTINEL_CLASSIFIER`:

| Backend | What it is | Runs | Needs |
|---|---|---|---|
| `nim` | NVIDIA NemoGuard JailbreakDetect, the jailbreak model behind NeMo Guardrails' jailbreak rail. Calls `POST /v1/classify`. | Separate service you host | NGC key and NVIDIA GPU; set `SENTINEL_NIM_URL` |
| `prompt_guard` | Meta Llama Prompt Guard 2, a small binary injection/jailbreak classifier (86M multilingual, or 22M English-only) | In-process, text never leaves the host | `pip install -e ".[ml]"`, accept Meta's license on Hugging Face (gated), `HF_TOKEN` |
| `module:Class` | Your own class with `score(text) -> float` | Anywhere | none |

Note: **Llama Guard** (Meta's generative content-safety model) is a different tool for a different job (harmful content, not injection), so it is not wired in. Prompt Guard 2 is Meta's injection detector.

```bash
export SENTINEL_CLASSIFIER=prompt_guard          # or nim, or nim,prompt_guard (ensemble: highest score wins)
export SENTINEL_CLASSIFIER_ON_ERROR=closed       # default
curl -H "X-Sentinel-Admin-Token: $SENTINEL_ADMIN_TOKEN" localhost:8080/v1/status   # shows which classifier is active
python scripts/eval_classifier.py                # measure it on the red-team corpus
python scripts/sweep_threshold.py [--csv scores.csv]   # raw model scores on the corpus, swept over thresholds (calls the backend directly, no rules)
```

Behaviour you should know:
- **Fail closed by default.** If the classifier errors or times out, the input is **blocked** (`classifier_error`). Set `SENTINEL_CLASSIFIER_ON_ERROR=open` to fall back to rules only (`classifier_unavailable`); the choice is yours, availability versus protection. Either way a `classifier_degraded` alert fires, so silent degradation can't go unnoticed.
- **A configured backend that can't load stops startup.** The gateway never quietly runs rules-only.
- **Long documents are scored in full** in overlapping windows (Prompt Guard has a ~512-token window). Input that would need more than the chunk limit (default 32) is treated as an error, not truncated, because truncation is an evasion route. Raise `SENTINEL_NIM_MAX_CHUNKS` / `SENTINEL_PG_MAX_CHUNKS` if you handle large pages.
- **Cost:** every item goes through the model, and ensembles run all members. Expect added latency per scan.
- **Data:** with `nim`, document text goes to wherever `SENTINEL_NIM_URL` points. It defaults to localhost; do not point it at a hosted endpoint for sensitive content.
- NIM tuning: `SENTINEL_NIM_TIMEOUT` (seconds, default 5), `SENTINEL_NIM_MAX_CHARS` (window size, default 4000), `SENTINEL_NIM_MODEL` (only needed behind NeMo's NIM Proxy). These are read by the code but not listed in `.env.example`. `SENTINEL_NIM_API_KEY` is sent to the NIM if set. For `prompt_guard`, `SENTINEL_PG_MODEL` (default `meta-llama/Llama-Prompt-Guard-2-86M`), `SENTINEL_PG_DEVICE` (e.g. `0` for the first GPU) and `SENTINEL_PG_MAX_CHUNKS` (default 32) tune the local model.
- Scores at or above `SENTINEL_CLASSIFIER_THRESHOLD` (default 0.8) are a high-severity finding. For `nim` the score is 1.0 or 0.0 from its boolean verdict. The NIM's own score field is not interpreted.

### 9. Test

```bash
pytest
```

The `opa`-backed integration test in `tests/unit/test_opa.py` is skipped when the `opa` binary is not on PATH. A full run reports 281 passed, 1 skipped (the OPA test) and 42 xfailed: the 25 known gaps and 17 known false positives in the red-team corpus, which are expected to fail (section 11).

### 10. Alerts (L5)

Every audit event is watched. Alerts are written back into the signed log as `alert` entries, logged, and optionally POSTed to a webhook (`SENTINEL_ALERT_WEBHOOK`).

| Rule | Fires when |
|---|---|
| `deny_spike` | many denied calls from one agent in a minute (`SENTINEL_DENY_LIMIT`, default 10) |
| `call_spike` | too many tool calls in a minute (`SENTINEL_CALL_LIMIT`, default 60) |
| `tool_after_blocked_input` | an agent requests a tool right after its input was blocked as an injection |
| `output_withheld` | a tool's output was withheld (credentials or injection in output) |
| `new_domain` | first request to a host, after the agent's learning period |
| `unusual_sequence` | a tool-to-tool transition never seen before, after the learning period |
| `auth_failure_spike` | many failed agent-auth attempts from one client address (`SENTINEL_AUTH_ALERT_LIMIT`, section 15) |
| `classifier_degraded` | the ML classifier errored or timed out, so screening fell back to a block or to rules only (section 8) |
| `policy_backend_degraded` | OPA returned an error or undefined result (section 12) |

```bash
curl -H "X-Sentinel-Admin-Token: $SENTINEL_ADMIN_TOKEN" http://127.0.0.1:8080/v1/alerts
```

Denied calls never teach the baseline, and baselines are rebuilt from the audit log on restart.

**Learning period.** `new_domain` and `unusual_sequence` stay silent while an agent is learning. Default: its first `SENTINEL_LEARN_CALLS` (50) allowed calls. Set `SENTINEL_LEARN_SECONDS` (> 0) to make it time based instead: the agent learns for that many seconds after its first allowed call, regardless of call volume, so flooding calls cannot end the period early. The clock is rebuilt from the audit log on restart.

**Quarantine (alert -> block, opt-in).** Set `SENTINEL_ALERT_BLOCK` to a comma list drawn from `deny_spike`, `call_spike`, `tool_after_blocked_input`, `output_withheld`, `new_domain`, `unusual_sequence`. When one of those fires for an agent, that agent is quarantined for `SENTINEL_QUARANTINE_SECONDS` (default 900): `/v1/tool/*` is denied, `/v1/scan` returns `block`, and the model proxy returns 403 `agent_quarantined`. A quarantine never extends itself while active. It is stored in SQLite (`SENTINEL_LIMITS_DB`), so it survives a restart, and is written to the signed log as a `quarantine` entry. `auth_failure_spike` cannot be used here (its agent name is attacker-claimed; the client lockout covers it). Unset = notify only.

```bash
curl -H "X-Sentinel-Admin-Token: $SENTINEL_ADMIN_TOKEN" http://127.0.0.1:8080/v1/quarantine
curl -X POST -H "X-Sentinel-Admin-Token: $SENTINEL_ADMIN_TOKEN" http://127.0.0.1:8080/v1/agents/research-bot/release
```

For tools that fetch URLs, add `allowed_hosts` in `policies/agents.yaml` (see `fetch_docs`). Every URL in the args must point at a listed host; IP literals (like cloud metadata addresses) and `allowed.com@evil.com` tricks are denied. The plain `web_fetch` example is deliberately permissive.

### 11. Red-team suite

```bash
pytest tests/redteam -rfEX            # corpus: attacks, benign text, known gaps
```

Current results on the bundled corpus (written by the same author as the rules, so treat it as a regression suite, not an independent benchmark): 36/36 attacks blocked and 28/28 benign allowed by the rules alone. The corpus also records what the rules **do not** handle, as strict expected failures (`xfail(strict=True)`):

- **25 known detection gaps** (`known_gaps` in `tests/redteam/cases/injection.yaml`): attacks the rules miss. Examples: Chinese, Japanese, Portuguese and Dutch overrides; letter-spaced and reversed text (`i g n o r e ...`); `[INST]` and `<system>` template spoofs; "what were your original instructions" style prompt-extraction; persona games (AIM, DAN mode); tool-call and file-read requests phrased as plain instructions; markdown-image exfiltration and hidden `display:none` HTML. These need the ML classifier layer (section 8).
- **17 known false positives** (`known_false_positives`): benign text the rules wrongly block. Examples: "Enable Developer mode in Settings", "You are now logged in", a paper about jailbreak attacks, "ignore the previous paragraph; it contained a typo", French, Italian and Russian "don't forget to read the instructions", and a `User:` / `Assistant:` chat transcript.

Two earlier false positives, a `System: Ubuntu 24.04 LTS` header line and advice to ignore a README's instructions, are handled by narrow exemptions in `rules.py` (see below), each pinned by near-miss attacks in the corpus. Attacks the rules do catch cover English overrides and paraphrase, Spanish, French, German, Italian and Russian, base64, hex and ROT13, leetspeak, Cyrillic homoglyphs, fullwidth and zero-width characters, hidden tag characters, persona resets, authority claims and exfiltration instructions.

Gaps and false positives are strict expected-failures: when you fix one, the suite fails until you move it to `attacks` or `benign`. The strict-xfail corpus assumes rules only. With a classifier enabled, use `scripts/eval_classifier.py` instead, which reports how many known gaps are now caught.

```bash
python -m uvicorn --factory sentinel.main:create_app --port 8080 &
npx promptfoo@0.124.0 eval -c tests/redteam/promptfooconfig.yaml --no-cache
```

CI (`.github/workflows/ci.yml`) runs both.

### 12. OPA policy backend (L2)

YAML keeps describing what each tool *is* (JSON Schema, sandbox, secrets, rate limit). OPA decides who may call it.

```bash
opa run --server --addr 127.0.0.1:8181 policies/opa      # sentinel.rego + data.json
export SENTINEL_POLICY_BACKEND=opa SENTINEL_OPA_URL=http://127.0.0.1:8181
opa test policies/opa -v
```

Other OPA settings: `SENTINEL_OPA_PATH` (default `sentinel/authz/decision`), `SENTINEL_OPA_TIMEOUT` (seconds, default 2) and `SENTINEL_OPA_TOKEN` (bearer token for the OPA server, empty by default).

OPA receives `{agent, tool, args, hosts}` and returns `data.sentinel.authz.decision = {effect: allow|deny|approve, reason}`.

- **Strictest wins.** Schema, YAML `allowed_hosts` and `approval: required` still apply; OPA can only add restrictions or require approval. A tool must exist in YAML, so OPA cannot invent one.
- **Fail closed.** OPA down, timeout, undefined result, unknown effect: deny, and a `policy_backend_degraded` alert fires. Startup fails if OPA is unreachable or the policy is not loaded.
- The example policy shows what YAML cannot do: it inspects argument content (`rm -rf` is denied even for an agent with an approval grant).
- Rate limits and approvals stay in the gateway (they need state); OPA stays a pure decision function.

### 13. Token revocation (L4)

- A token is revoked automatically **when its tool call finishes** (the container has exited, so nothing legitimate still needs it).
- Admin: `POST /v1/tokens/{jti}/revoke` (find the jti in the `run` audit entries) and `POST /v1/agents/{agent}/revoke-tokens` (kills every token that agent holds now; tokens issued afterwards work).
- The denylist is in SQLite (`SENTINEL_REVOKE_DB`, default the audit DB), survives restarts, and prunes itself once a revoked token could no longer be valid. Admin revocations are written to the audit log.
- **Services must verify through the gateway** to see revocations: `POST /v1/token/verify {token, scope}`. Authenticate with `X-Sentinel-Verifier-Token` (`SENTINEL_VERIFIER_TOKEN`) so services never hold the admin token. Verifying offline with the shared key checks signature and expiry only.

### 14. Model-traffic proxy (and garak)

Set `SENTINEL_UPSTREAM_URL` (and `SENTINEL_UPSTREAM_KEY`; the gateway holds it, agents never see a provider key) and point your agent's OpenAI client at SENTINEL:

```python
OpenAI(base_url="http://127.0.0.1:8080/proxy/research-bot/v1", api_key="unused")        # /v1/chat/completions
Anthropic(base_url="http://127.0.0.1:8080/proxy/research-bot", api_key="unused")        # /v1/messages
# or POST /v1/chat/completions | /v1/messages on the gateway root with header X-Sentinel-Agent: research-bot
```

Proxy settings: `SENTINEL_PROXY_BLOCK_MODE` (`error`, the default, or `refusal`), `SENTINEL_PROXY_TOOLCALLS` (`enforce`, the default, or `off` to skip preflight of model-proposed tool calls) and `SENTINEL_PROXY_STREAM` (`buffered`, the default, or `reject`).

The upstream must speak the format you call (the proxy does not translate between them). The agent's own `Authorization` / `x-api-key` / `anthropic-beta` headers are never forwarded; `anthropic-version` is (default `2023-06-01`).

| Direction | What happens |
|---|---|
| Request | `user` messages are scanned (L1); `tool` messages are scanned **and wrapped as `<untrusted>`**. Blocked: 403 `input_blocked`, upstream never called |
| Response text | L4 output scan: credentials withhold the response (403 `output_withheld`), PII/exfil is redacted |
| Response tool calls | Each proposed call is preflighted against L2 (allowlist, schema, hosts, OPA). Any denial blocks the response (403 `tool_denied`). Rate limits and human approval still apply when your runtime calls `/v1/tool/authorize`; preflight consumes neither |
| Audit | One `model` event per request (hashes only unless `SENTINEL_LOG_CONTENT=1`); denied proposed calls also log as `tool` events so `deny_spike` sees them |

Anthropic specifics: `tool_result` blocks are treated as external data (scanned, wrapped `<untrusted>`); `tool_use` blocks are the proposed calls; the top-level `system` prompt is trusted and not scanned unless `scan: [system]` is set; refusal mode returns a `message` with `stop_reason: "refusal"`.

**Streaming (`stream=true`) is buffered, not pass-through.** SENTINEL calls the upstream non-streaming, scans and preflights the *complete* reply, and only then re-emits it to the agent as SSE in the caller's format (`chat.completion.chunk` + `[DONE]` for OpenAI; `message_start` ... `message_stop` for Anthropic). Agent code that sets `stream=true` works unchanged and nothing unscanned is ever sent. Consequences: there is **no time-to-first-token benefit** (the whole reply is held until it is scanned; `SENTINEL_UPSTREAM_TIMEOUT` defaults to 300s to cover full generation time), and real pass-through streaming cannot be made safe for credential withholding. A blocked or failed streamed request returns an ordinary JSON error (403 / 502 / upstream status), as providers do for failures before the first event; in `refusal` block mode the refusal is streamed like a normal reply. `stream` and `stream_options` are never forwarded upstream, but `stream_options.include_usage` is honoured in the re-emitted stream. Text, thinking and tool-argument deltas are cut into 32-character pieces so client UIs look like token streaming; this is cosmetic, since the reply is already fully scanned. Set `SENTINEL_PROXY_STREAM=reject` to get the old behaviour (400 `streaming_unsupported`). Audit `model` events for streamed requests carry `stream: "buffered"`.

Streaming troubleshooting:

- **Replies cut off or time out.** A reverse proxy in front of SENTINEL needs a read timeout above `SENTINEL_UPSTREAM_TIMEOUT` (default 300s), because nothing is sent until the full reply has been generated and scanned (section 16).
- **404 on the proxy routes.** The model proxy is mounted only when `SENTINEL_UPSTREAM_URL` is set.
- **Plain JSON instead of an event stream.** A blocked or failed streamed request returns an ordinary JSON error (403, 502 or the upstream status), not SSE. Clients should check the HTTP status before parsing events.

Limits: only text is scanned (images, audio, documents pass through unless the agent sets `non_text: block` in `agents.yaml`, which rejects such requests with 403 `non_text_blocked`); the system prompt and assistant history are not scanned unless the agent opts in with `scan: [system, assistant]` in `agents.yaml` (system at user tolerance, assistant turns at the stricter external tolerance; assistant text, replayed tool-call arguments (`tool_use` inputs, OpenAI `tool_calls`/`function_call`) `thinking` blocks and JSON object keys inside tool-call inputs are all scanned, never rewritten; `redacted_thinking` is provider-encrypted and cannot be read: it is forwarded as-is by default, or removed from replayed history with `redacted_thinking: strip` per agent (audit records `redacted_thinking_stripped`; blocks in the open tool-use loop, after the last non-tool-result user turn, are kept so extended thinking with tools still works)), and reasoning fields are never scanned. Clean text is cached by hash so a growing conversation is not rescanned every turn.

**garak** now fits because there is an LLM endpoint to aim it at. Run the same probes straight at the model and through SENTINEL; the gap is what the gateway stops.

```bash
pip install garak
export SENTINEL_PROXY_BLOCK_MODE=refusal     # blocks come back as a 200 content_filter completion; garak aborts on HTTP errors
scripts/garak_scan.sh direct <model>         # baseline (needs UPSTREAM_URI, UPSTREAM_KEY)
scripts/garak_scan.sh proxy  <model>         # through SENTINEL as agent "garak-target" (no tools)
```

To check that `redacted_thinking: strip` does not break extended-thinking tool loops, run `scripts/verify_thinking_loop.py` against a running gateway whose upstream is the real Anthropic API (it needs `SENTINEL_AUDIT_KEY` and the same `SENTINEL_AUDIT_DB`; add `SENTINEL_AGENT_TOKEN` if agent auth is on). It has not been run in the build environment.

garak scores model behaviour, so a result is "model + SENTINEL", not SENTINEL alone. The rules-only L1 will miss many garak probes (encodings, paraphrase); run with a classifier backend for a meaningful number.

### 15. Agent authentication (optional)

> [!WARNING]
> **Auth off + non-loopback bind = open gateway.** Auth on + non-loopback bind without TLS = tokens readable on the wire. Either combination logs a startup warning.

By default the agent-facing endpoints trust whoever can reach them, so you bind to localhost. To close that gap, give each agent its own token:

```bash
export SENTINEL_AGENT_TOKENS="research-bot=$(openssl rand -hex 24),garak-target=$(openssl rand -hex 24)"
# or SENTINEL_AGENT_TOKENS_FILE=tokens.json:  {"research-bot": ["<new>", "<old>"], "garak-target": "<token>"}   (a list = rotation)
# file tokens can expire: {"research-bot": [{"token": "<old>", "expires": "2026-12-31T00:00:00Z"}, "<new>"]}
```

With tokens set, `/v1/scan`, `/v1/tool/authorize`, `/v1/tool/run` and the model proxy all require a token **that belongs to the agent being claimed**, so agent A cannot borrow agent B's policy, rate limits, approvals or audit identity (401 for a missing or invalid token, 403 for a valid token used for another agent). Send it as `Authorization: Bearer`, `x-api-key` or `X-Sentinel-Agent-Token`; for the proxy that means the SDK's own `api_key` is the agent token (the proxy never forwards it upstream):

```python
OpenAI(base_url="http://127.0.0.1:8080/proxy/research-bot/v1", api_key=AGENT_TOKEN)
Anthropic(base_url="http://127.0.0.1:8080/proxy/research-bot", api_key=AGENT_TOKEN)
# on the root routes (/v1/chat/completions, /v1/messages) X-Sentinel-Agent can be omitted: the token identifies the agent
```

- **Fail closed.** An agent with no token configured cannot authenticate once auth is on. Startup refuses tokens that are under 16 characters, name an agent missing from policy, are shared by two agents, or equal the admin or verifier token (an agent must not be able to approve its own requests).
- **`/healthz`** needs any valid agent token or the admin token (`X-Sentinel-Admin-Token`), and returns only `{"ok": true}`. Probes that cannot send headers (some load balancers, Docker `HEALTHCHECK` without a header) cannot use it. Classifier, fail mode, policy backend and proxy state are served at `GET /v1/status` with the admin token. Admin and verifier endpoints keep their own credentials, which an agent token does not satisfy.
- **Audit.** Failures are logged as `auth` events (agent claimed, reason, client address, path; never the token), at most one per agent, reason and client every 10 seconds so an unauthenticated caller cannot flood the log. Every failure is still counted before that throttle: `SENTINEL_AUTH_ALERT_LIMIT` (default 10) failures from one client address in 60s raises an `auth_failure_spike` alert (cooldown 60s per client).
- **Expiry.** In the token file a token can be `{"token": "...", "expires": "<ISO 8601>"}` (no timezone = UTC). Past that time it is rejected as invalid and audited as `expired agent token`, so a rotation's old token can be given an end date. Tokens from `SENTINEL_AGENT_TOKENS` take the same end date as a suffix: `research-bot=<token>;expires=2026-12-31T00:00:00Z`. Set `SENTINEL_REQUIRE_TOKEN_EXPIRY=1` to refuse to start while any token, from either source, has no expiry.
- **Lockout.** After `SENTINEL_AUTH_MAX_FAILURES` (default 10) invalid tokens from one client address within `SENTINEL_AUTH_FAILURE_WINDOW` seconds (60), that client gets `429` with `Retry-After` for `SENTINEL_AUTH_LOCKOUT_SECONDS` (300), even with a valid token. Missing tokens and a valid token used for the wrong agent (403) do not count. It is keyed by client address, not agent, so guessing an agent's name cannot lock that agent out. Behind a reverse proxy all callers share the proxy's address, so rate-limit per client at the proxy too. State is in SQLite (`SENTINEL_LIMITS_DB`, default the audit DB) and survives a restart.
- **TLS.** Tokens are bearer secrets, so they need TLS off localhost. `python -m sentinel` serves TLS itself (`SENTINEL_TLS_CERT`, `SENTINEL_TLS_KEY`) and refuses plain HTTP on a non-loopback host; `SENTINEL_REQUIRE_TLS=1` makes startup fail for any non-loopback bind without TLS (section 16). Alternatives: a TLS-terminating proxy or a private network.

### 16. Deploying with TLS

Anything beyond localhost needs TLS from one of the options below, plus agent auth (section 15). Without both, tokens and prompts cross the network in cleartext. Set `SENTINEL_REQUIRE_TLS=1` to make startup fail on a non-loopback bind that has no TLS.

**Option A: SENTINEL terminates TLS.** `python -m sentinel` (a thin uvicorn launcher), fine for a single host.

```bash
export SENTINEL_AGENT_TOKENS="research-bot=$(openssl rand -hex 24);expires=2026-12-31T00:00:00Z"
export SENTINEL_REQUIRE_TLS=1 SENTINEL_REQUIRE_TOKEN_EXPIRY=1
SENTINEL_HOST=0.0.0.0 SENTINEL_PORT=8443 SENTINEL_TLS_CERT=/etc/sentinel/cert.pem SENTINEL_TLS_KEY=/etc/sentinel/key.pem python -m sentinel
```

Plain uvicorn with `--ssl-keyfile` and `--ssl-certfile` works the same way:

```bash
export SENTINEL_AGENT_TOKENS="research-bot=$(openssl rand -hex 24)"
export SENTINEL_ACK_NONLOOPBACK=1        # only after TLS + auth are in place
uvicorn --factory sentinel.main:create_app --host 0.0.0.0 --port 8443 \
  --ssl-keyfile /etc/sentinel/key.pem --ssl-certfile /etc/sentinel/cert.pem
```

Checked with a self-signed certificate on loopback: `https://` answered and plain `http://` against the same port was refused. Not checked on a real network or with a CA-issued certificate.

- The startup check recognises `--ssl-keyfile`/`--ssl-certfile` and `SENTINEL_TLS_CERT`/`SENTINEL_TLS_KEY`, so it stays quiet when auth and TLS are both on. Without TLS it warns until `SENTINEL_ACK_NONLOOPBACK=1` is set (use that for proxy-terminated TLS).
- Uvicorn reads the certificate files at startup. Renewing a certificate means restarting the gateway. Approvals, revocations and the audit log live in SQLite and survive that; rate-limit counters and auth lockout state live in SQLite too (`SENTINEL_LIMITS_DB`).
- The gateway sees real client addresses, so lockout and `auth_failure_spike` work per client.

**Option B: TLS-terminating reverse proxy.** Keep SENTINEL on `127.0.0.1:8080` and let the proxy hold the certificate and renew it. A minimal Caddy config (not tested here):

```
sentinel.example.com {
    reverse_proxy 127.0.0.1:8080 {
        transport http { response_header_timeout 330s }
    }
}
```

- Set the proxy's read or response timeout above `SENTINEL_UPSTREAM_TIMEOUT` (default 300s). SENTINEL holds the whole model reply until it is scanned, including for `stream=true`, so a short proxy timeout cuts off slow generations.
- Every caller then appears to come from the proxy's address, so SENTINEL's lockout and `auth_failure_spike` treat all clients as one. Rate-limit per client at the proxy too.
- Do not publish port 8080 itself; bind SENTINEL to loopback or a private interface so the proxy is the only way in.

**Option C: private network or service mesh** (WireGuard, mesh mTLS) when everything stays inside one trust boundary.

**Per-client limits at the proxy.** SENTINEL's rate limits (per agent and tool) and its auth lockout (per client address) are persisted in SQLite and survive a restart; workers sharing one DB file share counters, separate replicas do not. Behind a proxy the lockout also sees one address for everyone. Put the durable, per-client limits in the proxy instead. A minimal nginx sketch (not tested here):

```nginx
limit_req_zone  $binary_remote_addr zone=sentinel_req:10m rate=20r/s;
limit_conn_zone $binary_remote_addr zone=sentinel_conn:10m;

server {
    listen 443 ssl;
    server_name sentinel.example.com;
    # ssl_certificate / ssl_certificate_key ...
    location / {
        limit_req  zone=sentinel_req burst=40 nodelay;
        limit_conn sentinel_conn 20;
        limit_req_status 429;
        proxy_read_timeout 330s;               # above SENTINEL_UPSTREAM_TIMEOUT
        proxy_pass http://127.0.0.1:8080;
    }
}
```

- This caps request volume per client address. It does not replace the per-tool limits in `policies/agents.yaml`, which are persisted in SQLite, so a restart does not reset those counters.
- Caddy has no built-in rate limiter; it needs a plugin such as `caddy-ratelimit`.
- A proxy cannot tell failed authentications from good ones unless you add rules for 401 responses (for example fail2ban on the proxy log). SENTINEL's own lockout still applies, but per proxy address.

**Clients must verify the certificate.** Point them at your CA bundle, for example `httpx.Client(verify="/path/ca.pem")` or `SSL_CERT_FILE`, and do not disable verification. Set `base_url` to the `https://` address, including for the OpenAI and Anthropic SDKs (section 14).

**Health checks.** `/healthz` needs a valid agent or admin token (section 15), so probes that cannot send headers cannot use it. Probe through a client that can send `X-Sentinel-Admin-Token`.

### 17. Injection evaluation study (research notes, separate from the gateway)

`docs/injection_eval.md` reports an experiment on whether text injected into a domain-reputation prompt changes a small local model's assessment. It uses `llama3.2:1b` served by Ollama at `127.0.0.1:11434`, prompts taken from a garak `latentinjection.LatentWhois` run, and 13 domains (4 exploration, 9 replication). The scripts query the model directly, so **SENTINEL is not in the path** and the results say nothing about what the gateway blocks.

Headline findings (revised Oct 15, 2026; see the document for methods, tables and limitations):

- Injected text roughly doubles how often the reply contains "not malicious" (40% vs 21%, p=0.007), partly because the model echoes the payload.
- The free-text benign verdict shows no significant change: 72% vs 67% on the keyword classifier (p=0.52) and 72% vs 64% on 96 hand labels per arm (p=0.28), which is underpowered rather than evidence of no effect.
- In the forced-label measure, injected text raised P(benign) about 3 points more than length-matched neutral text, in all nine unseen domains. No payload or wrapper stood out, and an earlier lead for the "Ignore previous instructions" payload did not replicate and is retracted.
- How the answer is phrased moves the verdict far more than any injection does.

To rerun, start the model server and follow "Reproducing the runs" in the document. The runners read a garak report from `~/.local/share/garak/garak_runs/garak_sentinel_capped.report.jsonl`, which is not in the repo. The `.jsonl` and `labels_*.json` files in the repo root are the outputs and hand labels from the reported runs.

---

## Integrations and standards

| Area | Approach |
|---|---|
| NVIDIA NemoGuard JailbreakDetect NIM | Built-in `nim` backend (L1). NeMo Guardrails itself (the framework) is not used |
| Meta Llama Prompt Guard 2 | Built-in `prompt_guard` backend (L1) |
| promptfoo | Wired in (HTTP provider against the live gateway); run for real, 8/8 |
| garak | `scripts/garak_scan.sh` runs it against the model directly or through the proxy (section 14); small baseline run, see the status note; full probe set not run |
| OPA | Optional L2 decision backend (section 12), tested against a real OPA server |
| Regulated-industry expectations | Fail-closed defaults, separation of duties (agents cannot approve), single-use bound approvals, tamper-evident audit, content hashed in logs by default |

Known limits: Prompt Guard 2 is measured on the red-team corpus only (see the status note); the NIM backend is still unmeasured, the garak baseline covers only two probes on a 1B model, and a classifier is itself attackable, so keep L2 to L4 in place. Alerts only notify unless you opt in to quarantine with `SENTINEL_ALERT_BLOCK` (section 10). Per-tool `allowed_hosts` checks URLs inside args only, not bare hostnames. Learning periods are call-count based unless `SENTINEL_LEARN_SECONDS` is set (section 10). The rule-based L1 only catches the patterns and languages listed in section 8; use the classifier hook for everything else. Two narrow benign exemptions exist (a short capitalised `System:`/`Assistant:` value that has a digit or is followed by another `Label: value` line and contains no directive words; and "you can/may/should ignore/skip the previous instructions in the README/docs if/when/unless ..."). They are intentionally strict, so close variants such as a lone `System: Dell XPS` line still block, and an attacker who phrases an override exactly in the advice form scoped to a document would pass the rule layer. Tokens are signed bearer tokens capped at 5 minutes; revocation is enforced only for verifiers that call `/v1/token/verify` (offline verification with the shared key cannot see it) and services must trust the SENTINEL key. The model proxy streams only in buffered mode (no latency benefit) and does not scan non-text content (set `non_text: block` per agent to refuse it). The egress proxy is HTTPS-only. Credential detection is pattern-based, so unknown formats can slip through. HMAC signing is symmetric and tail truncation of the log is not detectable from the file alone (anchor `head` off-box for stronger guarantees). Agent-facing endpoints have no auth unless you set `SENTINEL_AGENT_TOKENS` (section 15); without it, bind to localhost or put them behind your own network controls. Agent tokens are bearer secrets (serve TLS with `python -m sentinel`, or put TLS in front; `SENTINEL_REQUIRE_TLS=1` enforces it), expiry is opt-in per token (`SENTINEL_REQUIRE_TOKEN_EXPIRY=1` enforces it), and lockout is per client address.

---

## Roadmap

| When | Deliverable |
|---|---|
| Done | L1 input filter, L2 policy engine, L3 sandbox, L4 secrets and output scanning, L5 audit log |
| Done | L5 anomaly detection and alerts; red-team corpus + promptfoo + CI workflow |
| Done | Classifier backends: NVIDIA JailbreakDetect NIM, Prompt Guard 2, ensemble, fail-closed error policy |
| Done | OPA policy option; token revocation; model proxy (OpenAI + Anthropic formats); garak harness |
| Next | Close the 25 known detection gaps and 17 known false positives in the red-team corpus (the ML backends are the intended fix for the gaps) |
| Done | Prompt Guard 2 measured on the red-team corpus (86M: 12/25 gaps caught, +1 benign FP; 22M: 3/25) |
| Done | garak baseline, direct vs proxy, on a small probe set (see the status note) |
| Done | Injection study on llama3.2:1b with replication and neutral-text control (section 17, `docs/injection_eval.md`) |
| Next | Measure the NIM backend (needs an NVIDIA GPU); run the full garak spec (encoding, latentinjection) on a larger model |

## Design principles

- **Deny by default.** No allowlist entry, no execution.
- **External content is data, never instructions.**
- **No ambient credentials.** Tokens are short-lived, scoped, and never in the prompt.
- **Everything is logged,** and the log is tamper-evident.
