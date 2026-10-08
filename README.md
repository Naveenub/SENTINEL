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

> **Status:** all five layers are built and tested: 146 tests (147 with the `opa` binary on PATH) plus a red-team corpus (11 documented detection gaps tracked as strict expected-failures). promptfoo was run against the live gateway (8/8). CI is written but has not been run on GitHub yet.
>
> **ML classifier backends (NVIDIA JailbreakDetect NIM, Meta Prompt Guard 2) are implemented but not measured against real models.** I could not download models or reach an NIM from the build environment. The NIM client is tested against a local server implementing NVIDIA's documented API, and Prompt Guard against a stand-in pipeline. Run `scripts/eval_classifier.py` on your machine to get real numbers before relying on either.
>
> It is a **decision API**: your agent runtime calls `/v1/scan` before content reaches the model, `/v1/tool/authorize` before any tool runs, or `/v1/tool/run` to have SENTINEL run a tool end to end (authorize, sandbox, scan output, audit). Optionally it also fronts your model endpoint (OpenAI-compatible or Anthropic Messages, see section 14), so prompts and completions are screened without agent-side changes.
>
> **OPA** is tested against a real OPA server (`opa test` plus integration tests). **garak:** `scripts/garak_scan.sh` uses flags checked against garak 0.17's source, but I did not run a scan in the build environment (garak pulls torch/CUDA). The model proxy is tested against fake upstreams and driven end to end by the official `anthropic` SDK, but not against a live provider.
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
│   │   ├── classifier.py          # backend loader + ensemble (SENTINEL_CLASSIFIER)
│   │   └── backends/
│   │       ├── nim.py             # NVIDIA NemoGuard JailbreakDetect NIM client
│   │       ├── prompt_guard.py    # Meta Llama Prompt Guard 2 (local, via transformers)
│   │       └── chunking.py        # overlapping windows; oversize input raises, never truncates
│   ├── policy/                    # L2
│   │   ├── engine.py              # allowlist, JSON-schema args, host allowlist, rate limit, approval, preflight
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
│   │   └── formats.py             # wire formats: OpenAI chat-completions, Anthropic Messages
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
│   └── verify_log.py              # CLI: verify audit chain offline
├── tests/
│   ├── unit/                      # test_core.py, test_l3_l4.py, test_l5.py, test_classifier.py
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

### 8. ML classifier backends (L1)

Rules catch the obvious attacks; they miss paraphrase, encodings, other languages and homoglyphs (see the red-team corpus). Add a model with `SENTINEL_CLASSIFIER`:

| Backend | What it is | Runs | Needs |
|---|---|---|---|
| `nim` | NVIDIA NemoGuard JailbreakDetect, the jailbreak model behind NeMo Guardrails' jailbreak rail. Calls `POST /v1/classify`. | Separate service you host | NGC key and NVIDIA GPU; set `SENTINEL_NIM_URL` |
| `prompt_guard` | Meta Llama Prompt Guard 2, a small binary injection/jailbreak classifier (86M multilingual, or 22M English-only) | In-process, text never leaves the host | `pip install -e ".[ml]"`, accept Meta's license on Hugging Face (gated), `HF_TOKEN` |
| `module:Class` | Your own class with `score(text) -> float` | Anywhere | none |

Note: **Llama Guard** (Meta's generative content-safety model) is a different tool for a different job (harmful content, not injection), so it is not wired in. Prompt Guard 2 is Meta's injection detector.

```bash
export SENTINEL_CLASSIFIER=prompt_guard          # or nim, or nim,prompt_guard (ensemble: highest score wins)
export SENTINEL_CLASSIFIER_ON_ERROR=closed       # default
curl localhost:8080/healthz                      # shows which classifier is active
python scripts/eval_classifier.py                # measure it on the red-team corpus
```

Behaviour you should know:
- **Fail closed by default.** If the classifier errors or times out, the input is **blocked** (`classifier_error`). Set `SENTINEL_CLASSIFIER_ON_ERROR=open` to fall back to rules only (`classifier_unavailable`); the choice is yours, availability versus protection. Either way a `classifier_degraded` alert fires, so silent degradation can't go unnoticed.
- **A configured backend that can't load stops startup.** The gateway never quietly runs rules-only.
- **Long documents are scored in full** in overlapping windows (Prompt Guard has a ~512-token window). Input that would need more than the chunk limit (default 32) is treated as an error, not truncated, because truncation is an evasion route. Raise `SENTINEL_NIM_MAX_CHUNKS` / `SENTINEL_PG_MAX_CHUNKS` if you handle large pages.
- **Cost:** every item goes through the model, and ensembles run all members. Expect added latency per scan.
- **Data:** with `nim`, document text goes to wherever `SENTINEL_NIM_URL` points. It defaults to localhost; do not point it at a hosted endpoint for sensitive content.
- Scores at or above `SENTINEL_CLASSIFIER_THRESHOLD` (default 0.8) are a high-severity finding. For `nim` the score is 1.0 or 0.0 from its boolean verdict. The NIM's own score field is not interpreted.

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

### 12. OPA policy backend (L2)

YAML keeps describing what each tool *is* (JSON Schema, sandbox, secrets, rate limit). OPA decides who may call it.

```bash
opa run --server --addr 127.0.0.1:8181 policies/opa      # sentinel.rego + data.json
export SENTINEL_POLICY_BACKEND=opa SENTINEL_OPA_URL=http://127.0.0.1:8181
opa test policies/opa -v
```

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

The upstream must speak the format you call (the proxy does not translate between them). The agent's own `Authorization` / `x-api-key` / `anthropic-beta` headers are never forwarded; `anthropic-version` is (default `2023-06-01`).

| Direction | What happens |
|---|---|
| Request | `user` messages are scanned (L1); `tool` messages are scanned **and wrapped as `<untrusted>`**. Blocked: 403 `input_blocked`, upstream never called |
| Response text | L4 output scan: credentials withhold the response (403 `output_withheld`), PII/exfil is redacted |
| Response tool calls | Each proposed call is preflighted against L2 (allowlist, schema, hosts, OPA). Any denial blocks the response (403 `tool_denied`). Rate limits and human approval still apply when your runtime calls `/v1/tool/authorize`; preflight consumes neither |
| Audit | One `model` event per request (hashes only unless `SENTINEL_LOG_CONTENT=1`); denied proposed calls also log as `tool` events so `deny_spike` sees them |

Anthropic specifics: `tool_result` blocks are treated as external data (scanned, wrapped `<untrusted>`); `tool_use` blocks are the proposed calls; the top-level `system` prompt is trusted and not scanned; refusal mode returns a `message` with `stop_reason: "refusal"`.

**Streaming (`stream=true`) is buffered, not pass-through.** SENTINEL calls the upstream non-streaming, scans and preflights the *complete* reply, and only then re-emits it to the agent as SSE in the caller's format (`chat.completion.chunk` + `[DONE]` for OpenAI; `message_start` ... `message_stop` for Anthropic). Agent code that sets `stream=true` works unchanged and nothing unscanned is ever sent. Consequences: there is **no time-to-first-token benefit** (the whole reply is held until it is scanned; `SENTINEL_UPSTREAM_TIMEOUT` defaults to 300s to cover full generation time), and real pass-through streaming cannot be made safe for credential withholding. A blocked or failed streamed request returns an ordinary JSON error (403 / 502 / upstream status), as providers do for failures before the first event; in `refusal` block mode the refusal is streamed like a normal reply. `stream` and `stream_options` are never forwarded upstream, but `stream_options.include_usage` is honoured in the re-emitted stream. Text, thinking and tool-argument deltas are cut into 32-character pieces so client UIs look like token streaming; this is cosmetic, since the reply is already fully scanned. Set `SENTINEL_PROXY_STREAM=reject` to get the old behaviour (400 `streaming_unsupported`). Audit `model` events for streamed requests carry `stream: "buffered"`.

Limits: only text is scanned (images, audio, documents pass through); system prompt, assistant history and reasoning fields are not scanned. Clean text is cached by hash so a growing conversation is not rescanned every turn.

**garak** now fits because there is an LLM endpoint to aim it at. Run the same probes straight at the model and through SENTINEL; the gap is what the gateway stops.

```bash
pip install garak
export SENTINEL_PROXY_BLOCK_MODE=refusal     # blocks come back as a 200 content_filter completion; garak aborts on HTTP errors
scripts/garak_scan.sh direct <model>         # baseline (needs UPSTREAM_URI, UPSTREAM_KEY)
scripts/garak_scan.sh proxy  <model>         # through SENTINEL as agent "garak-target" (no tools)
```

garak scores model behaviour, so a result is "model + SENTINEL", not SENTINEL alone. The rules-only L1 will miss many garak probes (encodings, paraphrase); run with a classifier backend for a meaningful number.

---

## Integrations and standards

| Area | Approach |
|---|---|
| NVIDIA NemoGuard JailbreakDetect NIM | Built-in `nim` backend (L1). NeMo Guardrails itself (the framework) is not used |
| Meta Llama Prompt Guard 2 | Built-in `prompt_guard` backend (L1) |
| promptfoo | Wired in (HTTP provider against the live gateway); run for real, 8/8 |
| garak | `scripts/garak_scan.sh` runs it against the model directly or through the proxy (section 14); not executed in the build environment |
| OPA | Optional L2 decision backend (section 12), tested against a real OPA server |
| Regulated-industry expectations | Fail-closed defaults, separation of duties (agents cannot approve), single-use bound approvals, tamper-evident audit, content hashed in logs by default |

Known limits: the ML backends are unmeasured on real models (see the status note), and a classifier is itself attackable, so keep L2 to L4 in place. Alerts **notify, they do not block** (a deny/approve decision is still L2's job). Per-tool `allowed_hosts` checks URLs inside args only, not bare hostnames. Detector learning periods are call-count based. The rule-based L1 misses paraphrase, encoded, foreign-language and homoglyph attacks (see the red-team corpus) and has known false positives; use the classifier hook for those. Tokens are signed bearer tokens capped at 5 minutes; revocation is enforced only for verifiers that call `/v1/token/verify` (offline verification with the shared key cannot see it) and services must trust the SENTINEL key. The model proxy streams only in buffered mode (no latency benefit) and does not scan non-text content. The egress proxy is HTTPS-only. Credential detection is pattern-based, so unknown formats can slip through. HMAC signing is symmetric and tail truncation of the log is not detectable from the file alone (anchor `head` off-box for stronger guarantees). Approvals are in-memory and lost on restart. Agent-facing endpoints have no auth, so bind to localhost or put them behind your own network controls.

---

## Roadmap

| When | Deliverable |
|---|---|
| Done | L1 input filter, L2 policy engine, L3 sandbox, L4 secrets and output scanning, L5 audit log |
| Done | L5 anomaly detection and alerts; red-team corpus + promptfoo + CI workflow |
| Done | Classifier backends: NVIDIA JailbreakDetect NIM, Prompt Guard 2, ensemble, fail-closed error policy |
| Done | OPA policy option; token revocation; model proxy (OpenAI + Anthropic formats); garak harness |
| Next | Measure the ML backends and a garak baseline on your hardware and tune the threshold |

## Design principles

- **Deny by default.** No allowlist entry, no execution.
- **External content is data, never instructions.**
- **No ambient credentials.** Tokens are short-lived, scoped, and never in the prompt.
- **Everything is logged,** and the log is tamper-evident.
