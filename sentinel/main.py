import hmac
import os
import time

from fastapi import Body, Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel

from sentinel.auth import AgentAuth
from sentinel.audit.alerts import log_sink, webhook_sink
from sentinel.audit.detect import Detector
from sentinel.audit.log import AuditLog
from sentinel.models import RunResponse, ScanRequest, ScanResponse, ToolDecision, ToolRequest
from sentinel.pipeline import Pipeline
from sentinel.policy.engine import PolicyEngine
from sentinel.policy.opa import OPAClient
from sentinel.proxy.formats import FORMATS
from sentinel.proxy.model import from_env as proxy_from_env
from sentinel.sandbox.runner import Sandbox
from sentinel.secrets.broker import TokenBroker
from sentinel.policy.approvals import ApprovalStore
from sentinel.secrets.revocation import RevocationStore


class VerifyRequest(BaseModel):
    token: str
    scope: str | None = None


def _opa_from_env():
    backend = os.getenv("SENTINEL_POLICY_BACKEND", "yaml")
    if backend == "yaml":
        return None
    if backend != "opa":
        raise ValueError("SENTINEL_POLICY_BACKEND must be 'yaml' or 'opa'")
    opa = OPAClient(os.getenv("SENTINEL_OPA_URL", "http://127.0.0.1:8181"),
                    os.getenv("SENTINEL_OPA_PATH", "sentinel/authz/decision"),
                    float(os.getenv("SENTINEL_OPA_TIMEOUT", "2")), os.getenv("SENTINEL_OPA_TOKEN", ""))
    opa.ping()  # configured backend that cannot answer stops startup, like the classifier
    return opa


def create_app(sandbox: Sandbox | None = None, classifier=None, opa=None, model_client=None) -> FastAPI:
    key = os.environ["SENTINEL_AUDIT_KEY"].encode()  # KeyError = refuse to start
    admin_token = os.environ["SENTINEL_ADMIN_TOKEN"].encode()
    log = AuditLog(os.getenv("SENTINEL_AUDIT_DB", "sentinel_audit.db"), key)
    opa = opa if opa is not None else _opa_from_env()
    approvals = ApprovalStore(os.getenv("SENTINEL_APPROVAL_DB", os.getenv("SENTINEL_AUDIT_DB", "sentinel_audit.db")),
                              float(os.getenv("SENTINEL_APPROVAL_TTL", "86400")),
                              int(os.getenv("SENTINEL_APPROVAL_MAX_PENDING", "1000")))
    engine = PolicyEngine(os.getenv("SENTINEL_POLICY", "policies/agents.yaml"), opa, approvals)
    detector = Detector(learn=int(os.getenv("SENTINEL_LEARN_CALLS", "50")),
                        call_limit=int(os.getenv("SENTINEL_CALL_LIMIT", "60")),
                        deny_limit=int(os.getenv("SENTINEL_DENY_LIMIT", "10")))
    for ts, ev in log.events():  # rebuild baselines from history so a restart is not an amnesty
        detector.observe(ev, now=ts, emit=False)
    sinks = [log_sink] + ([webhook_sink(os.environ["SENTINEL_ALERT_WEBHOOK"])] if os.getenv("SENTINEL_ALERT_WEBHOOK") else [])

    def on_event(ev: dict):
        for a in detector.observe(ev):
            log.append({"type": "alert", **a})  # alerts are themselves tamper-evident
            for s in sinks:
                s(a)

    log.subscribe(on_event)
    broker = TokenBroker(key, RevocationStore(os.getenv("SENTINEL_REVOKE_DB", os.getenv("SENTINEL_AUDIT_DB", "sentinel_audit.db"))))
    verifier_token = os.getenv("SENTINEL_VERIFIER_TOKEN", "").encode()
    auth = AgentAuth.from_env(engine.agent_names, [admin_token, verifier_token])  # None = auth off
    pipe = Pipeline(engine, log, sandbox or Sandbox(), broker, classifier)
    proxy = proxy_from_env(pipe, model_client)

    app = FastAPI(title="SENTINEL")
    app.state.log = log
    app.state.detector = detector

    def admin(x_sentinel_admin_token: str = Header(default="")):
        if not hmac.compare_digest(x_sentinel_admin_token.encode(), admin_token):
            raise HTTPException(403, "admin token required")

    def verifier(x_sentinel_admin_token: str = Header(default=""), x_sentinel_verifier_token: str = Header(default="")):
        """Services that check tokens use their own credential, not the admin token (which approves actions)."""
        ok = hmac.compare_digest(x_sentinel_admin_token.encode(), admin_token) or (
            bool(verifier_token) and hmac.compare_digest(x_sentinel_verifier_token.encode(), verifier_token))
        if not ok:
            raise HTTPException(403, "admin or verifier token required")

    # ---- optional per-agent auth (SENTINEL_AGENT_TOKENS / _FILE); a no-op when not configured
    class _AuthFail(Exception):
        def __init__(self, status: int, code: str, msg: str, api: str | None):
            self.status, self.code, self.msg, self.api = status, code, msg, api

    @app.exception_handler(_AuthFail)
    def _auth_failed(_: Request, e: _AuthFail):
        body = FORMATS[e.api].error(e.status, e.code, e.msg) if e.api else {"detail": e.msg}
        return JSONResponse(body, status_code=e.status, headers={"WWW-Authenticate": "Bearer"} if e.status == 401 else None)

    _auth_seen: dict[tuple, float] = {}

    def _auth_audit(request: Request, claimed: str, reason: str) -> None:
        """One audit entry per (agent, reason, client) per 10s, so an unauthenticated caller cannot flood the log.
        The token itself is never recorded."""
        client = request.client.host if request.client else "?"
        k, now = (claimed[:64], reason, client), time.monotonic()
        if now - _auth_seen.get(k, -1e18) < 10:
            return
        if len(_auth_seen) > 1024:
            _auth_seen.clear()
        _auth_seen[k] = now
        log.append({"type": "auth", "decision": "deny", "agent": claimed[:64], "reason": reason,
                    "client": client, "path": request.url.path})

    def _agent_auth(api: str | None = None):
        def dep(request: Request) -> str | None:
            if auth is None:
                return None
            who, presented = auth.identify(request.headers)
            if who is None:
                reason = "invalid agent token" if presented else "missing agent token"
                _auth_audit(request, str(request.path_params.get("agent") or request.headers.get("x-sentinel-agent") or ""), reason)
                raise _AuthFail(401, "unauthorized", "a valid agent token is required", api)
            return who
        return dep

    def _bind(who: str | None, claimed: str, request: Request, api: str | None = None) -> None:
        """The token authenticates `who`; it may only act as that agent."""
        if auth is not None and who != claimed:
            _auth_audit(request, claimed, f"token belongs to a different agent ({who})")
            raise _AuthFail(403, "agent_mismatch", "this token is not valid for that agent", api)

    plain_auth, oai_auth, ant_auth = _agent_auth(), _agent_auth("openai"), _agent_auth("anthropic")

    @app.get("/healthz")
    def healthz():
        c = pipe.classifier
        return {"ok": True, "classifier": getattr(c, "name", type(c).__name__) if c else None,
                "classifier_on_error": pipe.on_error, "policy_backend": "opa" if opa else "yaml",
                "model_proxy": bool(proxy)}

    @app.post("/v1/scan", response_model=ScanResponse)
    def scan(req: ScanRequest, request: Request, who=Depends(plain_auth)):
        _bind(who, req.agent, request)
        return pipe.scan(req)

    @app.post("/v1/tool/authorize", response_model=ToolDecision)
    def authorize(req: ToolRequest, request: Request, who=Depends(plain_auth)):
        _bind(who, req.agent, request)
        return pipe.authorize(req)

    @app.post("/v1/tool/run", response_model=RunResponse)
    def run(req: ToolRequest, request: Request, who=Depends(plain_auth)):
        _bind(who, req.agent, request)
        return pipe.run(req)

    # ---- token revocation (L4)
    @app.post("/v1/token/verify", dependencies=[Depends(verifier)])
    def verify_token(req: VerifyRequest):
        claims = broker.verify(req.token, req.scope)
        return {"valid": claims is not None, "claims": claims}

    @app.post("/v1/tokens/{jti}/revoke", dependencies=[Depends(admin)])
    def revoke_token(jti: str):
        broker.revoke(jti, "admin")
        log.append({"type": "revoke", "jti": jti})
        return {"jti": jti, "revoked": True}

    @app.post("/v1/agents/{agent}/revoke-tokens", dependencies=[Depends(admin)])
    def revoke_agent_tokens(agent: str):
        cutoff = broker.revoke_agent(agent)
        log.append({"type": "revoke", "agent": agent, "cutoff": cutoff})
        return {"agent": agent, "revoked_before": cutoff}

    # ---- model proxy (OpenAI chat-completions and Anthropic messages); mounted only when SENTINEL_UPSTREAM_URL is set
    if proxy:
        def _call(agent: str, body: dict, api: str, version: str):
            status, payload = proxy.handle(agent, body, api, version)
            if proxy.streams(body, status, payload, api):  # buffered streaming: scanned in full, then re-emitted
                return StreamingResponse(proxy.events(api, payload, body), media_type="text/event-stream",
                                         headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
            return JSONResponse(payload, status_code=status)

        def _need_agent(api: str):
            return JSONResponse(FORMATS[api].error(400, "missing_agent", "X-Sentinel-Agent header required"), status_code=400)

        @app.post("/v1/chat/completions")  # with auth on, the agent defaults to the token's owner
        def chat_header(request: Request, body: dict = Body(...), x_sentinel_agent: str = Header(default=""),
                        who=Depends(oai_auth)):
            agent = x_sentinel_agent or who
            if agent:
                _bind(who, agent, request, "openai")
            return _call(agent, body, "openai", "") if agent else _need_agent("openai")

        @app.post("/proxy/{agent}/v1/chat/completions")  # OpenAI base_url: http://gw/proxy/<agent>/v1
        def chat_path(agent: str, request: Request, body: dict = Body(...), who=Depends(oai_auth)):
            _bind(who, agent, request, "openai")
            return _call(agent, body, "openai", "")

        @app.post("/v1/messages")
        def messages_header(request: Request, body: dict = Body(...), x_sentinel_agent: str = Header(default=""),
                            anthropic_version: str = Header(default=""), who=Depends(ant_auth)):
            agent = x_sentinel_agent or who
            if agent:
                _bind(who, agent, request, "anthropic")
            return _call(agent, body, "anthropic", anthropic_version) if agent else _need_agent("anthropic")

        @app.post("/proxy/{agent}/v1/messages")  # Anthropic base_url: http://gw/proxy/<agent>
        def messages_path(agent: str, request: Request, body: dict = Body(...), anthropic_version: str = Header(default=""),
                          who=Depends(ant_auth)):
            _bind(who, agent, request, "anthropic")
            return _call(agent, body, "anthropic", anthropic_version)

    @app.get("/v1/approvals", dependencies=[Depends(admin)])
    def approvals():
        return engine.pending()

    def _resolve(aid: str, approve: bool):
        if not engine.resolve(aid, approve):
            raise HTTPException(404, "no pending approval with that id")
        log.append({"type": "approval", "approval_id": aid, "approved": approve})
        return {"approval_id": aid, "approved": approve}

    @app.post("/v1/approvals/{aid}/approve", dependencies=[Depends(admin)])
    def approve(aid: str):
        return _resolve(aid, True)

    @app.post("/v1/approvals/{aid}/deny", dependencies=[Depends(admin)])
    def deny(aid: str):
        return _resolve(aid, False)

    @app.get("/v1/alerts", dependencies=[Depends(admin)])
    def alerts(limit: int = 50):
        return log.recent("alert", min(max(limit, 1), 500))

    @app.get("/v1/audit/verify", dependencies=[Depends(admin)])
    def verify():
        ok, bad = log.verify()
        return {"ok": ok, "first_bad_id": bad, "head": log.head()}

    return app
