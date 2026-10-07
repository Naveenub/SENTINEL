import hmac
import os

from fastapi import Depends, FastAPI, Header, HTTPException

from sentinel.audit.log import AuditLog
from sentinel.models import ScanRequest, ScanResponse, ToolDecision, ToolRequest
from sentinel.pipeline import Pipeline
from sentinel.policy.engine import PolicyEngine


def create_app() -> FastAPI:
    key = os.environ["SENTINEL_AUDIT_KEY"].encode()  # KeyError = refuse to start
    admin_token = os.environ["SENTINEL_ADMIN_TOKEN"].encode()
    log = AuditLog(os.getenv("SENTINEL_AUDIT_DB", "sentinel_audit.db"), key)
    engine = PolicyEngine(os.getenv("SENTINEL_POLICY", "policies/agents.yaml"))
    pipe = Pipeline(engine, log)

    app = FastAPI(title="SENTINEL")
    app.state.log = log

    def admin(x_sentinel_admin_token: str = Header(default="")):
        if not hmac.compare_digest(x_sentinel_admin_token.encode(), admin_token):
            raise HTTPException(403, "admin token required")

    @app.get("/healthz")
    def healthz():
        return {"ok": True}

    @app.post("/v1/scan", response_model=ScanResponse)
    def scan(req: ScanRequest):
        return pipe.scan(req)

    @app.post("/v1/tool/authorize", response_model=ToolDecision)
    def authorize(req: ToolRequest):
        return pipe.authorize(req)

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

    @app.get("/v1/audit/verify", dependencies=[Depends(admin)])
    def verify():
        ok, bad = log.verify()
        return {"ok": ok, "first_bad_id": bad, "head": log.head()}

    return app
