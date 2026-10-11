import hashlib
import json
import logging
import os

from sentinel.audit.log import AuditLog
from sentinel.input_filter import classifier as clf
from sentinel.input_filter.rules import scan_text
from sentinel.input_filter.tagger import tag
from sentinel.models import Finding, Item, RunResponse, ScanRequest, ScanResponse, ToolDecision, ToolRequest
from sentinel.policy.engine import PolicyEngine
from sentinel.policy.hosts import extract_hosts
from sentinel.sandbox.runner import Sandbox, SandboxUnavailable
from sentinel.secrets.broker import TokenBroker
from sentinel.secrets.scanner import scan_output

_BLOCK_AT = {"user": 3, "external": 2}  # external content gets a lower tolerance


class Pipeline:
    def __init__(self, engine: PolicyEngine, log: AuditLog, sandbox: Sandbox, broker: TokenBroker, classifier=None):
        self.engine, self.log, self.sandbox, self.broker = engine, log, sandbox, broker
        self.classifier = classifier if classifier is not None else clf.load()
        self.on_error = os.getenv("SENTINEL_CLASSIFIER_ON_ERROR", "closed")
        if self.on_error not in ("closed", "open"):
            raise ValueError("SENTINEL_CLASSIFIER_ON_ERROR must be 'closed' or 'open'")
        self.threshold = float(os.getenv("SENTINEL_CLASSIFIER_THRESHOLD", "0.8"))
        self.log_content = os.getenv("SENTINEL_LOG_CONTENT") == "1"

    def scan(self, req: ScanRequest) -> ScanResponse:
        findings: list[Finding] = []
        blocked = False
        if self.engine.quarantine_reason(req.agent):  # alert -> block: a quarantined agent gets no clean verdicts
            findings.append(Finding(rule="agent_quarantined", severity=3, item=0))
            blocked = True
        for i, item in enumerate(req.items):
            hits = scan_text(item.text)
            if self.classifier:
                try:
                    if self.classifier.score(item.text) >= self.threshold:
                        hits.append(("classifier", 3))
                except Exception:  # details go to the server log only, never to the caller
                    logging.getLogger("sentinel.classifier").exception("classifier failed")
                    # closed (default): treat as high severity -> block. open: record it and continue on rules alone.
                    hits.append(("classifier_error", 3) if self.on_error == "closed" else ("classifier_unavailable", 1))
            findings += [Finding(rule=r, severity=s, item=i) for r, s in hits]
            blocked |= any(s >= _BLOCK_AT[item.source] for _, s in hits)
        resp = ScanResponse(
            verdict="block" if blocked else "allow",
            findings=findings,
            tagged=[] if blocked else [tag(it) for it in req.items],
        )
        self.log.append({
            "type": "scan", "agent": req.agent, "verdict": resp.verdict,
            "findings": [f.model_dump() for f in findings],
            "items": [
                {"source": it.source, "ref": it.ref, "sha256": hashlib.sha256(it.text.encode()).hexdigest(),
                 "len": len(it.text), **({"text": it.text} if self.log_content else {})}
                for it in req.items
            ],
        })
        return resp

    def authorize(self, req: ToolRequest) -> ToolDecision:
        d = self.engine.authorize(req.agent, req.tool, req.args, req.approval_id)
        self.log.append({
            "type": "tool", "agent": req.agent, "tool": req.tool, "decision": d.decision,
            "reason": d.reason, "approval_id": d.approval_id, "hosts": extract_hosts(req.args),
            "args_sha256": hashlib.sha256(repr(sorted(req.args.items())).encode()).hexdigest(),
            **({"args": req.args} if self.log_content else {}),
        })
        return d

    def run(self, req: ToolRequest) -> RunResponse:
        """authorize (L2) -> token (L4) -> sandbox (L3) -> scan output (L4 + L1) -> audit (L5)."""
        ex = self.engine.exec_spec(req.agent, req.tool)
        if ex is None:  # checked first so a missing sandbox config cannot burn a human approval
            d = ToolDecision(decision="deny", reason="tool is not allowlisted or has no sandbox config")
            self.log.append({"type": "run", "agent": req.agent, "tool": req.tool, "decision": "deny", "reason": d.reason})
            return RunResponse(**d.model_dump())
        d = self.authorize(req)
        if d.decision != "allow":
            return RunResponse(**d.model_dump())

        token, jti, env = None, None, {}
        if ex["secrets"]:
            token, jti = self.broker.issue(req.agent, req.tool, ex["secrets"], ex["token_ttl"])
            env["SENTINEL_TOKEN"] = token  # sandbox env only; never prompt, response, or log
        ev = {"type": "run", "agent": req.agent, "tool": req.tool, "token_jti": jti}
        try:
            res = self.sandbox.run(ex["sandbox"], json.dumps(req.args), env)
        except SandboxUnavailable as e:
            self.log.append({**ev, "decision": "deny", "reason": f"sandbox unavailable: {e}"})
            return RunResponse(decision="deny", reason="sandbox unavailable (fail closed)")
        finally:
            if jti:  # a token lives exactly as long as the call it was minted for
                self.broker.revoke(jti, "tool call finished")
        if res.timed_out:
            self.log.append({**ev, "decision": "allow", "timed_out": True})
            return RunResponse(decision="allow", reason="tool timed out and was killed")

        raw = res.stdout + (f"\n[stderr]\n{res.stderr}" if res.stderr else "")
        out = scan_output(raw, [token] if token else [])
        injection = [r for r, s in scan_text(out.text) if s >= 2]  # tool output is untrusted input to L1
        findings = out.findings + [f"output_{r}" for r in injection]
        withheld = out.block or bool(injection)
        self.log.append({**ev, "decision": "allow", "exit_code": res.exit_code, "findings": findings,
                         "withheld": withheld, "output_sha256": hashlib.sha256(raw.encode()).hexdigest()})
        return RunResponse(
            decision="allow", reason="output withheld" if withheld else "ok", exit_code=res.exit_code,
            output=None if withheld else tag(Item(source="external", ref=f"tool:{req.tool}", text=out.text)),
            findings=findings,
        )
