import hashlib
import os

from sentinel.audit.log import AuditLog
from sentinel.input_filter import classifier as clf
from sentinel.input_filter.rules import scan_text
from sentinel.input_filter.tagger import tag
from sentinel.models import Finding, ScanRequest, ScanResponse, ToolDecision, ToolRequest
from sentinel.policy.engine import PolicyEngine

_BLOCK_AT = {"user": 3, "external": 2}  # external content gets a lower tolerance


class Pipeline:
    def __init__(self, engine: PolicyEngine, log: AuditLog):
        self.engine, self.log = engine, log
        self.classifier = clf.load()
        self.threshold = float(os.getenv("SENTINEL_CLASSIFIER_THRESHOLD", "0.8"))
        self.log_content = os.getenv("SENTINEL_LOG_CONTENT") == "1"

    def scan(self, req: ScanRequest) -> ScanResponse:
        findings: list[Finding] = []
        blocked = False
        for i, item in enumerate(req.items):
            hits = scan_text(item.text)
            if self.classifier and self.classifier.score(item.text) >= self.threshold:
                hits.append(("classifier", 3))
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
            "reason": d.reason, "approval_id": d.approval_id,
            "args_sha256": hashlib.sha256(repr(sorted(req.args.items())).encode()).hexdigest(),
            **({"args": req.args} if self.log_content else {}),
        })
        return d
