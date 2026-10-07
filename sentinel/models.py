from typing import Any, Literal

from pydantic import BaseModel, Field


class Item(BaseModel):
    source: Literal["user", "external"]
    ref: str = ""  # url, filename, or tool name the content came from
    text: str


class ScanRequest(BaseModel):
    agent: str
    items: list[Item] = Field(min_length=1)


class Finding(BaseModel):
    rule: str
    severity: int  # 1 low .. 3 high
    item: int


class ScanResponse(BaseModel):
    verdict: Literal["allow", "block"]
    findings: list[Finding]
    tagged: list[str]  # items ready to place in the model context


class ToolRequest(BaseModel):
    agent: str
    tool: str
    args: dict[str, Any] = Field(default_factory=dict)
    approval_id: str | None = None


class ToolDecision(BaseModel):
    decision: Literal["allow", "deny", "pending"]
    reason: str
    approval_id: str | None = None
