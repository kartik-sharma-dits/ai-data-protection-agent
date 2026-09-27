from typing import Literal

from pydantic import BaseModel, Field

# Understood by the API today but not yet used to change any decision
# (Phase 4's policy engine doesn't branch on destination yet). Reserved so
# callers can start sending it now without a breaking change later.
Destination = Literal["external_llm", "internal_llm", "self_hosted_llm"]


class ProtectRequest(BaseModel):
    # Empty text is allowed on purpose -- Phases 2-4 already handle it safely
    # (0 entities -> ALLOW), so rejecting it here would be a new, arbitrary
    # rule with no underlying reason. max_length is a second, cheap guard
    # behind the Content-Length middleware check (see app.py).
    text: str = Field(..., max_length=20_000)
    destination: Destination = "external_llm"


class ProtectResponse(BaseModel):
    allowed: bool
    action: Literal["ALLOW", "WARN", "SANITIZE", "BLOCK"]
    text: str | None = None  # never the original text when sanitized; omitted entirely for BLOCK
    entities_detected: int
    reason: str | None = None  # entity TYPES only (e.g. "API_KEY"), never values
