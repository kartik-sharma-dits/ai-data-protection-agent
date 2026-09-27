import logging
import os
import time
from contextlib import asynccontextmanager
from functools import lru_cache

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse

from ai_data_protection_agent.detection.detector import PIIDetector
from ai_data_protection_agent.policy.engine import PolicyEngine
from ai_data_protection_agent.policy.models import Action
from ai_data_protection_agent.sanitization.sanitizer import PIISanitizer

from . import metrics
from .auth import API_KEY_ENV_VAR, verify_api_key
from .rate_limit import InMemoryRateLimiter
from .schemas import ProtectRequest, ProtectResponse
from .service import ProtectionError, ProtectionService

load_dotenv()  # loads a local .env if present; never overrides real env vars

logger = logging.getLogger("ai_data_protection_agent.api")

if os.environ.get(API_KEY_ENV_VAR) is None:
    logger.warning(
        "%s is not set -- API key auth is DISABLED. Set it before any "
        "real deployment.",
        API_KEY_ENV_VAR,
    )

# Hard byte ceiling checked BEFORE the body is even parsed as JSON -- a
# cheaper, earlier defense than the schema's max_length (which only applies
# after JSON parsing succeeds).
MAX_BODY_BYTES = 100_000

_rate_limiter = InMemoryRateLimiter()


@asynccontextmanager
async def _lifespan(app: FastAPI):
    # A Phase 6 load-test run showed p99 latency spiking to ~1.6s -- entirely
    # the cost of lazily loading the spaCy model on the FIRST real request.
    # Building the singleton now, at server startup, means that cost is paid
    # once during deploy/startup instead of by the first real caller.
    get_protection_service()
    yield


app = FastAPI(
    title="AI Data Protection Agent",
    description=(
        "Detects sensitive information in text and applies a security "
        "policy (ALLOW/WARN/SANITIZE/BLOCK) before the text would reach an "
        "external or self-hosted LLM. Sanitization mappings are internal "
        "only and are never returned by this API."
    ),
    version="0.1.0",
    lifespan=_lifespan,
)


@lru_cache
def get_protection_service() -> ProtectionService:
    # Built once per process and reused (loading the spaCy model is slow --
    # see Phase 2). @lru_cache with no args makes this a simple singleton.
    return ProtectionService(
        detector=PIIDetector(),
        policy_engine=PolicyEngine(),
        sanitizer=PIISanitizer(),
    )


@app.middleware("http")
async def limit_body_size(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length is not None and int(content_length) > MAX_BODY_BYTES:
        return JSONResponse(status_code=413, content={"detail": "Request body too large"})
    return await call_next(request)


@app.middleware("http")
async def rate_limit(request: Request, call_next):
    client_id = request.client.host if request.client else "unknown"
    if not _rate_limiter.allow(client_id):
        return JSONResponse(status_code=429, content={"detail": "Too many requests"})
    return await call_next(request)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    # This is a server-to-server JSON API, not a browser-rendered page, so
    # browser-focused headers like CSP/X-Frame-Options/HSTS don't apply --
    # there's no HTML being rendered for them to protect. nosniff is the
    # one cheap, always-relevant header here: it stops a browser from
    # trying to "helpfully" reinterpret our JSON as something executable.
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@app.exception_handler(ProtectionError)
async def protection_error_handler(request: Request, exc: ProtectionError) -> JSONResponse:
    # Generic, predictable message -- never the original text or the raw
    # exception message (which could, in principle, echo request content).
    metrics.record_error(exc.component)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal error while processing the request."},
    )


@app.get(
    "/metrics",
    summary="Safe, aggregate-only operational metrics",
    dependencies=[Depends(verify_api_key)],
)
def get_metrics() -> dict:
    """Counts and latency percentiles only -- never any request text, so
    this is always safe to expose, unlike application logs."""
    return metrics.snapshot()


@app.post(
    "/v1/protect",
    response_model=ProtectResponse,
    summary="Detect and act on sensitive information in text",
    response_description="The protection decision and, if applicable, safe text",
    dependencies=[Depends(verify_api_key)],
)
def protect(request: ProtectRequest) -> ProtectResponse:
    """
    Runs text through PII detection, policy evaluation, and (if the policy
    requires it) sanitization -- in that order, reusing the existing
    detection/policy/sanitization engines unchanged.

    - **ALLOW**: `text` is returned unchanged.
    - **WARN**: `text` is returned unchanged; `reason` names the entity types
      that triggered the warning (never their values).
    - **SANITIZE**: `text` has sensitive values replaced with placeholders
      (e.g. `<EMAIL_1>`). The placeholder-to-original mapping is used
      internally for this request only and is **never** included in the
      response.
    - **BLOCK**: `text` is omitted entirely (`null`) and `allowed` is
      `false`; the caller must not send anything onward for this request.

    `destination` is accepted for forward compatibility but does not yet
    change the decision (see project docs for why).
    """
    service = get_protection_service()
    start = time.perf_counter()
    # ProtectionError, if raised, hits protection_error_handler
    result = service.protect(request.text, request.destination)
    metrics.record_result(result.action.name, time.perf_counter() - start)

    response = ProtectResponse(
        allowed=result.allowed,
        action=result.action.name,
        text=result.text,
        entities_detected=result.entities_detected,
        reason=result.reason,
    )
    if result.action == Action.BLOCK:
        return JSONResponse(status_code=403, content=response.model_dump())
    return response
