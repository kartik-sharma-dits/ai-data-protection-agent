import os

from fastapi import Header, HTTPException

API_KEY_ENV_VAR = "PROTECTION_API_KEY"


def verify_api_key(x_api_key: str | None = Header(default=None)) -> None:
    """MVP auth: a single shared key read from an environment variable.

    If PROTECTION_API_KEY is not set, auth is skipped -- this keeps local
    development/testing simple, but means a real deployment MUST set this
    variable to actually be protected. This trade-off is documented, not
    hidden: see Phase 6 notes and the startup log warning in app.py.
    """
    expected = os.environ.get(API_KEY_ENV_VAR)
    if expected is None:
        return
    if x_api_key != expected:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")
