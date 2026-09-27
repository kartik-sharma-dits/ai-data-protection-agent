"""Vercel entrypoint. Vercel's Python builder expects a root-level `api/`
directory containing a file with an ASGI/WSGI callable named `app`.

This project's actual code lives under src/ai_data_protection_agent/ (the
normal src-layout used throughout this project, unchanged for Vercel's
sake) -- this file only makes that package importable and re-exports its
FastAPI app. No application logic lives here.
"""

import sys
from pathlib import Path

_SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

from ai_data_protection_agent.api.app import app  # noqa: E402
