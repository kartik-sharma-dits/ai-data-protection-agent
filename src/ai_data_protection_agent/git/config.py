import os

# Fixed for this MVP (see README) -- not loaded from a separate config file,
# to avoid a second, competing configuration system alongside the env-var
# style already used elsewhere in this project (PROTECTION_API_KEY).
ENABLED = os.environ.get("GIT_PROTECTION_ENABLED", "true").lower() != "false"

# A scanner failure (git command error, detector crash, policy crash) BLOCKS
# the commit rather than allowing it through. Fixed, not env-configurable --
# a security gate's own failure mode should not be silently toggleable.
FAIL_CLOSED = True

# Per the MVP design: WARN shows a message but still allows the commit.
WARN_BLOCKS_COMMIT = False

# Reasoning for the default size: Phase 6's own load testing showed
# detection time scales with text size (~20,000 characters scans in well
# under a second once the spaCy model is warm). 500,000 bytes keeps a
# single file's scan time to a few seconds at most while comfortably
# covering ordinary source/config files. This is deliberately NOT the same
# number as the HTTP API's 100,000-byte body limit -- that limit bounds an
# arbitrary network request; this one bounds a single file, and legitimate
# source/config files can reasonably be larger than 100KB without being
# suspicious.
DEFAULT_MAX_FILE_BYTES = 500_000
MAX_FILE_BYTES = int(os.environ.get("GIT_PROTECTION_MAX_FILE_BYTES", DEFAULT_MAX_FILE_BYTES))

# Explicit, documented exclusions ONLY -- generated/dependency directories
# that are never meant to be committed content in the first place.
# Deliberately does NOT include .env, config files, or deployment scripts --
# a secret in one of those is exactly what this feature exists to catch.
EXCLUDED_PATH_PREFIXES = (
    ".git/",
    "node_modules/",
    ".venv/",
    "dist/",
    "build/",
    "coverage/",
    "__pycache__/",
)


def is_excluded(path: str) -> bool:
    return any(path.startswith(prefix) for prefix in EXCLUDED_PATH_PREFIXES)
