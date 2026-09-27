# AI Data Protection Agent

## 0. What was found when inspecting this repository

Before writing this document, the actual code was inspected (not assumed from earlier planning). Here's what genuinely exists today:

- **Python 3.12** only (`requires-python = ">=3.12,<3.13"`, pinned in `.python-version`), managed with **`uv`**.
- **One HTTP API**: FastAPI app at `src/ai_data_protection_agent/api/app.py`, with exactly two routes:
  - `POST /v1/protect` — the protection endpoint.
  - `GET /metrics` — aggregate, PII-free operational counters.
  - **No dedicated `/health` endpoint exists.** `GET /docs` (Swagger) is used instead to confirm the server is up.
- **Request shape** (`api/schemas.py`): `{"text": "...", "destination": "external_llm" | "internal_llm" | "self_hosted_llm"}`. `destination` is optional (defaults to `"external_llm"`) and is validated but **does not currently change the decision** — it's accepted for forward compatibility only.
- **Response shape**: `{"allowed": bool, "action": "ALLOW"|"WARN"|"SANITIZE"|"BLOCK", "text": str|null, "entities_detected": int, "reason": str|null}`. There is **no field for the placeholder mapping** — it is never returned by design.
- **Detection**: Microsoft Presidio + spaCy (`en_core_web_sm`), plus 4 custom recognizers: `CUSTOMER_ID`, `API_KEY`, `ACCESS_TOKEN`, `DATABASE_CONNECTION_STRING`.
- **Policy engine** (`policy/config.py`) has entries for more entity types than are currently detectable — e.g. `EMPLOYEE_ID`, `CLIENT_ID`, `PROJECT_ID`, `INTERNAL_DOMAIN`, `INTERNAL_SERVER`, `INTERNAL_URL` have a configured action but **no recognizer produces them yet**. This is documented honestly below, not hidden.
- **Authentication**: a single shared API key via the `PROTECTION_API_KEY` environment variable, checked against an `X-API-Key` request header. **If the variable is unset, auth is skipped entirely** (logged as a warning at startup) — this is the actual current behavior, not a bug.
- **Rate limiting**: a simple in-memory limiter, 100 requests / 60 seconds per client IP (`api/rate_limit.py`), single-process only.
- **Size limits**: request bodies over 100,000 bytes get `HTTP 413`; the `text` field itself is capped at 20,000 characters by the schema (`HTTP 422` if exceeded).
- **No database anywhere.** No LLM provider is called anywhere (`api/llm_provider.py` is an unused interface stub for a future phase).
- **132 automated tests** across 10 files in `tests/`.
- Two manual dev scripts exist under `scripts/`: `loadtest.py` (performance baseline) and `fake_downstream.py` (a tiny standard-library-only mock "downstream LLM" for the manual verification guide below).

Everything below is based on this actual code, verified by really running it.

---

## 1. Overview

The AI Data Protection Agent is a local HTTP service that sits between your applications and any LLM/AI API. You send it text; it detects sensitive information, decides what to do about it, and gives you back either the original text, a warning, a sanitized version, or a refusal — before anything reaches an external or self-hosted LLM.

## 2. Problem

Applications increasingly send free-text prompts to LLMs (hosted or self-hosted). Some of that text contains PII (names, emails, phone numbers) or outright secrets (API keys, database passwords). This project exists to catch that **before** it leaves your infrastructure, regardless of which language the calling application is written in.

## 3. How It Works

```
Application (.NET / Java / PHP / Node.js / Python / ...)
        │  POST /v1/protect  (HTTP + JSON)
        ▼
Protection API (FastAPI)
        │
        ▼
PII Detection  (Presidio + spaCy + 4 custom recognizers)
        │
        ▼
Policy Engine  (ALLOW / WARN / SANITIZE / BLOCK, per entity type)
        │
        ▼
Sanitizer (only if the decision is SANITIZE)
        │
        ▼
Safe Result returned to the calling application
        │
        ▼
(Your application decides what to do next — e.g. forward `text` to an LLM.
 The Protection API itself does not call any LLM -- see "Current Status".)
```

## 4. Architecture

- **PII Detection** (`detection/`): pure "what did I find" — never modifies text, never decides policy.
- **Policy Engine** (`policy/`): pure "what should happen" — never touches the original text, never sanitizes.
- **Sanitizer** (`sanitization/`): pure "how do I safely replace it" — only runs when the Policy Engine says `SANITIZE`.
- **Protection API** (`api/`): orchestrates the three above via `ProtectionService`, and is the only layer that speaks HTTP.

Each layer only knows about the one below it — the API never contains detection/policy/sanitization logic itself.

## 5. Project Structure

```
ai-data-protection-agent/
├── src/ai_data_protection_agent/
│   ├── detection/        PIIDetector, custom recognizers, file scanning
│   ├── sanitization/     PIISanitizer, placeholder mapping
│   ├── policy/           PolicyEngine, DEFAULT_POLICIES, risk levels
│   └── api/               FastAPI app, ProtectionService, auth, rate limiting, metrics
├── tests/                 132 automated tests (pytest)
├── scripts/
│   ├── loadtest.py         manual performance baseline tool
│   └── fake_downstream.py  manual "fake LLM" mock for verification (see MV-17)
├── .env.example            template for PROTECTION_API_KEY (never commit real .env)
├── pyproject.toml / uv.lock
└── README.md                this file
```

## 6. Prerequisites

- **Python 3.12** (the project is pinned to this version — see `.python-version`).
- **`uv`** installed (this project does not use plain `pip`/`venv`).
- Windows, macOS, or Linux — commands below are given for PowerShell/Git Bash on Windows since that's this project's environment; adjust path syntax for your shell if different.

## 7. Installation

```bash
uv sync
```

**What this does:** reads `pyproject.toml`/`uv.lock`, creates an isolated `.venv/` for this project only, and installs the exact pinned versions of every dependency (FastAPI, Presidio, spaCy, the spaCy language model, etc.). Nothing is installed system-wide.

## 8. Configuration

All configuration is via environment variables (never hard-coded). Copy the template and edit it:

```bash
cp .env.example .env
```

| Variable | Required? | Effect |
|---|---|---|
| `PROTECTION_API_KEY` | No | If set, every request to `/v1/protect` and `/metrics` must include a matching `X-API-Key` header, or gets `401`. **If unset, auth is disabled** — fine for local testing, not for any real deployment. |

`.env` is loaded automatically on startup if present, and is already excluded from git via `.gitignore`.

---

## 9. Quick Start

```bash
1. uv sync
2. uv run uvicorn ai_data_protection_agent.api.app:app --reload
3. Open http://127.0.0.1:8000/docs
4. Try POST /v1/protect
5. Send {"text": "This document explains our onboarding process."}   -> ALLOW
6. Send {"text": "Contact John Smith at john@example.com."}          -> SANITIZE
7. Send {"text": "See https://example.com for our project update."}  -> WARN
8. Send {"text": "Use this fake test API key: sk-faketestkeydonotusethisvalue"} -> BLOCK
```

---

## 10. Starting the API

```bash
uv run uvicorn ai_data_protection_agent.api.app:app --reload
```

- **`uv run`**: runs the command inside this project's isolated environment.
- **`uvicorn`**: the ASGI server that actually listens on the network port and hands requests to FastAPI.
- **`ai_data_protection_agent.api.app:app`**: module path `:` the FastAPI instance variable name inside it.
- **`--reload`**: restarts the server automatically when you edit source code — a **development-only** convenience (it costs extra CPU watching files and is never used in production).
- **Host/port**: not specified above, so Uvicorn uses its defaults — **host `127.0.0.1`, port `8000`** (i.e. only reachable from this same machine). Section 20 (LAN Testing) below shows how to change this deliberately.

**Expected startup output:**

```
PROTECTION_API_KEY is not set -- API key auth is DISABLED. Set it before any real deployment.
INFO:     Started server process [xxxxx]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://127.0.0.1:8000 (Press CTRL+C to quit)
```

(The first line only appears if you have *not* set `PROTECTION_API_KEY` — this is expected on a fresh clone.)

## 11. Swagger (API docs)

Open:

```
http://127.0.0.1:8000/docs
```

```
Server running
    ↓
Swagger opens, shows POST /v1/protect and GET /metrics
    ↓
API is ready for testing
```

There is no separate health-check endpoint in this project — the Swagger page loading successfully **is** the health check.

## 12. API Usage (reference)

```
POST /v1/protect
Content-Type: application/json

{
  "text": "your text here",
  "destination": "external_llm"   // optional, default shown; accepted but doesn't change the decision yet
}
```

Response fields: `allowed` (bool), `action` (`ALLOW`|`WARN`|`SANITIZE`|`BLOCK`), `text` (string, or `null` when `action` is `BLOCK`), `entities_detected` (int — counts every raw detection, including overlapping/duplicate labels on the same text span, so it can be higher than the number of placeholders you actually see), `reason` (string naming the triggering entity **types** only, never populated for `ALLOW`/`SANITIZE`).

---

# Manual Verification Guide

**Manual verification means:** starting the actual application yourself and personally checking, with your own eyes, that the protection behavior works as expected — not reading the code, not trusting that "the tests pass," but sending real requests and looking at real responses. Automated tests (Section 31) prove the code does what its authors intended; manual verification proves it does what *you* need, on *your* machine, before you connect it to anything real.

## 13. Manual Verification Checklist

```
MV-01 Start server
MV-02 Open Swagger
MV-03 Test ALLOW
MV-04 Test SANITIZE
MV-05 Test WARN
MV-06 Test BLOCK
MV-07 Test multiple PII
MV-08 Test repeated PII
MV-09 Test policy precedence
MV-10 Test invalid request
MV-11 Test oversized request
MV-12 Test unknown destination
MV-13 Verify no PII in response
MV-14 Verify no PII in logs
MV-15 Verify BLOCK stops downstream request
MV-16 Test from another application
MV-17 Test fake downstream service
MV-18 Test from another computer
MV-19 Colleague verification
```

All 19 apply to this project. (One clarification up front: MV-15's "stops downstream request" is enforced by *your calling application* checking `allowed`, not by the Protection API itself calling anything downstream — see MV-15 below for why.)

---

### MV-01 — Start server

**Action:** run the server.

**Command:**
```bash
uv run uvicorn ai_data_protection_agent.api.app:app --reload
```

**Expected:** the startup output shown in Section 10.

**PASS condition:** the last line reads `Uvicorn running on http://127.0.0.1:8000` with no traceback above it.

---

### MV-02 — Open Swagger

**Action:** open `http://127.0.0.1:8000/docs` in a browser.

**Expected:** the FastAPI Swagger UI loads, showing `POST /v1/protect` and `GET /metrics`.

**PASS condition:** you can click `POST /v1/protect` → "Try it out" and see a request body editor.

---

### MV-03 — Manually test ALLOW

**Why:** ordinary business text must pass through unmodified — over-flagging harmless text is what makes people stop trusting a security tool.

**Input:**
```json
{"text": "This document explains our onboarding process."}
```

**Expected response:**
```json
{"allowed": true, "action": "ALLOW", "text": "This document explains our onboarding process.", "entities_detected": 0, "reason": null}
```

**Manually verify:** `text` in the response is character-for-character identical to what you sent.

**PASS condition:** `action` is `"ALLOW"` and `text` is unchanged.

> Note: the earlier obvious-looking example *"Write a blog post about AI agents."* is deliberately **not** used here — it actually triggers `SANITIZE` in this system (spaCy misreads "AI" as a `LOCATION`). That's real, current, honest behavior, not a typo — worth trying yourself to see a live false positive.

---

### MV-04 — Manually test SANITIZE

**Why:** this proves the system's core promise — sensitive values are changed before they can leave the protection boundary.

**Input:**
```json
{"text": "Contact John Smith at john@example.com."}
```

**Expected response:**
```json
{"allowed": true, "action": "SANITIZE", "text": "Contact <PERSON_1> at <EMAIL_1>.", "entities_detected": 3, "reason": null}
```

(`entities_detected` is `3`, not `2` — the email's domain also independently matches a `URL` pattern, which the sanitizer correctly collapses into the same `<EMAIL_1>` placeholder rather than double-replacing. Do not be surprised the count is higher than the number of placeholders shown.)

**Manually verify all of these:**
```
Person detected        -> yes
Email detected          -> yes
Action = SANITIZE       -> yes
Original values removed -> yes
Placeholders appear     -> <PERSON_1>, <EMAIL_1>
```

**Compare directly:**
```
INPUT                          OUTPUT
John Smith          ──────►    <PERSON_1>
john@example.com     ──────►    <EMAIL_1>
```

**PASS condition:** neither `"John Smith"` nor `"john@example.com"` appears anywhere in the response.

---

### MV-05 — Manually test WARN

**Why:** some entities are worth flagging to a human without blocking the request outright. In this codebase, `URL` is configured as `WARN` (see `policy/config.py`).

**Input:**
```json
{"text": "See https://example.com for our project update."}
```

**Expected response:**
```json
{"allowed": true, "action": "WARN", "text": "See https://example.com for our project update.", "entities_detected": 1, "reason": "Warning due to: URL"}
```

**Manually verify:** `text` is unchanged (WARN does **not** sanitize), and `reason` names the entity type (`URL`) — never a value.

**PASS condition:** `action` is `"WARN"` and `reason` contains `"URL"`.

---

### MV-06 — Manually test BLOCK

**Why:** BLOCK is the most important security behavior — some data (secrets) must never be sent onward in any form, sanitized or not.

**Never use a real API key, token, password, or company credential for this test.** Use a fake, obviously-test value shaped like the real thing:

**Input:**
```json
{"text": "Use this fake test API key: sk-faketestkeydonotusethisvalue"}
```

**Expected response** (HTTP status **403**):
```json
{"allowed": false, "action": "BLOCK", "text": null, "entities_detected": 2, "reason": "Blocked due to: API_KEY"}
```

**Manually verify:**
```
Request is blocked (HTTP 403)     -> yes
text is null (no partial leak)     -> yes
reason names API_KEY, not the value -> yes
```

**PASS condition:** `text` is `null` and the fake key string does not appear anywhere in the response body.

---

### MV-07 — Multiple PII

**Why:** real text usually contains more than one sensitive item at once; every applicable entity must be handled, not just the first one found.

**Input:**
```json
{"text": "Customer John Smith can be contacted at john@example.com or +91 9876543210."}
```

**Expected response:**
```json
{"allowed": true, "action": "SANITIZE", "text": "Customer <PERSON_1> can be contacted at <EMAIL_1> or <PHONE_1>.", "entities_detected": 8, "reason": null}
```

**Manually verify:** `PERSON`, `EMAIL_ADDRESS`, and `PHONE_NUMBER` are all represented by a placeholder in the output. (`entities_detected` being `8` is expected, not a bug — Presidio's phone-number detector is genuinely noisy on this format and produces several overlapping raw labels for the same digits, e.g. a false-positive `UK_NHS` match alongside the correct `PHONE_NUMBER`; the sanitizer still collapses them to one correct `<PHONE_1>`.)

**PASS condition:** none of `John Smith`, `john@example.com`, `9876543210` appear in `text`.

---

### MV-08 — Repeated PII

**Why:** the same real-world value mentioned multiple times should get the *same* placeholder each time — otherwise a downstream LLM loses the fact that all three mentions refer to the same person.

**Input:**
```json
{"text": "John Smith contacted us. John Smith requested an update. Please contact John Smith again."}
```

**Expected response:**
```json
{"allowed": true, "action": "SANITIZE", "text": "<PERSON_1> contacted us. <PERSON_1> requested an update. Please contact <PERSON_1> again.", "entities_detected": 3, "reason": null}
```

**PASS condition:** all three mentions map to `<PERSON_1>` — not `<PERSON_1>`, `<PERSON_2>`, `<PERSON_3>`.

---

### MV-09 — Policy precedence

**Why:** when a request contains entities with different required actions, the system must never let a lower-severity action (like SANITIZE) override a higher one (like BLOCK). The implemented order is `BLOCK > SANITIZE > WARN > ALLOW`.

**Test A — PERSON + EMAIL (both SANITIZE):**
```json
{"text": "Contact John Smith at john@example.com."}
```
Expected: `"action": "SANITIZE"` (matches MV-04).

**Test B — PERSON + a BLOCK-level entity:**
```json
{"text": "Contact John Smith. Use this fake test API key: sk-faketestkeydonotusethisvalue"}
```
Expected: `"action": "BLOCK"` — the presence of a harmless `PERSON` entity must not weaken the outcome.

**PASS condition:** Test B returns `"BLOCK"`, not `"SANITIZE"`, even though `PERSON` alone would only need sanitizing.

---

### MV-10 — Invalid request

Only the following are actually enforced by the current Pydantic schema (verified by sending each):

**Missing `text`:**
```json
{"destination": "external_llm"}
```
→ **HTTP 422**, body mentions `"loc": ["body", "text"], "msg": "Field required"`.

**Null `text`:**
```json
{"text": null}
```
→ **HTTP 422**, `"msg": "Input should be a valid string"`.

**Wrong data type:**
```json
{"text": 123}
```
→ **HTTP 422**, same message as above.

**Invalid destination:**
```json
{"text": "Hello", "destination": "unknown_service"}
```
→ **HTTP 422**, `"msg": "Input should be 'external_llm', 'internal_llm' or 'self_hosted_llm'"`.

**Why 422 and not 400:** FastAPI/Pydantic use 422 for "syntactically valid JSON that doesn't satisfy the schema," reserving 400 for genuinely malformed JSON. This is a deliberate, documented choice (see Phase 5 notes), not an oversight.

**PASS condition:** all four return `422`, and no detection/policy/sanitization code runs at all (nothing is logged for these — they're rejected before reaching the engines).

---

### MV-11 — Oversized request

Two independent limits actually exist in this code:

1. **Body size ≥ 100,000 bytes → HTTP 413** (checked via the `Content-Length` header, before JSON is even parsed).
2. **`text` field > 20,000 characters → HTTP 422** (Pydantic schema check, after JSON parsing).

**To generate a large synthetic body without any real data**, PowerShell:
```powershell
$big = "a" * 150000
$body = @{ text = $big } | ConvertTo-Json
Invoke-WebRequest -Uri http://127.0.0.1:8000/v1/protect -Method Post -Body $body -ContentType "application/json"
```
or Git Bash:
```bash
python -c "print('{\"text\": \"' + 'a'*150000 + '\"}')" > big.json
curl -i -X POST http://127.0.0.1:8000/v1/protect -H "Content-Type: application/json" --data-binary @big.json
```

**PASS condition:** HTTP `413` with body `{"detail": "Request body too large"}`.

---

### MV-12 — Unknown destination

Already covered concretely in MV-10 ("Invalid destination") — `destination` validation genuinely exists (`Literal["external_llm", "internal_llm", "self_hosted_llm"]`), so a value outside that set is rejected with `422` before any processing happens.

**PASS condition:** same as MV-10's destination case.

---

### MV-13 — Manually verify no PII in response

**Why:** this is the single most important security property of the whole system.

**Input:**
```json
{"text": "Contact John Smith at john@example.com."}
```

**Check the raw response text** (view Swagger's raw response, or `curl`'s output) for the literal substrings `John Smith` and `john@example.com`. They must be **absent** — only `<PERSON_1>` and `<EMAIL_1>` should appear.

**Also check an error response**: trigger a validation error (MV-10) with a body containing a fake secret, e.g. `{"text": "my key is sk-shouldnotleak12345", "destination": 123}`, and confirm the fake key doesn't appear in the `422` error body either (Pydantic's error messages echo the *field* that failed, not unrelated fields — verify this yourself rather than assume it).

**PASS condition:** the original text is never found in any response body, success or error.

---

### MV-14 — Manually verify no PII in logs

**Action:** start the server in a visible terminal (MV-01), then send:
```json
{"text": "Contact John Smith at john@example.com."}
```

**Look at the terminal.** You should see a line like:
```
INFO:     Request processed. action=SANITIZE entities=3 destination=external_llm
```

**You should NOT see** `John Smith` or `john@example.com` anywhere in that output.

**PASS condition:** the log line contains only `action`, `entities` (a count), and `destination` — never the actual text. Do not modify the code to log the full request "just to check" — that would defeat the point of this test.

---

### MV-15 — Verify BLOCK stops downstream processing

**Important clarification before testing:** in the current implementation, the Protection API **does not itself call any downstream service** — Phase 5 deliberately stops at "return a decision." Stopping the downstream request is therefore *your calling application's* responsibility: check `response.allowed` (or `response.action == "BLOCK"`), and simply do not forward `text` (which is `null` anyway) to anything if it's `false`.

**How to verify this concretely:** send the BLOCK example from MV-06, and confirm `text` is `null`. Since there is nothing to forward (`null`), a correctly-written calling application has nothing to send onward — the absence of usable `text` *is* the enforcement mechanism. See MV-17 for a live demonstration using the included fake downstream mock.

**PASS condition:** for the BLOCK request, `text` is `null` — there is no sanitized-or-otherwise text available for any downstream call to accidentally use.

---

### MV-16 — Test from another (local) application

**Why:** proves the gateway is genuinely language-independent — it only needs HTTP + JSON.

A minimal Python client, using only the standard library (no project dependencies needed — this simulates a totally separate application):

```python
import json
import urllib.request

body = json.dumps({"text": "Contact John Smith at john@example.com."}).encode()
req = urllib.request.Request(
    "http://127.0.0.1:8000/v1/protect",
    data=body,
    headers={"Content-Type": "application/json"},
    method="POST",
)
with urllib.request.urlopen(req) as response:
    print(json.load(response))
```

Save this as e.g. `test_client.py` anywhere on your machine (outside this repo) and run it with your system Python (`python test_client.py`) — not `uv run` — to prove it needs none of this project's dependencies.

The same idea applies to .NET/Java/Node.js/PHP: each just needs its own native HTTP client and JSON library, pointed at `POST http://127.0.0.1:8000/v1/protect`. No SDK is provided or required.

**PASS condition:** the standalone script prints the same JSON shape as Swagger/curl, using zero imports from this project.

---

### MV-17 — Fake downstream service verification

**Why:** this is the most convincing proof of the whole system — showing, with your own eyes, that only sanitized data ever leaves the boundary.

This repo includes a tiny mock "downstream LLM" for exactly this purpose (`scripts/fake_downstream.py`, standard-library only, not a real LLM):

**Terminal 1 — start the Protection API** (MV-01, if not already running).

**Terminal 2 — start the fake downstream service:**
```bash
uv run python scripts/fake_downstream.py 9000
```
Expected output: `Fake downstream service listening on http://127.0.0.1:9000`.

**Terminal 3 — run the two-step flow:**
```bash
# Step 1: protect the text
curl -s -X POST http://127.0.0.1:8000/v1/protect -H "Content-Type: application/json" \
  -d "{\"text\": \"Customer John Smith can be contacted at john@example.com.\"}"
# Copy the "text" value from the response, then:

# Step 2: forward ONLY that safe text to the fake downstream
curl -s -X POST http://127.0.0.1:9000/ -H "Content-Type: application/json" \
  -d "{\"text\": \"Customer <PERSON_1> can be contacted at <EMAIL_1>.\"}"
```

**Look at Terminal 2** — it will print exactly what it received:
```
FAKE DOWNSTREAM SERVICE RECEIVED:
{
  "text": "Customer <PERSON_1> can be contacted at <EMAIL_1>."
}
```

**PASS condition:** Terminal 2's output contains `<PERSON_1>` and `<EMAIL_1>` — and never `John Smith` or `john@example.com`.

---

### MV-18 — Test from another computer (LAN)

**`127.0.0.1` vs `0.0.0.0`, in simple terms:** `127.0.0.1` ("localhost") means "only this same computer can connect." `0.0.0.0` means "accept connections arriving on any of this computer's network interfaces" — including your LAN — so other devices on the same network can reach it too.

**Start the server listening on your LAN interface:**
```bash
uv run uvicorn ai_data_protection_agent.api.app:app --host 0.0.0.0 --port 8000
```

**Find this computer's private IP (Windows):**
```cmd
ipconfig
```
Look for a line like:
```
IPv4 Address. . . . . . . . . . . : 192.168.1.25
```
*(This is only an example — use whatever your own `ipconfig` shows.)*

**Your colleague, on another computer on the same network**, opens:
```
http://<YOUR-IP>:8000/docs
```

**PASS condition:** your colleague's browser shows the same Swagger page you see locally.

## 14. Manual LAN Test Sequence

```
1. Start API on host machine, bound to 0.0.0.0        -> PASS if no startup error
2. Confirm localhost still works on host                -> PASS if http://127.0.0.1:8000/docs loads
3. Find host private IP via ipconfig                     -> PASS if an IPv4 address is shown
4. Confirm both computers are on the same network         -> PASS if colleague can ping the host IP
5. Colleague opens Swagger via http://<host-ip>:8000/docs -> PASS if page loads
6. Colleague calls POST /v1/protect                        -> PASS if a JSON response returns
7. Colleague sends the MV-03 ALLOW example                  -> PASS if action=ALLOW
8. Colleague sends the MV-04 SANITIZE example                -> PASS if placeholders appear
9. Colleague sends the MV-06 BLOCK example                    -> PASS if HTTP 403
10. Colleague confirms no PII in their own responses          -> PASS if MV-13 holds from their side too
11. Host terminal shows log lines for colleague's requests      -> PASS if entries appear with no PII (MV-14)
```

## 15. Network Troubleshooting

| Symptom | Check |
|---|---|
| Swagger works on host but not colleague | Server bound to `0.0.0.0` (not `127.0.0.1`)? Windows Firewall blocking inbound on the port? Both machines actually on the same LAN/subnet? |
| Connection refused | Is the server actually running? Right port? |
| Timeout (no response at all) | Firewall silently dropping the connection, or wrong IP/network |
| 404 Not Found | Wrong path — must be exactly `/v1/protect` or `/metrics` |
| 422 Validation error | Request body doesn't match the schema (see MV-10) |
| 401 Unauthorized | `PROTECTION_API_KEY` is set on the server but your request is missing/wrong `X-API-Key` |
| 429 Too Many Requests | You've exceeded 100 requests/60s from the same IP — wait, this is the rate limiter working as designed |
| BLOCK not happening when expected | Check `policy/config.py` for that entity's configured action, and confirm the detector actually recognizes that entity type at all (see Section 0 — several policy entries currently have no matching recognizer) |
| PII appears in a response/log | This should never happen — treat as a real bug, and add a regression test to `tests/test_security_regression.py` |

**Do not** disable Windows Firewall entirely to fix the first two rows — instead add a specific inbound rule scoped to the exact port you're using (e.g. TCP 8000), for **Private networks only**. **Do not** expose this server to the public internet for testing — LAN-only, always.

## 16. MV-19 — Colleague testing sheet

Give a colleague this list, without requiring them to read any code:

```
Test 1 — Normal text
  Send: {"text": "This document explains our onboarding process."}
  Expected: action = ALLOW

Test 2 — Synthetic person
  Send: {"text": "Contact John Smith about the project."}
  Expected: action = SANITIZE

Test 3 — Synthetic email
  Send: {"text": "My email is test.user@example.com."}
  Expected: action = SANITIZE

Test 4 — Synthetic phone
  Send: {"text": "My phone number is +1 415-555-2671."}
  Expected: action = SANITIZE or WARN (never ALLOW)

Test 5 — Fake critical secret
  Send: {"text": "Use this fake test API key: sk-faketestkeydonotusethisvalue"}
  Expected: action = BLOCK, text = null

Test 6 — Multiple PII
  Send: {"text": "Customer John Smith can be contacted at john@example.com or +91 9876543210."}
  Expected: a policy-based result with all values replaced

Test 7 — Invalid request
  Send: {"destination": "external_llm"}   (no text field)
  Expected: HTTP 422
```

Then ask them to try inputs **we did not suggest** — their real goal is to find something unexpected, using only synthetic (fake) data, never real customer/company information.

## 17. Manual Test Result Sheet

| ID | Test | Expected | Actual | Pass/Fail | Notes |
|---|---|---|---|---|---|
| MV-01 | Start API | Server starts | | | |
| MV-02 | Swagger | Opens | | | |
| MV-03 | ALLOW | Allowed, text unchanged | | | |
| MV-04 | SANITIZE | PII replaced with placeholders | | | |
| MV-05 | WARN | Text unchanged, reason names entity type | | | |
| MV-06 | BLOCK | HTTP 403, text null | | | |
| MV-07 | Multiple PII | All applicable entities replaced | | | |
| MV-08 | Repeated PII | Same placeholder reused | | | |
| MV-09 | Policy precedence | BLOCK wins over SANITIZE | | | |
| MV-10 | Invalid request | HTTP 422 | | | |
| MV-11 | Large request | HTTP 413 | | | |
| MV-12 | Unknown destination | HTTP 422 | | | |
| MV-13 | Response privacy | No raw PII anywhere in response | | | |
| MV-14 | Log privacy | No raw PII in server logs | | | |
| MV-15 | Downstream blocking | `text` is null on BLOCK | | | |
| MV-16 | Other local application | Standalone script gets same response | | | |
| MV-17 | Fake downstream | Mock receives placeholders only | | | |
| MV-18 | LAN | Colleague's machine connects | | | |
| MV-19 | Colleague testing | Independent tests pass | | | |

---

## 18. Automated Testing

```
Manual Testing    = a human personally verifies actual behavior, once, by hand
Automated Testing = the same (and more) checks, run repeatedly by code, on every change
```

**Run everything:**
```bash
uv run pytest
```

**Run one file:**
```bash
uv run pytest tests/test_security_regression.py
```

**Run one test:**
```bash
uv run pytest tests/test_api.py::test_block_request
```

**Run with detail:**
```bash
uv run pytest -v
```

**Expected success output:**
```
132 passed in ~5s
```

**Test files that actually exist** (10 files, `tests/`): `test_detector.py`, `test_sanitizer.py`, `test_policy_engine.py`, `test_protection_service.py`, `test_api.py`, `test_custom_recognizers.py`, `test_accuracy.py`, `test_security_regression.py`, `test_hardening.py`, `conftest.py` (shared fixtures).

## 19. Manual vs. Automated Testing

| Area | Manual | Automated |
|---|---|---|
| Swagger behavior | ✅ | Optional |
| Browser verification | ✅ | ❌ |
| API regression | Limited | ✅ |
| Security regression | Limited | ✅ |
| Network/LAN | ✅ | Limited |
| User experience | ✅ | Limited |
| Repeated execution | ❌ | ✅ |

Both matter: automated tests catch regressions instantly and repeatedly, but they can't tell you whether Swagger actually renders correctly in a real browser, whether a colleague on another machine can actually reach the server, or whether the error message is actually *readable* to a human. Manual verification catches what automation structurally cannot see.

## 20. Security Verification — End-to-End Real-World Test

```
Developer Application
        ↓
Protection API
        ↓
PII Detector
        ↓
Policy Engine
        ↓
Sanitizer
        ↓
Fake Downstream (scripts/fake_downstream.py)
```

Using `"Customer John Smith can be contacted at john@example.com."`, the fake downstream service must receive exactly:
```
Customer <PERSON_1> can be contacted at <EMAIL_1>.
```
This is the complete, literal demonstration of this project's entire purpose — see MV-17 for the exact steps.

## 21. Test With a Real LLM/API

**Not implemented yet.** The Protection API never calls any LLM provider (hosted or self-hosted) itself — Phase 5 stops at "return a safe decision + text," and `api/llm_provider.py` is an unused interface stub reserved for a future phase. Today, testing against a real LLM means *your own application* takes the `text` field from a `SANITIZE`/`ALLOW`/`WARN` response and sends it to whatever LLM you use, entirely outside this project. When you do this yourself: use synthetic data only, and never paste real customer data, employee data, passwords, API keys, tokens, or confidential company information into any test — sanitized or not.

## 22. Security Testing Rules

```
IMPORTANT

Use synthetic data for testing.
Never use real customer PII.
Never use real API keys.
Never use real access tokens.
Never use real passwords.
Never intentionally expose confidential company information.
Do not expose the local API to the public internet for testing.
```

## 23. Recommended Developer Testing Flow

```
LEVEL 1 — Same machine
  Protection API -> Swagger -> Manual tests (MV-01 to MV-14)

LEVEL 2 — Your own project
  Your Application -> Protection API -> Fake Downstream (MV-16, MV-17)

LEVEL 3 — Real API/LLM (future integration, your own responsibility today)
  Your Application -> Protection API -> Safe request -> LLM/API

LEVEL 4 — Another computer
  Colleague Application -> LAN -> Protection API (MV-18)

LEVEL 5 — Independent colleague testing (MV-19)
```

Each level should pass before moving to the next — there's little value LAN-testing a behavior you haven't confirmed locally first.

---

# Manual Verification Complete When...

```
[x] API starts correctly
[x] Swagger opens
[x] ALLOW works
[x] SANITIZE works
[x] WARN works
[x] BLOCK works
[x] Multiple PII works
[x] Repeated PII works
[x] Policy precedence works
[x] Invalid requests are handled
[x] Request limits work (413 body size, 422 field length)
[x] Original PII isn't exposed in responses
[x] Original PII isn't exposed in logs
[x] BLOCK prevents downstream processing (text is null; enforced by the caller)
[x] Another local application can call the API
[x] Fake downstream receives sanitized data only
[x] Another machine can connect over LAN
[x] Colleague can execute the basic tests
[ ] Any discovered issues are added to regression tests   <- ongoing, not a one-time checkbox
```

---

# Git Pre-Commit Protection

The MVP now has **two protection paths**, both built on the exact same core (`PIIDetector` + `PolicyEngine` — no second detector, no second policy engine):

```
                    AI DATA PROTECTION CORE
                    (PIIDetector + PolicyEngine)
                             │
                 ┌───────────┴───────────┐
                 │                       │
                 ▼                       ▼
        Protection API             Git Protection
     (src/.../api/)             (src/.../git/)
                 │                       │
                 ▼                       ▼
       Application Requests        Git Pre-Commit Hook
                 │                       │
                 ▼                       ▼
        Detect → Policy            Detect → Policy
                 │                       │
          ┌──────┼──────┐          ┌─────┴─────┐
          ▼      ▼      ▼          ▼           ▼
        ALLOW  WARN  SANITIZE   ALLOW+WARN   BLOCK COMMIT
                         │        commit    (BLOCK or
                         ▼                   SANITIZE)
                    (API returns
                     safe text)
```

- **Application/API path**: protects data before it reaches an AI/external API — you send text, get back a policy-based result.
- **Git path**: protects the *repository itself* — a developer's `git commit` is scanned before it's created, and can be blocked.

Both call the identical `PIIDetector.detect()` and `PolicyEngine.evaluate()` — verified by inspection, not just claimed: `src/ai_data_protection_agent/git/scanner.py` imports directly from `detection/` and `policy/`, never from `api/`.

## What it does

```
git commit
    ↓
pre-commit hook (.githooks/pre-commit, thin shell wrapper)
    ↓
GitProtectionService.scan_staged()  (src/ai_data_protection_agent/git/)
    ↓
reads the STAGED git snapshot only (git show :<path>, never the file on disk)
    ↓
PIIDetector.detect()  (same engine as the API)
    ↓
PolicyEngine.evaluate()  (same engine as the API)
    ↓
ALLOW / WARN  -> commit proceeds
SANITIZE / BLOCK -> commit is rejected (exit code 1)
```

**Working tree vs. staged content vs. committed content, in simple terms:**
- **Working tree** = whatever is currently on disk, including edits you haven't run `git add` on yet.
- **Staged content** = the exact snapshot `git add` recorded — this is what `git commit` will actually turn into a commit.
- **Committed content** = what already exists in a previous commit.

**This scanner only ever reads the staged snapshot** (`git show ":<path>"`), never the working-tree file on disk. This was verified directly, not assumed: staging a safe file and then dirtying the working-tree copy with a fake email allowed the commit; staging a fake-email file and then overwriting the working-tree copy with safe content still blocked the commit. Only the staged snapshot decides the outcome.

## Why SANITIZE means "block the commit", not "auto-fix it"

The Policy Engine's `SANITIZE` action normally means "replace the value with a placeholder" (that's what the HTTP API does). For Git, that would mean **silently rewriting a developer's staged file content during a commit** — which can corrupt code, break builds, or hide a mistake instead of surfacing it. The MVP deliberately never does this. Instead:

```
Sensitive data found (SANITIZE or BLOCK)
    ↓
Commit is rejected; entity types/files/lines are shown (never the values)
    ↓
Developer removes or fixes the sensitive content themselves
    ↓
git add
    ↓
git commit again -> succeeds once clean
```

This was verified end-to-end: a commit containing a fake email was rejected, `git log` confirmed no commit was created, the file was then rewritten with safe content, and the exact same `git commit` command succeeded and appeared in `git log`.

## Installation

**In this repository** (protects this project's own commits):
```bash
git config core.hooksPath .githooks
```
On macOS/Linux (harmless no-op on most Windows setups, but included for correctness):
```bash
chmod +x .githooks/pre-commit
```

**In a different repository** (e.g. your own application's repo), copy `.githooks/pre-commit` into that repo's `.githooks/` folder, run the same `git config core.hooksPath .githooks` there, and set an environment variable pointing at *this* project (since the hook needs this project's Python environment to run the scanner):
```bash
export PROTECTION_AGENT_PROJECT="/absolute/path/to/ai-data-protection-agent"
```
(PowerShell: `$env:PROTECTION_AGENT_PROJECT = "D:\path\to\ai-data-protection-agent"`.) If unset, the hook defaults to protecting whatever repo it's installed in — correct for the first case above, and why no configuration is needed there.

> Packaging this as a properly installable, distributable tool (so other repos don't need this environment variable) is real future work, not part of this MVP — see "Future Work" below.

## Usage

Nothing changes about how you use Git day to day:
```bash
git add .
git commit -m "your message"
```
If the commit is rejected, fix the flagged content, `git add` again, and re-run `git commit`.

## Manual test command (without creating a real commit)

```bash
uv run python -m ai_data_protection_agent.git.cli scan-staged
```
This runs the exact same scan the hook runs, prints the same report, and returns the same exit code (`0` = would allow, `1` = would block) — **without ever creating a commit** — useful for debugging what the hook will do before you actually commit.

## Manual Verification

All of the following were actually run against a real, temporary git repository (not this project's own history) while building this feature:

| Test | Command | Result |
|---|---|---|
| Safe commit | `echo 'print("Hello world")' > hello.py && git add hello.py && git commit -m "..."` | `[OK] Commit allowed.` — commit created |
| Email | `echo 'Contact john@example.com...' > test.txt && git add . && git commit -m "..."` | `[BLOCKED]`, `Entity: EMAIL_ADDRESS`, no email printed, no commit created |
| Phone | `echo 'Call +91 9876543210.' > test.txt && ...` | `[BLOCKED]` — reported as `UK_NHS` (a known Presidio false-positive label on this digit pattern, documented since Phase 2/6 — still correctly blocks) |
| Fake secret | `echo 'API_KEY = "sk-faketestsecretonlydonotuse123"' > config.txt && ...` | `[BLOCKED]`, `Entity: API_KEY`, `Risk: CRITICAL`, secret value never printed |
| WARN | `echo 'See https://example.com...' > warn.txt && ...` | `[WARNING]`, `Entity: URL` — **commit still created** |
| Multiple PII | one file with a name, email, and phone | all three entity types reported, commit blocked |
| Precedence | one file with a name (SANITIZE-level) + a fake secret (BLOCK-level) | overall result is `BLOCK`, not `SANITIZE` |
| Staged vs. unstaged | stage safe content, then edit the working-tree copy with a fake email *without staging it* | commit **allowed** (proves only the staged snapshot is scanned) |
| Unstaged vs. staged (reverse) | stage a fake email, then overwrite the working-tree copy with safe content | commit **blocked** (proves the staged snapshot, not what's currently on disk, decides) |
| Deleted file | `git rm hello.py && git commit -m "..."` | handled without error, commit allowed |
| Binary file | stage a raw byte file (`bytes(range(256))`) | not decoded as text, commit allowed |
| Large file | stage a 675,000-byte text file (limit is 500,000 bytes) | `[BLOCKED]` — "exceeded the scan size limit... treated as unsafe by default" (fail-closed, not silently skipped) |
| No staged files | `git commit -m "..."` with nothing staged | hook exits fast with `[OK]`; Git's own "nothing to commit" message follows separately |

### Git Pre-Commit Verification checklist

```
[x] Safe commit succeeds
[x] Email causes expected protection
[x] Phone causes expected protection
[x] Fake API key is blocked
[x] Multiple PII is handled
[x] WARN behavior works
[x] Policy precedence works
[x] Staged content is scanned
[x] Unstaged content is not incorrectly scanned
[x] Deleted files are handled
[x] Binary files are handled
[x] Large files are handled
[x] Original PII is not displayed
[x] Scanner failures fail safely
[x] Blocked commit is actually not created
[x] Cleaned file can be committed afterward
[x] Hook works from another (temporary) test repository
```

## Automated tests

```bash
uv run pytest tests/test_git_protection.py
```
18 tests, using a fresh temporary git repository per test (never this project's real repository) — covering everything in the manual list above, plus scanner-failure fail-closed behavior and "no PII in scanner logs/output."

## Configuration

Fixed for this MVP (deliberately not a second configuration system alongside the API's environment-variable style):

| Setting | Value | Override |
|---|---|---|
| Enabled | `true` | `GIT_PROTECTION_ENABLED=false` to disable |
| Fail-closed on scanner errors | always on | not configurable — a security gate's own failure shouldn't be silently toggleable |
| WARN blocks commit? | no (allows + shows warning) | fixed in `git/config.py` |
| Max file size scanned | 500,000 bytes | `GIT_PROTECTION_MAX_FILE_BYTES` |
| Excluded paths | `.git/`, `node_modules/`, `.venv/`, `dist/`, `build/`, `coverage/`, `__pycache__/` | edit `git/config.py`'s `EXCLUDED_PATH_PREFIXES` — deliberately does **not** exclude `.env` or config files, since a secret there is exactly what this feature exists to catch |

## Fail-safe behavior

If the scanner itself fails for any reason (a git command error, a detector crash, an unexpected exception), **the commit is blocked, not allowed** — verified by a dedicated test (`test_scanner_failure_fails_closed`, `test_cli_blocks_commit_on_scanner_failure`). The reasoning: a security gate that fails open (silently allowing everything when broken) is worse than one that's occasionally inconveniently strict — a blocked commit costs a developer a few minutes; a real secret slipping through during a silent failure cannot be undone. The error message shown is generic (only the exception's type name, never its message or any file content), matching the same discipline as the HTTP API's error handling.

## Security Limitation — read this before relying on it

**A local pre-commit hook is not an absolute security boundary.** Git allows any developer to bypass it intentionally:
```bash
git commit --no-verify
```
This skips the hook entirely, with no warning shown by Git itself. This is real, documented Git behavior, not a flaw in this implementation — there is no way for a *local* hook to prevent this. Describe this feature accurately: it is **a local, commit-time convenience/safety-net control**, not a guarantee that "no secret can ever enter the repository." Closing this gap requires enforcement the developer cannot bypass on their own machine — e.g. **server-side checks** (protected branches with required status checks), **CI-based scanning** (re-run the same scan on every push, in a place developers don't control), or a **centralized secret-scanning service**. None of these are built in this MVP — they're legitimate, separate future work.

## Troubleshooting

| Symptom | Check |
|---|---|
| Hook doesn't seem to run at all | Did you run `git config core.hooksPath .githooks` in *that* repository? Check with `git config --get core.hooksPath`. |
| "scanner not found" / import errors | Is `PROTECTION_AGENT_PROJECT` set correctly (if this is a different repo than this project itself)? Does that path actually contain `pyproject.toml`? |
| `uv: command not found` | `uv` must be on `PATH` for the shell Git invokes hooks with — confirm `uv --version` works in the same terminal you commit from. |
| Permission denied running the hook | On macOS/Linux, run `chmod +x .githooks/pre-commit`. |
| Works in Git Bash but not another Windows Git client | Git for Windows' bundled `sh.exe` runs the hook via its shebang line regardless of the executable bit — if a GUI Git client behaves differently, test from Git Bash first to isolate whether it's a hook issue or a client issue. |
| Commit unexpectedly blocked on clearly safe text | Run the manual command (`uv run python -m ai_data_protection_agent.git.cli scan-staged`) to see exactly which entity/file/line triggered it — spaCy's small model does produce real false positives on ordinary prose (e.g. "AI" as a `LOCATION`, common in comments/docs — see the main README's "Current Status" notes). |
| Stale hook path after switching branches/clones | `core.hooksPath` is a per-repository git config value (not versioned automatically) — re-run the install command in any fresh clone. |
| Want to bypass for a specific, reviewed commit | `git commit --no-verify` — see "Security Limitation" above; use sparingly and knowingly. |

---

## Current Status (what's actually built)

**Protection API path**: detection, sanitization, policy engine, HTTP API, auth (opt-in), rate limiting, size limits, safe logging, safe metrics, a permanent security regression suite, and a manual verification guide.

**Git protection path**: staged-snapshot scanning reusing the same detector/policy engine, binary/large-file/deleted-file handling, fail-closed error handling, a thin cross-platform pre-commit hook, a manual test CLI, 18 automated tests, and this documentation.

Both paths share one core and were verified — automated (150 total tests passing) and manual (real `git commit` runs, real HTTP requests) — not just implemented.

## Future Work (explicitly not built — do not assume otherwise)

Real LLM provider adapters (OpenAI/Claude/Gemini/Ollama/vLLM/etc.), response inspection and placeholder re-identification, an admin dashboard, a policy management UI, database-backed audit logs, organization/workspace management, centralized policy management, per-language SDKs, enterprise SSO, secret-scanning/DLP/SIEM integrations, advanced analytics, distributed deployment, Kubernetes, high availability, destination-aware policy differences (the `destination` field is accepted today but does not yet change any decision), packaging the Git protection engine as an installable tool for use in repositories other than this one without an environment variable, automatic Git-side sanitization, and server-side/CI-based enforcement of the Git protection (to close the `--no-verify` bypass gap).
