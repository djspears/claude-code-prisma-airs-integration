#!/usr/bin/env python3
"""
Prisma AIRS Prompt Scanner — Claude Code UserPromptSubmit Hook

Intercepts every prompt before it reaches Claude and scans it via the
Prisma AI Runtime Security API. Blocks the prompt if a threat is detected.

Required environment variables:
  AIRS_API_KEY      — your x-pan-token from Strata Cloud Manager
  AIRS_PROFILE_NAME — your security profile name (e.g. "my-security-profile")

Optional:
  AIRS_API_ENDPOINT — override the base URL (default: US endpoint)
  AIRS_APP_NAME     — label shown in AIRS logs (default: "claude-code")
  AIRS_FAIL_CLOSED  — set to "1" to block prompts when AIRS is unavailable
                      (default: "0" — fail open, allow prompts on errors)
  AIRS_DEBUG        — set to "1" to enable verbose debug output
"""

import json
import os
import sys
import uuid

try:
    import urllib.request
    import urllib.error
except ImportError:
    pass  # stdlib, always available


# ── Config ─────────────────────────────────────────────────────────────────────
API_KEY      = os.environ.get("AIRS_API_KEY", "")
PROFILE_NAME = os.environ.get("AIRS_PROFILE_NAME", "")
ENDPOINT     = os.environ.get("AIRS_API_ENDPOINT",
               "https://service.api.aisecurity.paloaltonetworks.com")
APP_NAME     = os.environ.get("AIRS_APP_NAME", "claude-code")
FAIL_CLOSED  = os.environ.get("AIRS_FAIL_CLOSED", "0") == "1"

SCAN_URL = f"{ENDPOINT.rstrip('/')}/v1/scan/sync/request"

# Threat type labels for human-readable output
THREAT_LABELS = {
    "injection":      "Prompt Injection",
    "url_cats":       "Malicious URL",
    "dlp":            "Sensitive Data (DLP)",
    "toxic_content":  "Toxic Content",
    "malicious_code": "Malicious Code",
    "agent":          "AI Agent Attack",
    "topic_violation": "Topic Violation",
}


def read_prompt_from_stdin() -> str:
    """Read and parse the hook input from Claude Code."""
    try:
        raw = sys.stdin.read()
        if not raw.strip():
            return ""
        data = json.loads(raw)
        # Claude Code sends the prompt under the "prompt" key
        return data.get("prompt", "")
    except (json.JSONDecodeError, Exception):
        return ""


def scan_prompt(prompt: str) -> dict:
    """Send the prompt to Prisma AIRS for scanning. Returns the API response."""
    payload = {
        "tr_id": str(uuid.uuid4()),
        "ai_profile": {
            "profile_name": PROFILE_NAME
        },
        "metadata": {
            "app_name": APP_NAME,
            "ai_model": "claude"
        },
        "contents": [
            {
                "prompt": prompt
            }
        ]
    }

    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        SCAN_URL,
        data=body,
        headers={
            "Content-Type": "application/json",
            "x-pan-token": API_KEY,
        },
        method="POST"
    )

    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8"))


def get_triggered_threats(result: dict) -> list[str]:
    """Extract which threat types were detected from the AIRS response."""
    detected = result.get("prompt_detected", {})
    return [
        THREAT_LABELS.get(k, k)
        for k, triggered in detected.items()
        if triggered is True
    ]


def main():
    debug = os.environ.get("AIRS_DEBUG", "") == "1"

    def dbg(msg):
        if debug:
            print(f"[AIRS DEBUG] {msg}", file=sys.stderr)

    # ── Validate config ────────────────────────────────────────────────────────
    dbg(f"API_KEY set: {bool(API_KEY)} | PROFILE_NAME: '{PROFILE_NAME}'")

    def fail(reason: str):
        """Block or allow based on AIRS_FAIL_CLOSED setting."""
        if FAIL_CLOSED:
            block_message = {
                "decision": "block",
                "reason": f"🛡️  AIRS scanner error (fail-closed mode):\n{reason}\n\nResolve the issue or set AIRS_FAIL_CLOSED=0 to allow prompts when AIRS is unavailable."
            }
            print(json.dumps(block_message))
            sys.exit(1)
        else:
            print(f"⚠️  AIRS scanner error (fail-open): {reason}", file=sys.stderr)
            sys.exit(0)

    if not API_KEY or not PROFILE_NAME:
        fail("AIRS_API_KEY and AIRS_PROFILE_NAME environment variables are not set.")

    # ── Read prompt ────────────────────────────────────────────────────────────
    prompt = read_prompt_from_stdin()
    dbg(f"Prompt received ({len(prompt)} chars): {prompt[:80]!r}")

    if not prompt.strip():
        dbg("Empty prompt — skipping scan")
        sys.exit(0)  # nothing to scan

    # ── Scan ───────────────────────────────────────────────────────────────────
    dbg(f"Sending to AIRS: {SCAN_URL}")
    try:
        result = scan_prompt(prompt)
        dbg(f"AIRS response: {json.dumps(result)}")
    except urllib.error.HTTPError as e:
        fail(f"AIRS API returned HTTP {e.code}: {e.reason}")
    except Exception as e:
        fail(f"Could not reach AIRS API: {e}")

    action   = result.get("action", "allow")
    category = result.get("category", "benign")
    dbg(f"Verdict: action={action} category={category}")

    # ── Allow ──────────────────────────────────────────────────────────────────
    if action == "allow":
        # Optionally log clean scans to stderr (visible in Claude Code output)
        # print(f"✅ AIRS: clean ({category})", file=sys.stderr)
        sys.exit(0)

    # ── Block ──────────────────────────────────────────────────────────────────
    threats = get_triggered_threats(result)
    threat_list = "\n  • ".join(threats) if threats else category

    scan_id   = result.get("scan_id", "N/A")
    report_id = result.get("report_id", "N/A")

    # Output goes to stdout — Claude Code shows this to the user on block
    block_message = {
        "decision": "block",
        "reason": (
            f"🛡️  Prisma AIRS blocked this prompt.\n\n"
            f"Threat(s) detected:\n  • {threat_list}\n\n"
            f"Scan ID:   {scan_id}\n"
            f"Report ID: {report_id}\n\n"
            f"Review the scan in Strata Cloud Manager for details."
        )
    }
    print(json.dumps(block_message))
    sys.exit(1)  # non-zero exit blocks the prompt


if __name__ == "__main__":
    main()
