"""
AI review layer.

The static scanner is fast and deterministic but only knows the patterns it was
given. This layer sends the code *plus* the static findings to Claude and asks it to:

  * confirm or reject each static finding (cutting false positives),
  * explain each real issue in plain language with a concrete fix,
  * catch logic-level issues regex/AST rules can't see (missing auth checks,
    IDOR, race conditions, business-logic flaws),
  * produce a patched version of the code.

Structured output is enforced with a forced tool call, so the response is always
valid JSON matching REVIEW_SCHEMA rather than free text that has to be parsed.

If no API key is configured (or the call fails), the app degrades gracefully to
static-only results so it still works offline and in CI.
"""

from __future__ import annotations

import json
import logging
import os

from .scanner import RULES, ScanResult

log = logging.getLogger("securelens.ai")

DEFAULT_MODEL = os.getenv("SECURELENS_MODEL", "claude-sonnet-5-5")
MAX_CODE_CHARS = 40_000

SYSTEM_PROMPT = """You are a senior application-security engineer reviewing code for a developer.
You receive source code and the output of a static analyser.

Rules:
- Judge each static finding on the actual code. Mark it a false positive only when the input
  provably cannot be attacker-controlled or the code is already safe.
- Add issues the analyser missed, especially logic flaws: missing authentication or authorisation,
  IDOR, mass assignment, race conditions, insecure defaults, information leakage.
- Explanations are for a junior developer: say what an attacker would actually do.
- Fixes must be minimal, idiomatic and runnable in the same language and framework.
- Never invent line numbers; use the numbered lines you were given.
- Return results ONLY via the submit_review tool."""

REVIEW_SCHEMA = {
    "type": "object",
    "properties": {
        "overall_assessment": {
            "type": "string",
            "description": "2-3 sentence verdict on the code's security posture.",
        },
        "verified_findings": {
            "type": "array",
            "description": "One entry per static finding, in the same order.",
            "items": {
                "type": "object",
                "properties": {
                    "index": {"type": "integer"},
                    "is_false_positive": {"type": "boolean"},
                    "explanation": {"type": "string", "description": "Plain-language attack scenario."},
                    "fixed_code": {"type": "string", "description": "Corrected version of the affected lines."},
                },
                "required": ["index", "is_false_positive", "explanation", "fixed_code"],
            },
        },
        "additional_findings": {
            "type": "array",
            "description": "Issues the static analyser missed.",
            "items": {
                "type": "object",
                "properties": {
                    "title": {"type": "string"},
                    "severity": {"type": "string", "enum": ["critical", "high", "medium", "low"]},
                    "line": {"type": "integer"},
                    "cwe": {"type": "string"},
                    "owasp": {"type": "string"},
                    "explanation": {"type": "string"},
                    "fixed_code": {"type": "string"},
                },
                "required": ["title", "severity", "line", "cwe", "explanation", "fixed_code"],
            },
        },
        "patched_code": {
            "type": "string",
            "description": "The full file with every confirmed issue fixed.",
        },
    },
    "required": ["overall_assessment", "verified_findings", "additional_findings", "patched_code"],
}


def ai_available() -> bool:
    return bool(os.getenv("ANTHROPIC_API_KEY"))


def _numbered(code: str) -> str:
    return "\n".join(f"{i:>4} | {line}" for i, line in enumerate(code.splitlines(), start=1))


def _build_user_message(code: str, result: ScanResult) -> str:
    static = [
        {"index": i, "rule": f.rule_id, "title": f.title, "severity": f.severity,
         "line": f.line, "snippet": f.snippet}
        for i, f in enumerate(result.findings)
    ]
    return (
        f"Language: {result.language}\n\n"
        f"Static analyser findings (JSON):\n{json.dumps(static, indent=2)}\n\n"
        f"Source code (line-numbered):\n```\n{_numbered(code[:MAX_CODE_CHARS])}\n```"
    )


def _offline_review(result: ScanResult, reason: str) -> dict:
    """Deterministic fallback built from rule metadata, used when Claude is unavailable."""
    return {
        "mode": "static-only",
        "reason": reason,
        "overall_assessment": (
            f"Static analysis found {len(result.findings)} potential "
            f"issue{'' if len(result.findings) == 1 else 's'}. Expand each one for why it matters and how to fix it."
        ),
        "verified_findings": [
            {"index": i, "is_false_positive": False,
             "explanation": RULES[f.rule_id]["description"],
             "fixed_code": RULES[f.rule_id]["recommendation"]}
            for i, f in enumerate(result.findings)
        ],
        "additional_findings": [],
        "patched_code": None,
    }


def review(code: str, result: ScanResult, client=None, model: str | None = None) -> dict:
    """
    Run the AI review. `client` can be injected for testing (any object exposing
    `.messages.create(...)` like anthropic.Anthropic).
    """
    if client is None:
        if not ai_available():
            return _offline_review(result, "ANTHROPIC_API_KEY not set")
        try:
            import anthropic
            client = anthropic.Anthropic()
        except Exception as e:  # pragma: no cover - import/config problems
            return _offline_review(result, f"Anthropic client unavailable: {e}")

    try:
        response = client.messages.create(
            model=model or DEFAULT_MODEL,
            max_tokens=8000,
            system=SYSTEM_PROMPT,
            tools=[{
                "name": "submit_review",
                "description": "Submit the structured security review.",
                "input_schema": REVIEW_SCHEMA,
            }],
            tool_choice={"type": "tool", "name": "submit_review"},
            messages=[{"role": "user", "content": _build_user_message(code, result)}],
        )
        tool_use = next(b for b in response.content if getattr(b, "type", None) == "tool_use")
        data = dict(tool_use.input)
    except Exception as e:
        log.warning("AI review failed, falling back to static-only: %s", e)
        return _offline_review(result, f"AI review failed: {type(e).__name__}")

    data["mode"] = "ai"
    data["model"] = model or DEFAULT_MODEL
    # Defensive normalisation: keep only indexes that exist
    data["verified_findings"] = [
        v for v in data.get("verified_findings", [])
        if isinstance(v.get("index"), int) and 0 <= v["index"] < len(result.findings)
    ]
    data.setdefault("additional_findings", [])
    return data


def merge(result: ScanResult, ai: dict) -> dict:
    """Combine static findings and AI review into one response payload."""
    is_ai = ai.get("mode") == "ai"
    by_index = {v["index"]: v for v in ai.get("verified_findings", [])}
    findings = []
    for i, f in enumerate(result.findings):
        item = f.to_dict()
        v = by_index.get(i)
        if v and is_ai:
            item["ai_explanation"] = v.get("explanation")
            item["ai_fix"] = v.get("fixed_code")
            item["false_positive"] = bool(v.get("is_false_positive"))
        else:
            item["false_positive"] = False
        findings.append(item)

    for extra in ai.get("additional_findings", []):
        findings.append({
            "rule_id": "AI_" + "".join(c if c.isalnum() else "_" for c in extra["title"].upper())[:40],
            "title": extra["title"],
            "severity": extra["severity"],
            "line": extra.get("line", 0),
            "snippet": "",
            "cwe": extra.get("cwe", ""),
            "owasp": extra.get("owasp", ""),
            "description": extra["explanation"],
            "recommendation": "",
            "ai_explanation": extra["explanation"],
            "ai_fix": extra.get("fixed_code"),
            "source": "ai",
            "false_positive": False,
        })

    from .scanner import SEVERITY_ORDER, SEVERITY_WEIGHT
    active = [f for f in findings if not f["false_positive"]]
    summary = {s: 0 for s in SEVERITY_ORDER}
    for f in active:
        summary[f["severity"]] += 1
    findings.sort(key=lambda f: (f["false_positive"], -SEVERITY_ORDER[f["severity"]], f["line"]))

    return {
        "language": result.language,
        "lines_scanned": result.lines_scanned,
        "parse_error": result.parse_error,
        "risk_score": min(100, sum(SEVERITY_WEIGHT[f["severity"]] for f in active)),
        "summary": summary,
        "findings": findings,
        "ai": {
            "mode": ai.get("mode"),
            "model": ai.get("model"),
            "reason": ai.get("reason"),
            "overall_assessment": ai.get("overall_assessment"),
            "patched_code": ai.get("patched_code"),
        },
    }
