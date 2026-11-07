"""AI layer tests using a fake Anthropic client, so they run offline and in CI."""

from types import SimpleNamespace

from app import ai
from app.scanner import scan

CODE = 'import os\nos.system("ping " + host)\napp.run(host="0.0.0.0")\n'


class FakeClient:
    def __init__(self, payload=None, error=None):
        self.payload, self.error, self.calls = payload, error, []
        self.messages = self

    def create(self, **kwargs):
        self.calls.append(kwargs)
        if self.error:
            raise self.error
        return SimpleNamespace(content=[SimpleNamespace(type="tool_use", input=self.payload)])


def payload(**over):
    base = {
        "overall_assessment": "Command injection allows remote code execution.",
        "verified_findings": [
            {"index": 0, "is_false_positive": False, "explanation": "host=;rm -rf / runs rm.",
             "fixed_code": 'subprocess.run(["ping", host])'},
            {"index": 1, "is_false_positive": True, "explanation": "Runs in a container.", "fixed_code": ""},
            {"index": 99, "is_false_positive": False, "explanation": "bogus", "fixed_code": ""},
        ],
        "additional_findings": [
            {"title": "Missing authentication", "severity": "high", "line": 2, "cwe": "CWE-306",
             "explanation": "Anyone can call this.", "fixed_code": "@login_required"},
        ],
        "patched_code": "import subprocess\n",
    }
    base.update(over)
    return base


def test_request_forces_structured_tool_output():
    client = FakeClient(payload())
    ai.review(CODE, scan(CODE, "python"), client=client)
    call = client.calls[0]
    assert call["tool_choice"] == {"type": "tool", "name": "submit_review"}
    assert call["tools"][0]["input_schema"] is ai.REVIEW_SCHEMA
    # Code is sent line-numbered so Claude can cite real lines
    assert "   2 | os.system" in call["messages"][0]["content"]


def test_merge_applies_verification_and_additions():
    result = scan(CODE, "python")
    merged = ai.merge(result, ai.review(CODE, result, client=FakeClient(payload())))

    cmd = next(f for f in merged["findings"] if f["rule_id"] == "COMMAND_INJECTION")
    assert cmd["ai_fix"] == 'subprocess.run(["ping", host])'

    bind = next(f for f in merged["findings"] if f["rule_id"] == "BIND_ALL_INTERFACES")
    assert bind["false_positive"] is True

    extra = next(f for f in merged["findings"] if f["source"] == "ai")
    assert extra["title"] == "Missing authentication"

    # False positives don't count toward score or summary
    assert merged["summary"]["low"] == 0
    assert merged["summary"]["high"] == 1
    assert merged["ai"]["patched_code"] == "import subprocess\n"


def test_invalid_indexes_from_model_are_dropped():
    out = ai.review(CODE, scan(CODE, "python"), client=FakeClient(payload()))
    assert all(v["index"] < 2 for v in out["verified_findings"])


def test_api_failure_falls_back_to_static():
    result = scan(CODE, "python")
    out = ai.review(CODE, result, client=FakeClient(error=RuntimeError("boom")))
    assert out["mode"] == "static-only"
    assert len(out["verified_findings"]) == len(result.findings)


def test_no_key_means_static_only(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    out = ai.review(CODE, scan(CODE, "python"))
    assert out["mode"] == "static-only" and "ANTHROPIC_API_KEY" in out["reason"]


def test_static_mode_does_not_pretend_to_be_ai():
    result = scan(CODE, "python")
    merged = ai.merge(result, ai._offline_review(result, "x"))
    assert all("ai_explanation" not in f for f in merged["findings"])
