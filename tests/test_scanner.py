"""Scanner tests: each rule must fire on vulnerable code and stay quiet on the safe equivalent."""

from pathlib import Path

import pytest

from app.scanner import detect_language, scan

EXAMPLES = Path(__file__).parent.parent / "examples"


def rules(code: str, language: str | None = None) -> set[str]:
    return {f.rule_id for f in scan(code, language=language).findings}


# ------------------------------------------------------------------ Python: vulnerable vs safe pairs
PY_CASES = [
    ("SQL_INJECTION",
     'cur.execute(f"SELECT * FROM u WHERE id = {uid}")',
     'cur.execute("SELECT * FROM u WHERE id = ?", (uid,))'),
    ("SQL_INJECTION",
     'cur.execute("SELECT * FROM u WHERE n = \'" + name + "\'")',
     'cur.execute("SELECT * FROM u")'),
    ("SQL_INJECTION",
     'cur.execute("SELECT * FROM u WHERE id = {}".format(uid))',
     'cur.execute("SELECT * FROM u WHERE id = %s", [uid])'),
    ("COMMAND_INJECTION",
     'import subprocess\nsubprocess.run(f"ping {host}", shell=True)',
     'import subprocess\nsubprocess.run(["ping", host])'),
    ("COMMAND_INJECTION",
     'import os\nos.system("rm " + path)',
     'import os\nos.remove(path)'),
    ("CODE_EXEC", "eval(user_input)", 'eval("1 + 1")'),
    ("INSECURE_DESERIALIZATION", "import pickle\npickle.loads(data)", "import json\njson.loads(data)"),
    ("INSECURE_DESERIALIZATION", "import yaml\nyaml.load(s)", "import yaml\nyaml.safe_load(s)"),
    ("HARDCODED_SECRET", 'API_KEY = "a8f3k2l9q0w1"', 'API_KEY = os.getenv("API_KEY")'),
    ("WEAK_HASH", "import hashlib\nhashlib.md5(pw)", "import hashlib\nhashlib.sha256(pw)"),
    ("INSECURE_RANDOM",
     "import random\nreset_token = str(random.randint(0, 10**6))",
     "import secrets\nreset_token = secrets.token_urlsafe(32)"),
    ("TLS_VERIFY_DISABLED", "requests.get(url, verify=False)", "requests.get(url)"),
    ("DEBUG_ENABLED", "app.run(debug=True)", "app.run(debug=False)"),
    ("PATH_TRAVERSAL",
     'open(os.path.join("uploads", request.args["f"]))',
     'open(os.path.join("uploads", secure_filename(request.args["f"])))'),
    ("ASSERT_FOR_SECURITY", "assert user.is_admin", "assert len(items) > 0"),
]


@pytest.mark.parametrize("rule,vulnerable,safe", PY_CASES)
def test_python_rule_pairs(rule, vulnerable, safe):
    assert rule in rules(vulnerable, "python"), f"{rule} missed:\n{vulnerable}"
    assert rule not in rules(safe, "python"), f"{rule} false positive:\n{safe}"


def test_placeholder_secrets_are_ignored():
    assert "HARDCODED_SECRET" not in rules('password = "changeme"\ntoken = ""', "python")


def test_known_token_formats_detected_in_any_language():
    assert "HARDCODED_SECRET" in rules('cfg = {"k": "AKIAABCDEFGHIJKLMNOP"}', "python")
    assert "HARDCODED_SECRET" in rules('const t = "ghp_' + "a" * 36 + '";', "javascript")


def test_md5_marked_not_for_security_is_allowed():
    assert "WEAK_HASH" not in rules("hashlib.md5(data, usedforsecurity=False)", "python")


# ------------------------------------------------------------------ JavaScript / PHP / Java
@pytest.mark.parametrize("rule,code,lang", [
    ("SQL_INJECTION", "db.query(`SELECT * FROM t WHERE id = ${req.query.id}`)", "javascript"),
    ("COMMAND_INJECTION", "exec(`ls ${req.query.dir}`)", "javascript"),
    ("XSS", "el.innerHTML = location.hash", "javascript"),
    ("CODE_EXEC", "eval(req.body.expr)", "javascript"),
    ("INSECURE_RANDOM", "const sessionId = Math.random().toString(36)", "javascript"),
    ("TLS_VERIFY_DISABLED", "https.request({ rejectUnauthorized: false })", "typescript"),
    ("SQL_INJECTION", '$db->query("SELECT * FROM u WHERE id = " . $_GET["id"]);', "php"),
    ("XSS", 'echo $_GET["name"];', "php"),
    ("INSECURE_DESERIALIZATION", "unserialize($_COOKIE['cart']);", "php"),
    ("COMMAND_INJECTION", 'Runtime.getRuntime().exec("ping " + host);', "java"),
    ("WEAK_HASH", 'MessageDigest.getInstance("MD5");', "java"),
])
def test_regex_rules(rule, code, lang):
    assert rule in rules(code, lang)


def test_comments_are_skipped():
    assert rules("// el.innerHTML = x", "javascript") == set()


# ------------------------------------------------------------------ behaviour
def test_example_app_finds_all_major_classes():
    found = rules((EXAMPLES / "vulnerable_app.py").read_text(), "python")
    assert {"SQL_INJECTION", "COMMAND_INJECTION", "CODE_EXEC", "INSECURE_DESERIALIZATION",
            "HARDCODED_SECRET", "WEAK_HASH", "INSECURE_RANDOM", "PATH_TRAVERSAL"} <= found


def test_findings_sorted_by_severity_and_deduplicated():
    result = scan('import os\nAPI_KEY = "abcdef123456"\nos.system("x" + y)', "python")
    sev = [f.severity for f in result.findings]
    assert sev == sorted(sev, key=["critical", "high", "medium", "low", "info"].index)
    keys = [(f.rule_id, f.line) for f in result.findings]
    assert len(keys) == len(set(keys))


def test_risk_score_bounds():
    assert scan("x = 1", "python").risk_score == 0
    assert scan((EXAMPLES / "vulnerable_app.py").read_text()).risk_score == 100


def test_syntax_error_falls_back_to_regex():
    result = scan('def broken(:\n    API_KEY = "abcdef123456"', "python")
    assert result.parse_error is not None
    assert "HARDCODED_SECRET" in {f.rule_id for f in result.findings}


def test_every_finding_has_taxonomy():
    for f in scan((EXAMPLES / "vulnerable_app.py").read_text()).findings:
        assert f.cwe.startswith("CWE-") and f.owasp


@pytest.mark.parametrize("code,filename,expected", [
    ("x = 1", "a.py", "python"),
    ("anything", "a.tsx", "typescript"),
    ("<?php echo 1;", None, "php"),
    ("def f():\n  pass", None, "python"),
    ("const x = () => 1;", None, "javascript"),
    ("public class A { }", None, "java"),
    ("eval(input())", None, "python"),
])
def test_detect_language(code, filename, expected):
    assert detect_language(code, filename) == expected
