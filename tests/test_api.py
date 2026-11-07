"""API tests with FastAPI's TestClient and a throwaway SQLite database."""

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    from app import db
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "test.db"))
    from app.main import app
    with TestClient(app) as c:
        yield c


def test_health(client):
    body = client.get("/api/health").json()
    assert body["status"] == "ok" and body["ai_enabled"] is False


def test_scan_saves_history_and_detail(client):
    r = client.post("/api/scan", json={"code": "eval(x)", "language": "python"})
    assert r.status_code == 200
    data = r.json()
    assert data["findings"][0]["rule_id"] == "CODE_EXEC"

    history = client.get("/api/scans").json()
    assert history["stats"]["scans"] == 1
    assert history["scans"][0]["finding_count"] == 1

    detail = client.get(f"/api/scans/{data['scan_id']}").json()
    assert detail["code"] == "eval(x)"


def test_upload(client):
    files = {"file": ("bad.js", b"el.innerHTML = location.hash;", "text/javascript")}
    data = client.post("/api/scan/upload", files=files).json()
    assert data["language"] == "javascript"
    assert data["findings"][0]["rule_id"] == "XSS"


def test_upload_rejects_binary(client):
    files = {"file": ("x.py", b"\xff\xfe\x00\x81", "application/octet-stream")}
    assert client.post("/api/scan/upload", files=files).status_code == 415


def test_empty_code_rejected(client):
    assert client.post("/api/scan", json={"code": ""}).status_code == 422


def test_delete_and_404(client):
    sid = client.post("/api/scan", json={"code": "x = 1"}).json()["scan_id"]
    assert client.delete(f"/api/scans/{sid}").status_code == 200
    assert client.get(f"/api/scans/{sid}").status_code == 404


def test_samples_use_allow_list(client):
    assert client.get("/api/samples/python").status_code == 200
    assert client.get("/api/samples/..%2F..%2Fetc%2Fpasswd").status_code == 404


def test_rules_listing(client):
    ids = {r["id"] for r in client.get("/api/rules").json()}
    assert {"SQL_INJECTION", "XSS", "HARDCODED_SECRET"} <= ids


def test_frontend_served(client):
    r = client.get("/")
    assert r.status_code == 200 and "SecureLens" in r.text
