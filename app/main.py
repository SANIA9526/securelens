"""FastAPI application: REST API + static frontend."""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import __version__, ai, db
from .scanner import RULES, scan

STATIC_DIR = Path(__file__).parent / "static"
EXAMPLES_DIR = Path(__file__).parent.parent / "examples"
# Fixed allow-list: the sample endpoint never builds a path from user input
SAMPLES = {"python": "vulnerable_app.py", "javascript": "vulnerable_server.js"}
MAX_UPLOAD_BYTES = 200_000


@asynccontextmanager
async def lifespan(_: FastAPI):
    db.init_db()
    yield


app = FastAPI(
    title="SecureLens",
    version=__version__,
    description="AI-assisted code security reviewer: static analysis + Claude verification and auto-fix.",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("SECURELENS_CORS", "http://localhost:8000").split(","),
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Content-Type"],
)


class ScanRequest(BaseModel):
    code: str = Field(..., min_length=1, max_length=MAX_UPLOAD_BYTES)
    language: str | None = Field(None, description="python | javascript | typescript | php | java")
    filename: str | None = Field(None, max_length=255)
    use_ai: bool = True


def _run(code: str, language: str | None, filename: str | None, use_ai: bool) -> dict:
    result = scan(code, language=language, filename=filename)
    if use_ai:
        review = ai.review(code, result)
    else:
        reason = "AI disabled for this request" if ai.ai_available() else "ANTHROPIC_API_KEY not set"
        review = ai._offline_review(result, reason)
    payload = ai.merge(result, review)
    payload["scan_id"] = db.save_scan(code, filename, payload)
    return payload


# ---------------------------------------------------------------- API routes
@app.get("/api/health")
def health():
    return {"status": "ok", "version": __version__, "ai_enabled": ai.ai_available(), "model": ai.DEFAULT_MODEL}


@app.get("/api/rules")
def rules():
    return [{"id": k, **{f: v[f] for f in ("title", "severity", "cwe", "owasp")}} for k, v in RULES.items()]


@app.get("/api/samples/{name}")
def sample(name: str):
    if name not in SAMPLES:
        raise HTTPException(404, "Unknown sample")
    filename = SAMPLES[name]
    return {"filename": filename, "language": name, "code": (EXAMPLES_DIR / filename).read_text()}


@app.post("/api/scan")
def scan_code(req: ScanRequest):
    return _run(req.code, req.language, req.filename, req.use_ai)


@app.post("/api/scan/upload")
async def scan_upload(file: UploadFile = File(...), use_ai: bool = Query(True)):
    raw = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(raw) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, f"File larger than {MAX_UPLOAD_BYTES // 1000} KB")
    try:
        code = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(415, "Only UTF-8 text source files are supported")
    # Never trust the client filename for anything but language detection / display
    name = Path(file.filename or "upload").name[:255]
    return _run(code, None, name, use_ai)


@app.get("/api/scans")
def history(limit: int = Query(20, ge=1, le=100)):
    return {"stats": db.stats(), "scans": db.list_scans(limit)}


@app.get("/api/scans/{scan_id}")
def scan_detail(scan_id: int):
    item = db.get_scan(scan_id)
    if item is None:
        raise HTTPException(404, "Scan not found")
    return item


@app.delete("/api/scans/{scan_id}")
def scan_delete(scan_id: int):
    if not db.delete_scan(scan_id):
        raise HTTPException(404, "Scan not found")
    return {"deleted": scan_id}


# ---------------------------------------------------------------- frontend
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(STATIC_DIR / "index.html")
