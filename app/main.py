"""FluxOpen dashboard API: authenticated, scope-bound, no browser-side GitHub token."""
from contextlib import contextmanager
import hashlib
import hmac
import io
import json
import os
from pathlib import Path
import secrets
import sqlite3
import subprocess
import sys
import threading
import time
import uuid
import zipfile
from datetime import date
from html import escape

import httpx
from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parent.parent
DB_PATH = Path(os.getenv("DB_PATH", "/data/fluxopen.db"))
REPORTS_DIR = Path(os.getenv("REPORTS_DIR", "/data/reports"))
GH_REPO = os.getenv("GH_REPO", "nutricionistaalmeidavh-spec/fluxopen")
GH_REF = os.getenv("GH_REF", "main")
BACKEND = os.getenv("SCAN_BACKEND", "github").lower()
SECRET = os.getenv("SCAN_SIGNING_SECRET", "")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").lower() == "true"
sys.path.insert(0, str(ROOT))
from security import TOOLS, PASSIVE, normalize_target, validate_selection, sign_manifest  # noqa: E402

if not ADMIN_PASSWORD or len(ADMIN_PASSWORD) < 12:
    raise RuntimeError("Defina ADMIN_PASSWORD com pelo menos 12 caracteres")
if len(SECRET) < 32:
    raise RuntimeError("Defina SCAN_SIGNING_SECRET com pelo menos 32 caracteres")
if BACKEND not in ("github", "local"):
    raise RuntimeError("SCAN_BACKEND deve ser github ou local")
DB_PATH.parent.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)
app = FastAPI(title="FluxOpen", docs_url=None, redoc_url=None, openapi_url=None)

@contextmanager
def db():
    con = sqlite3.connect(str(DB_PATH), timeout=20)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA busy_timeout=20000")
    try:
        yield con
        con.commit()
    finally:
        con.close()

with db() as con:
    con.executescript("""
    CREATE TABLE IF NOT EXISTS sessions (
      token_hash TEXT PRIMARY KEY, csrf TEXT NOT NULL, expires INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS targets (
      id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
      url TEXT UNIQUE NOT NULL, permission TEXT NOT NULL,
      valid_until TEXT NOT NULL, created INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS scans (
      id TEXT PRIMARY KEY, target_id INTEGER NOT NULL, url TEXT NOT NULL,
      tools TEXT NOT NULL, mode TEXT NOT NULL, status TEXT NOT NULL,
      started INTEGER NOT NULL, updated INTEGER NOT NULL,
      run_id INTEGER, report TEXT, error TEXT,
      FOREIGN KEY(target_id) REFERENCES targets(id)
    );
    """)

LOGIN_FAILURES = {}

def unauthorized():
    raise HTTPException(401, "Sessão inválida. Entre novamente.")

def session(request: Request):
    token = request.cookies.get("fluxopen_session", "")
    if not token:
        unauthorized()
    hashed = hashlib.sha256(token.encode()).hexdigest()
    with db() as con:
        record = con.execute("SELECT csrf, expires FROM sessions WHERE token_hash = ?", (hashed,)).fetchone()
    if not record or record["expires"] < time.time():
        unauthorized()
    return dict(record)

def protected(request: Request):
    user = session(request)
    if request.method not in ("GET", "HEAD", "OPTIONS"):
        csrf = request.headers.get("X-CSRF-Token", "")
        if not hmac.compare_digest(csrf, user["csrf"]):
            raise HTTPException(403, "Proteção CSRF: recarregue a página")
    return user

class Login(BaseModel):
    password: str

class TargetIn(BaseModel):
    name: str = Field(min_length=2, max_length=80)
    url: str = Field(min_length=10, max_length=2048)
    permission: str = Field(min_length=15, max_length=500)
    valid_until: date
    confirmed: bool

class ScanIn(BaseModel):
    target_id: int
    tools: list[str]
    mode: str
    confirmed_active: bool = False

@app.get("/")
def index():
    return FileResponse(ROOT / "app" / "static" / "index.html")

@app.get("/api/session")
def get_session(request: Request):
    try:
        user = session(request)
        return {"authenticated": True, "csrf": user["csrf"], "backend": BACKEND, "tools": TOOLS, "passive": PASSIVE}
    except HTTPException:
        return {"authenticated": False}

@app.post("/api/login")
def login(body: Login, request: Request):
    key = request.client.host if request.client else "unknown"
    now = time.time()
    recent = [t for t in LOGIN_FAILURES.get(key, []) if t > now - 900]
    if len(recent) >= 6:
        raise HTTPException(429, "Muitas tentativas. Aguarde 15 minutos")
    if not hmac.compare_digest(body.password, ADMIN_PASSWORD):
        recent.append(now)
        LOGIN_FAILURES[key] = recent
        raise HTTPException(401, "Senha incorreta")
    LOGIN_FAILURES.pop(key, None)
    token = secrets.token_urlsafe(48)
    csrf = secrets.token_urlsafe(32)
    with db() as con:
        con.execute("DELETE FROM sessions WHERE expires < ?", (int(now),))
        con.execute("INSERT INTO sessions VALUES (?, ?, ?)",
                    (hashlib.sha256(token.encode()).hexdigest(), csrf, int(now + 12 * 3600)))
        con.commit()
    response = JSONResponse({"authenticated": True, "csrf": csrf})
    response.set_cookie("fluxopen_session", token, max_age=12 * 3600, httponly=True,
                        secure=COOKIE_SECURE, samesite="strict", path="/")
    return response

@app.post("/api/logout")
def logout(request: Request, _=Depends(protected)):
    token = request.cookies.get("fluxopen_session", "")
    with db() as con:
        con.execute("DELETE FROM sessions WHERE token_hash = ?", (hashlib.sha256(token.encode()).hexdigest(),))
        con.commit()
    response = JSONResponse({"ok": True})
    response.delete_cookie("fluxopen_session", path="/")
    return response

@app.get("/api/targets")
def list_targets(_=Depends(protected)):
    with db() as con:
        rows = con.execute("SELECT id,name,url,valid_until,created FROM targets ORDER BY id DESC").fetchall()
    return [dict(row) for row in rows]

@app.post("/api/targets")
def create_target(body: TargetIn, _=Depends(protected)):
    if not body.confirmed:
        raise HTTPException(422, "Confirme a autorização explícita do proprietário")
    if body.valid_until <= date.today():
        raise HTTPException(422, "A autorização precisa estar vigente")
    try:
        url = normalize_target(body.url)
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    with db() as con:
        try:
            cur = con.execute("INSERT INTO targets (name,url,permission,valid_until,created) VALUES (?,?,?,?,?)",
                              (body.name.strip(), url, body.permission.strip(),
                               body.valid_until.isoformat(), int(time.time())))
            con.commit()
        except sqlite3.IntegrityError:
            raise HTTPException(409, "Esta URL já está cadastrada")
    return {"id": cur.lastrowid, "url": url}

@app.get("/api/scans")
def list_scans(_=Depends(protected)):
    with db() as con:
        rows = con.execute("""SELECT s.id,s.url,s.tools,s.mode,s.status,s.started,
          s.updated,s.run_id,s.error,t.name AS target_name FROM scans s
          JOIN targets t ON t.id=s.target_id ORDER BY s.started DESC LIMIT 100""").fetchall()
    # Update a small number of pending runs; do not flood the GitHub API.
    for row in [r for r in rows if r["status"] in ("queued", "running")][:2]:
        refresh_github(row)
    with db() as con:
        rows = con.execute("""SELECT s.id,s.url,s.tools,s.mode,s.status,s.started,
          s.updated,s.run_id,s.error,t.name AS target_name FROM scans s
          JOIN targets t ON t.id=s.target_id ORDER BY s.started DESC LIMIT 100""").fetchall()
    return [{**dict(row), "tools": json.loads(row["tools"])} for row in rows]

def github_request(method, endpoint, **kwargs):
    token = os.getenv("GH_TOKEN", "")
    if not token:
        raise RuntimeError("Configure GH_TOKEN no servidor (não no navegador)")
    headers = {"Authorization": "Bearer " + token, "Accept": "application/vnd.github+json",
               "X-GitHub-Api-Version": "2022-11-28"}
    with httpx.Client(timeout=25, follow_redirects=True) as client:
        response = client.request(method, "https://api.github.com/repos/" + GH_REPO + endpoint,
                                  headers=headers, **kwargs)
        response.raise_for_status()
        return response

def mark_scan(scan_id, **values):
    values["updated"] = int(time.time())
    columns = ",".join(k + "=?" for k in values)
    with db() as con:
        con.execute("UPDATE scans SET " + columns + " WHERE id=?", (*values.values(), scan_id))
        con.commit()

def watch_local(scan_id, process):
    process.wait()
    path = REPORTS_DIR / scan_id / "report.json"
    if path.exists():
        try:
            report = json.loads(path.read_text())
            mark_scan(scan_id, status=report.get("status", "failed"),
                      report=json.dumps(report), error=None)
            return
        except Exception:
            pass
    mark_scan(scan_id, status="failed", error="Runner local terminou sem relatório válido")

@app.post("/api/scans")
def create_scan(body: ScanIn, _=Depends(protected)):
    try:
        selected = validate_selection(body.tools, body.mode)
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    if body.mode == "active" and not body.confirmed_active:
        raise HTTPException(422, "Confirme a autorização para testes ativos")
    with db() as con:
        target = con.execute("SELECT * FROM targets WHERE id=?", (body.target_id,)).fetchone()
    if not target:
        raise HTTPException(404, "Alvo não encontrado")
    if date.fromisoformat(target["valid_until"]) <= date.today():
        raise HTTPException(422, "Autorização do alvo expirada")
    try:
        url = normalize_target(target["url"])
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    scan_id = uuid.uuid4().hex
    now = int(time.time())
    manifest = dict(id=scan_id, url=url, tools=selected, mode=body.mode, issued=now, expires=now + 7200)
    packed, signature = sign_manifest(manifest, SECRET)
    with db() as con:
        con.execute("""INSERT INTO scans
          (id,target_id,url,tools,mode,status,started,updated) VALUES (?,?,?,?,?,?,?,?)""",
                    (scan_id, body.target_id, url, json.dumps(selected), body.mode, "queued", now, now))
        con.commit()
    try:
        if BACKEND == "github":
            github_request("POST", "/actions/workflows/scan.yml/dispatches",
                           json={"ref": GH_REF, "inputs": {"payload": packed, "signature": signature,
                                                            "scan_id": scan_id}})
        else:
            out = REPORTS_DIR / scan_id
            out.mkdir(parents=True, exist_ok=True)
            with open(out / "runner.log", "wb") as log:
                proc = subprocess.Popen([sys.executable, str(ROOT / "scanner" / "runner.py"),
                                         "--payload", packed, "--signature", signature,
                                         "--output", str(out)], cwd=str(ROOT),
                                        env={**os.environ, "SCAN_SIGNING_SECRET": SECRET},
                                        stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            mark_scan(scan_id, status="running")
            threading.Thread(target=watch_local, args=(scan_id, proc), daemon=True).start()
    except (Exception) as exc:
        mark_scan(scan_id, status="failed", error="Falha no disparo: " + str(exc)[:240])
        raise HTTPException(502, "Não foi possível disparar: " + str(exc)[:180])
    return {"id": scan_id, "status": "queued", "backend": BACKEND}

def refresh_github(row):
    if row["status"] not in ("queued", "running") or BACKEND != "github":
        return
    try:
        if row["run_id"]:
            run = github_request("GET", "/actions/runs/" + str(row["run_id"])).json()
        else:
            runs = github_request("GET", "/actions/workflows/scan.yml/runs",
                                   params={"event": "workflow_dispatch", "per_page": 100}).json().get("workflow_runs", [])
            run = next((r for r in runs if row["id"] in
                        (str(r.get("display_title", "")) + " " + str(r.get("name", "")))), None)
            if not run:
                return
        run_id = run["id"]
        if run["status"] != "completed":
            mark_scan(row["id"], run_id=run_id, status="running")
            return
        artifact_list = github_request("GET", "/actions/runs/" + str(run_id) + "/artifacts").json().get("artifacts", [])
        artifact = next((a for a in artifact_list if a["name"] == "fluxopen-" + row["id"]), None)
        if artifact:
            archive = github_request("GET", "/actions/artifacts/" + str(artifact["id"]) + "/zip").content
            with zipfile.ZipFile(io.BytesIO(archive)) as zf:
                report_name = next((n for n in zf.namelist() if n.endswith("report.json")), None)
                if report_name:
                    report = json.loads(zf.read(report_name))
                    if report.get("id") != row["id"]:
                        raise ValueError("Relatório não corresponde à auditoria")
                    mark_scan(row["id"], run_id=run_id, status=report.get("status", "failed"),
                              report=json.dumps(report), error=None)
                    return
        mark_scan(row["id"], run_id=run_id, status="failed",
                  error="Workflow concluído sem artefato. Consulte os logs no GitHub.")
    except Exception as exc:
        mark_scan(row["id"], error="Sincronização: " + str(exc)[:180])

@app.get("/api/scans/{scan_id}")
def scan_detail(scan_id: str, _=Depends(protected)):
    with db() as con:
        row = con.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Auditoria não encontrada")
    refresh_github(row)
    if BACKEND == "local" and row["status"] in ("running", "queued"):
        path = REPORTS_DIR / scan_id / "report.json"
        if path.exists():
            try:
                report = json.loads(path.read_text())
                mark_scan(scan_id, status=report.get("status", "failed"), report=json.dumps(report))
            except Exception:
                pass
    with db() as con:
        row = con.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    output = dict(row)
    output["tools"] = json.loads(output["tools"])
    output["report"] = json.loads(output["report"]) if output["report"] else None
    if BACKEND == "local" and output["report"] is None:
        progress = REPORTS_DIR / scan_id / "progress.json"
        if progress.exists():
            try:
                output["report"] = json.loads(progress.read_text())
            except (OSError, ValueError):
                pass
    return output

@app.get("/api/scans/{scan_id}/download")
def download(scan_id: str, format: str = "json", _=Depends(protected)):
    with db() as con:
        row = con.execute("SELECT report FROM scans WHERE id=?", (scan_id,)).fetchone()
    if not row or not row["report"]:
        raise HTTPException(404, "Relatório ainda indisponível")
    report = json.loads(row["report"])
    if format == "json":
        return Response(json.dumps(report, ensure_ascii=False, indent=2),
                        media_type="application/json",
                        headers={"Content-Disposition": 'attachment; filename="fluxopen-' + scan_id + '.json"'})
    if format != "html":
        raise HTTPException(422, "Formato inválido")
    modules = "".join("<section><h2>" + escape(t["tool"]) + " — " + escape(t["status"]) +
                      "</h2><pre>" + escape(t.get("excerpt", "")) + "</pre></section>"
                      for t in report.get("modules", []))
    html = ("<!doctype html><html lang='pt-BR'><meta charset='utf-8'><title>FluxOpen</title>"
            "<style>body{font:16px system-ui;max-width:900px;margin:40px auto;padding:24px}"
            "section{border-top:1px solid #ddd;padding:14px 0}pre{white-space:pre-wrap;overflow-wrap:anywhere}</style>"
            "<h1>FluxOpen · Relatório de segurança</h1><p>Alvo: " +
            escape(report.get("url", "")) + "</p><p>Status: " +
            escape(report.get("status", "")) + "</p>" + modules + "</html>")
    return HTMLResponse(html, headers={"Content-Disposition": 'attachment; filename="fluxopen-' + scan_id + '.html"'})

@app.get("/health")
def health():
    return {"ok": True}
