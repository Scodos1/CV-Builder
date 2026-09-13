"""MONO Studio — real backend (FastAPI + SQLAlchemy).

Contract (matches frontend):
  POST /api/auth/register/  {name,email,password} -> {token,refresh,user}
  POST /api/auth/login/     {email,password}      -> {token,refresh,user}
  POST /api/auth/refresh/   {refresh}             -> {token}
  GET  /api/resumes/                              -> owned resumes
  POST /api/resumes/                              -> create
  GET  /api/resumes/{id}/                         -> single (ownership-verified)
  PATCH /api/resumes/{id}/                        -> autosave
  DELETE /api/resumes/{id}/                       -> delete
  POST /api/resumes/{id}/duplicate/               -> fork
  GET  /api/resumes/{id}/export/?format=html|txt  -> server-side export
  POST /api/resumes/{id}/export/                  -> same (compat with UI label)
  POST /api/ai/improve-summary/ {text,mode}       -> {improved, provider}
  POST /api/ai/improve-bullet/  {text}            -> {improved, provider}
  POST /api/ai/analyze-resume/  {resume}          -> {score,checks?,note}
  POST /api/ai/analyze-job/ {resume,jd}           -> {score,matched,missing}

Storage: SQLAlchemy. Default SQLite file (dev, zero setup).
Prod: set DATABASE_URL=postgresql+psycopg2://user:pass@host:5432/mono
Existing db.json is imported once via: py -3 migrate_json_to_sql.py

Run:
  cd backend
  py -3 -m pip install -r requirements.txt
  py -3 main.py   # http://localhost:8000/docs
Env: see .env.example
"""
import copy
import json
import os
import re
import time
import uuid
from collections import defaultdict
from pathlib import Path
from typing import Optional

import jwt
from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from db import DATABASE_URL, Resume as ResumeRow, User, get_db, init_db

# Password hashing: stdlib PBKDF2 (avoids bcrypt version pain on Windows).
# Old db.json bcrypt hashes from the pre-Postgres prototype won't verify —
# affected dev users re-register once (see README migration note).
import hashlib
import secrets

def hash_pw(password: str) -> str:
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 200_000)
    return f"pbkdf2$200000${salt}${dk.hex()}"

def verify_pw(password: str, stored: str) -> bool:
    try:
        if stored.startswith("pbkdf2$"):
            _, iters, salt, hexdk = stored.split("$")
            dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(iters))
            return secrets.compare_digest(dk.hex(), hexdk)
        from passlib.context import CryptContext as _CC  # legacy bcrypt hashes only
        return _CC(schemes=["bcrypt"], deprecated="auto").verify(password, stored)
    except Exception:
        return False

SECRET = os.getenv("MONO_JWT_SECRET", "dev-secret-change-me")
ENV = os.getenv("MONO_ENV", "dev").lower()  # dev | prod
if ENV == "prod" and (not os.getenv("MONO_JWT_SECRET") or len(SECRET) < 32):
    raise RuntimeError("MONO_ENV=prod requires MONO_JWT_SECRET of 32+ chars")
DB_PATH = Path(os.getenv("MONO_DB_PATH", str(Path(__file__).parent / "db.json")))
CORS_ORIGINS = [o.strip() for o in os.getenv("MONO_CORS_ORIGINS", "*").split(",") if o.strip()]
if ENV == "prod" and CORS_ORIGINS == ["*"]:
    raise RuntimeError("MONO_ENV=prod requires MONO_CORS_ORIGINS set to your domain(s), not *")
ACCESS_TTL = int(os.getenv("MONO_ACCESS_TTL", "3600"))       # 1h
REFRESH_TTL = int(os.getenv("MONO_REFRESH_TTL", "2592000"))  # 30d
MAX_RESUME_BYTES = int(os.getenv("MONO_MAX_RESUME_BYTES", "512000"))  # 500KB DoS cap
MAX_AI_TEXT = int(os.getenv("MONO_MAX_AI_TEXT", "6000"))

from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

_docs = None if ENV == "prod" else "/docs"
app = FastAPI(title="MONO Studio API", lifespan=lifespan, docs_url=_docs, redoc_url=None)
init_db()  # also init on import so TestClient / workers without lifespan still work

app.add_middleware(CORSMiddleware,
                   allow_origins=["*"] if CORS_ORIGINS == ["*"] else CORS_ORIGINS,
                   allow_methods=["*"], allow_headers=["*"])

@app.middleware("http")
async def _security_headers(req: Request, call_next):
    resp = await call_next(req)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    if req.url.scheme == "https":
        resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return resp

def _enforce_size(payload: dict, what: str = "payload"):
    try:
        n = len(json.dumps(payload or {}))
    except Exception:
        n = 0
    if n > MAX_RESUME_BYTES:
        raise HTTPException(413, f"{what} too large ({n} > {MAX_RESUME_BYTES} bytes)")

# ---------- rate limit (in-memory, per-process; use Redis for multi-worker) ----------
_hits: dict = defaultdict(list)
def rate_limit(key: str, limit: int, window: int = 60):
    now = time.time()
    arr = [t for t in _hits[key] if now - t < window]
    if len(arr) >= limit:
        raise HTTPException(429, "Rate limited — slow down")
    arr.append(now); _hits[key] = arr

def rl_auth(req: Request): rate_limit(f"auth:{req.client.host if req.client else '?'}", 20)
def rl_ai(req: Request): rate_limit(f"ai:{req.client.host if req.client else '?'}", 30)

# ---------- auth ----------
def make_token(uid: str, ttl: int = ACCESS_TTL, kind: str = "access"):
    now = int(time.time())
    return jwt.encode({"sub": uid, "kind": kind, "iat": now, "exp": now + ttl}, SECRET, algorithm="HS256")

def auth_user(authorization: Optional[str] = Header(None), db: Session = Depends(get_db)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Missing Bearer token")
    try:
        data = jwt.decode(authorization[7:], SECRET, algorithms=["HS256"])
        if data.get("kind", "access") != "access": raise ValueError("not access token")
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "Token expired — refresh it")
    except Exception:
        raise HTTPException(401, "Invalid token")
    u = db.query(User).filter(User.id == data.get("sub")).first()
    if not u: raise HTTPException(401, "User not found")
    return u

class Register(BaseModel):
    name: str; email: str; password: str
class Login(BaseModel):
    email: str; password: str

def _public(u: User): return {"id": u.id, "name": u.name, "email": u.email}

@app.post("/api/auth/register/", dependencies=[])
def register(b: Register, req: Request, db: Session = Depends(get_db)):
    rl_auth(req)
    email = (b.email or "").strip().lower()[:320]
    name = (b.name or "").strip()[:200]
    if not re.match(r".+@.+\..+", email): raise HTTPException(400, "Invalid email")
    if len(b.password or "") < 8 or len(b.password or "") > 128: raise HTTPException(400, "Use 8–128 characters")
    if not name: raise HTTPException(400, "Name required")
    if db.query(User).filter(User.email == email).first():
        raise HTTPException(409, "Account exists — please log in")
    u = User(id=uuid.uuid4().hex[:12], name=b.name.strip(), email=email,
             pw=hash_pw(b.password), created_at=int(time.time()*1000))
    db.add(u); db.commit(); db.refresh(u)
    return {"token": make_token(u.id), "refresh": make_token(u.id, REFRESH_TTL, "refresh"), "user": _public(u)}

@app.post("/api/auth/login/")
def login(b: Login, req: Request, db: Session = Depends(get_db)):
    rl_auth(req)
    u = db.query(User).filter(User.email == (b.email or "").strip().lower()).first()
    if not u or not verify_pw(b.password or "", u.pw):
        raise HTTPException(401, "Invalid email or password")
    return {"token": make_token(u.id), "refresh": make_token(u.id, REFRESH_TTL, "refresh"), "user": _public(u)}

@app.post("/api/auth/refresh/")
def refresh(p: dict):
    try:
        data = jwt.decode((p.get("refresh") or ""), SECRET, algorithms=["HS256"])
        if data.get("kind") != "refresh": raise ValueError()
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "Refresh expired — log in again")
    except Exception:
        raise HTTPException(401, "Invalid refresh token")
    return {"token": make_token(data["sub"])}

# ---------- resumes (ORM, ownership-verified) ----------
def _to_dict(row: ResumeRow) -> dict:
    out = dict(row.data or {})
    out.update(id=row.id, ownerId=row.owner_id, createdAt=row.created_at, updatedAt=row.updated_at)
    return out

def _owned(db: Session, rid: str, uid: str) -> ResumeRow:
    r = db.query(ResumeRow).filter(ResumeRow.id == rid, ResumeRow.owner_id == uid).first()
    if not r: raise HTTPException(404, "Resume not found")
    return r

@app.get("/api/resumes/")
def list_resumes(u: User = Depends(auth_user), db: Session = Depends(get_db), limit: int = 50, offset: int = 0):
    limit = max(1, min(limit, 100)); offset = max(0, offset)
    rows = (db.query(ResumeRow).filter(ResumeRow.owner_id == u.id)
            .order_by(ResumeRow.updated_at.desc()).limit(limit).offset(offset).all())
    total = db.query(ResumeRow).filter(ResumeRow.owner_id == u.id).count()
    return {"items": [_to_dict(r) for r in rows], "total": total, "limit": limit, "offset": offset}

@app.post("/api/resumes/")
def create_resume(payload: dict, u: User = Depends(auth_user), db: Session = Depends(get_db)):
    _enforce_size(payload, "resume")
    now = int(time.time()*1000)
    r = {"id": uuid.uuid4().hex[:12], "ownerId": u.id, "createdAt": now, "updatedAt": now}
    if isinstance(payload, dict): r.update(payload)
    r["id"] = r.get("id") or uuid.uuid4().hex[:12]; r["ownerId"] = u.id
    row = ResumeRow(id=r["id"], owner_id=u.id, data=r, created_at=r.get("createdAt", now), updated_at=now)
    db.add(row); db.commit(); db.refresh(row)
    return _to_dict(row)

@app.get("/api/resumes/{rid}/")
def get_resume(rid: str, u: User = Depends(auth_user), db: Session = Depends(get_db)):
    return _to_dict(_owned(db, rid, u.id))

@app.patch("/api/resumes/{rid}/")
def update_resume(rid: str, payload: dict, u: User = Depends(auth_user), db: Session = Depends(get_db)):
    _enforce_size(payload, "resume")
    row = _owned(db, rid, u.id)
    r = _to_dict(row)
    if isinstance(payload, dict):
        payload.pop("ownerId", None); payload.pop("id", None); r.update(payload)
    now = int(time.time()*1000); r["updatedAt"] = now
    row.data = r; row.updated_at = now
    db.add(row); db.commit(); db.refresh(row)
    return _to_dict(row)

@app.delete("/api/resumes/{rid}/")
def delete_resume(rid: str, u: User = Depends(auth_user), db: Session = Depends(get_db)):
    row = _owned(db, rid, u.id)
    db.delete(row); db.commit(); return {"ok": True}

@app.post("/api/resumes/{rid}/duplicate/")
def duplicate(rid: str, u: User = Depends(auth_user), db: Session = Depends(get_db)):
    src = _to_dict(_owned(db, rid, u.id))
    c = copy.deepcopy(src); now = int(time.time()*1000)
    c["id"] = uuid.uuid4().hex[:12]
    c["name"] = (src.get("name", "Resume") + " (Copy)")[:80]
    c["createdAt"] = c["updatedAt"] = now
    row = ResumeRow(id=c["id"], owner_id=u.id, data=c, created_at=now, updated_at=now)
    db.add(row); db.commit(); db.refresh(row)
    return _to_dict(row)

# ---------- server-side export (HTML + TXT always; PDF if weasyprint installed) ----------
def _contact(p: dict):
    return " | ".join([x for x in [p.get("email",""), p.get("phone",""), p.get("location","")] if x])

def _resume_html(r: dict) -> str:
    p = r.get("personal", {})
    def esc(s): return (str(s or "").replace("&","&amp;").replace("<","&lt;").replace(">","&gt;"))
    exp = "".join(f"<div><b>{esc(e.get('jobTitle'))}</b> — {esc(e.get('company'))}<br/>{'<br/>'.join(esc(b) for b in (e.get('bullets') or []) if b)}</div><br/>" for e in (r.get("experience") or []))
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>{esc(r.get('name','Resume'))}</title>
<style>@page{{size:A4;margin:18mm}}body{{font-family:Georgia,serif;color:#000;max-width:700px;margin:0 auto}}</style></head>
<body><h1>{esc(p.get('fullName'))}</h1><div>{esc(p.get('title'))}</div><div>{esc(_contact(p))}</div><hr/>
<h3>SUMMARY</h3><p>{esc(r.get('summary'))}</p><h3>EXPERIENCE</h3>{exp or '<p>—</p>'}</body></html>"""

def _resume_txt(r: dict) -> str:
    p = r.get("personal", {})
    lines = [p.get("fullName",""), p.get("title",""), _contact(p), "", "SUMMARY", r.get("summary",""), ""]
    for e in (r.get("experience") or []):
        lines.append(f"{e.get('jobTitle','')} — {e.get('company','')}")
        lines += [f"- {b}" for b in (e.get("bullets") or []) if b]
        lines.append("")
    return "\n".join(lines).strip() + "\n"

def _export(rid: str, u: User, db: Session, fmt: str):
    r = _to_dict(_owned(db, rid, u.id))
    fmt = (fmt or "html").lower()
    if fmt == "txt": return PlainTextResponse(_resume_txt(r), headers={"Content-Disposition": f"attachment; filename={rid}.txt"})
    if fmt == "pdf":
        try:
            from weasyprint import HTML as WHTML  # optional dep
            pdf = WHTML(string=_resume_html(r)).write_pdf()
            return Response(pdf, media_type="application/pdf", headers={"Content-Disposition": f"attachment; filename={rid}.pdf"})
        except Exception as e:
            raise HTTPException(501, f"PDF engine not installed ({e}). Use format=html or install weasyprint.")
    return HTMLResponse(_resume_html(r))

@app.get("/api/resumes/{rid}/export/")
def export_get(rid: str, format: str = "html", u: User = Depends(auth_user), db: Session = Depends(get_db)):
    return _export(rid, u, db, format)

@app.post("/api/resumes/{rid}/export/")
def export_post(rid: str, p: dict = None, u: User = Depends(auth_user), db: Session = Depends(get_db)):
    fmt = ((p or {}).get("format") or "html")
    return _export(rid, u, db, fmt)

# ---------- AI (real LLM when key set, else guarded rule-based fallback) ----------
GROQ_KEY = os.getenv("GROQ_API_KEY", "")
OPENAI_KEY = os.getenv("OPENAI_API_KEY", "")
AI_PROVIDER = "groq" if GROQ_KEY else ("openai" if OPENAI_KEY else "rule-based")
AI_MODEL = os.getenv("MONO_AI_MODEL", "llama-3.1-8b-instant")  # Groq free model
SYSTEM_GUARD = ("You are a resume writing expert. REWRITE the text to be stronger and more professional. "
                "Never invent employers, dates, metrics, qualifications or skills not mentioned. "
                "Keep all facts identical but IMPROVE the wording significantly: use strong action verbs, "
                "make it concise, and ensure it sounds professional. Always produce a meaningfully different version.")
SYSTEM_BUILDER = ("You are an expert resume writer. Generate realistic, tailored resume content "
                  "for the given role and level. Use professional language. Never invent specific "
                  "company names unless provided. Use bullet points that start with strong verbs.")

def _rule_polish(t: str, mode: str = "polish") -> str:
    t = " ".join((t or "").split())
    if not t: return t
    orig = t
    repl = [
        (r"\bworked on\b", "Developed"), (r"\bhelped\b", "Collaborated to deliver"),
        (r"\bresponsible for\b", "Led"), (r"\bmade\b", "Built"),
        (r"\bdid\b", "Executed"), (r"\bhandled\b", "Managed"),
        (r"\bwas involved in\b", "Contributed to"), (r"\bused\b", "Leveraged"),
        (r"\bmanaged\b", "Directed"), (r"\bcreated\b", "Designed and built"),
        (r"\bwas in charge of\b", "Spearheaded"), (r"\bworked with\b", "Partnered with"),
        (r"\bassisted\b", "Supported"), (r"\bparticipated in\b", "Contributed to"),
        (r"\bwas responsible for\b", "Led"), (r"\bdid work on\b", "Developed"),
        (r"\bcompleted\b", "Executed"), (r"\bperformed\b", "Executed"),
        (r"\bset up\b", "Established"), (r"\bcame up with\b", "Developed"),
        (r"\bran\b", "Operated"), (r"\bput together\b", "Assembled"),
        (r"\bfigure out\b", "Resolved"), (r"\bmake sure\b", "Ensure"),
    ]
    for pat, rep in repl:
        t = re.sub(pat, rep, t, flags=re.I)
    t = re.sub(r"\bvery\b", "", t, flags=re.I)
    t = re.sub(r"\bjust\b", "", t, flags=re.I)
    t = re.sub(r"\breally\b", "", t, flags=re.I)
    t = re.sub(r"\bstuff\b", "initiatives", t, flags=re.I)
    t = re.sub(r"\bthings\b", "deliverables", t, flags=re.I)
    t = re.sub(r"\ba lot of\b", "significant", t, flags=re.I)
    t = re.sub(r"\bvarious\b", "multiple", t, flags=re.I)
    t = re.sub(r"\butilized\b", "Leveraged", t, flags=re.I)
    if mode == "concise":
        t = re.sub(r"\bin order to\b", "to", t, flags=re.I)
        t = re.sub(r"\bdue to the fact that\b", "because", t, flags=re.I)
        w = t.split()
        if len(w) > 22: t = " ".join(w[:22]) + "."
    if mode == "pro":
        ACTION = ["Developed", "Designed", "Engineered", "Led", "Delivered", "Built",
                  "Launched", "Optimized", "Automated", "Streamlined", "Implemented", "Drove", "Improved", "Shipped"]
        if not any(t.startswith(a) for a in ACTION):
            for weak in ["I ", "my ", "the ", "a "]:
                if t.lower().startswith(weak.lower()):
                    t = "Delivered " + t[len(weak):]
                    break
    t = re.sub(r"\bi\b", "I", t)
    t = re.sub(r"\s{2,}", " ", t).strip()
    if t and not t[0].isupper(): t = t[0].upper() + t[1:]
    if t and t[-1] not in ".!?": t += "."
    # If nothing changed, force a restructuring
    if t == orig:
        base = re.sub(r"[.!?]+$", "", t).strip()
        if not any(base.startswith(a) for a in ["Developed","Designed","Led","Built","Delivered","Engineered","Implemented","Optimized","Shipped","Automated","Streamlined","Drove","Improved","Launched"]):
            base = "Successfully delivered " + base[0].lower() + base[1:]
        t = base + "."
    return t

def _llm(prompt: str, system: str = "", max_tokens: int = 400) -> Optional[str]:
    sys_msg = system or SYSTEM_GUARD
    # Try Groq first (free)
    if GROQ_KEY:
        try:
            from groq import Groq
            c = Groq(api_key=GROQ_KEY)
            r = c.chat.completions.create(model=AI_MODEL, messages=[
                {"role": "system", "content": sys_msg},
                {"role": "user", "content": prompt[:4000]}],
                temperature=0.4, max_tokens=max_tokens)
            return (r.choices[0].message.content or "").strip()
        except Exception:
            pass
    # Fallback to OpenAI
    if OPENAI_KEY:
        try:
            from openai import OpenAI
            c = OpenAI(api_key=OPENAI_KEY)
            r = c.chat.completions.create(model="gpt-4o-mini", messages=[
                {"role": "system", "content": sys_msg},
                {"role": "user", "content": prompt[:4000]}],
                temperature=0.4, max_tokens=max_tokens)
            return (r.choices[0].message.content or "").strip()
        except Exception:
            pass
    return None

@app.post("/api/ai/improve-summary/")
def improve_summary(p: dict, req: Request):
    rl_ai(req)
    t = ((p or {}).get("text") or "").strip()[:MAX_AI_TEXT]
    if not t: raise HTTPException(400, "Empty text")
    mode = str((p or {}).get("mode", "polish"))[:20]
    out = _llm(f"Polish this resume summary ({mode}), keep all facts identical:\n{t}")
    return {"improved": out or _rule_polish(t, mode), "provider": "llm" if out else "rule-based"}

@app.post("/api/ai/improve-bullet/")
def improve_bullet(p: dict, req: Request):
    rl_ai(req)
    t = ((p or {}).get("text") or "").strip()[:MAX_AI_TEXT]
    if not t: raise HTTPException(400, "Empty text")
    out = _llm(f"Rewrite this resume bullet to start with a strong action verb, keep facts identical, no invented numbers:\n{t}")
    return {"improved": out or _rule_polish(t, "pro"), "provider": "llm" if out else "rule-based"}

@app.post("/api/ai/analyze-resume/")
def analyze_resume(p: dict, req: Request):
    rl_ai(req)
    r = (p or {}).get("resume") or {}
    score = 50
    if r.get("summary"): score += 10
    if r.get("experience"): score += 15
    if r.get("education"): score += 10
    if any("@" in str(x) for x in [((r.get("personal") or {}).get("email"))]): score += 5
    return {"score": min(100, score), "note": "Estimate only — real ATS systems vary."}

@app.post("/api/ai/analyze-job/")
def analyze_job(p: dict, req: Request):
    rl_ai(req)
    _enforce_size((p or {}).get("resume") or {}, "resume")
    jd = str((p or {}).get("jd") or "")[:20000].lower()
    resume_text = json.dumps((p or {}).get("resume") or {}).lower()
    lex = ["react","typescript","javascript","next.js","node","python","django","sql","postgresql",
           "aws","docker","kubernetes","ci/cd","git","figma","tailwind","rest","graphql","jest",
           "agile","scrum","leadership","communication"]
    req_skills = sorted({k for k in lex if k in jd})
    matched = [k for k in req_skills if k in resume_text]
    missing = [k for k in req_skills if k not in resume_text]
    score = round(len(matched)/len(req_skills)*100) if req_skills else 0
    return {"score": score, "matched": matched, "missing": missing}

@app.post("/api/ai/build-resume/")
def build_resume(p: dict, req: Request):
    rl_ai(req)
    p = p or {}
    role = str(p.get("role") or "Professional")[:80]
    level = str(p.get("experience_level") or "mid")[:20]
    skills = [str(s)[:40] for s in (p.get("skills") or [])][:10]
    education = p.get("education") or {}
    personal = p.get("personal") or {}
    user_exp = p.get("experience") or []
    user_projs = p.get("projects") or []
    user_certs = p.get("certifications") or []
    user_langs = p.get("languages") or []

    level_label = {"junior":"Junior","mid":"Mid-Level","senior":"Senior","lead":"Lead"}.get(level,"Mid-Level")
    years_map = {"junior":"0–2","mid":"3–5","senior":"5–8","lead":"8+"}
    years = years_map.get(level, "3–5")

    # Build LLM prompt with user's real data
    exp_str = ""
    for e in user_exp[:5]:
        bullets = "\n".join(f"  - {b}" for b in (e.get("bullets") or [])[:5])
        exp_str += f"\n{e.get('title','')} at {e.get('company','')} ({e.get('start','')}–{e.get('end','present')})\n{bullets}\n"
    proj_str = "\n".join(f"- {pr.get('name','')}: {pr.get('description','')} [{pr.get('tech','')}]" for pr in user_projs[:5])
    cert_str = "\n".join(f"- {c.get('name','')} ({c.get('org','')}, {c.get('start','')})" for c in user_certs[:5])
    lang_str = ", ".join(f"{l.get('lang','')} ({l.get('level','')})" for l in user_langs[:6])
    edu_str = f"\nEducation: {education.get('degree','')} in {education.get('field','')} from {education.get('school','')} ({education.get('startYear','')}–{education.get('endYear','')})" if education else ""

    prompt = (f"You are building a professional resume for a {level_label} {role}.\n\n"
              f"CONTACT: {personal.get('name','')} | {personal.get('email','')} | {personal.get('phone','')} | {personal.get('location','')}\n"
              f"LINKEDIN: {personal.get('linkedin','')} | GITHUB: {personal.get('github','')} | WEBSITE: {personal.get('website','')}\n"
              f"SKILLS: {', '.join(skills)}\n{edu_str}\n"
              f"WORK EXPERIENCE:\n{exp_str}\n"
              f"PROJECTS:\n{proj_str}\n"
              f"CERTIFICATIONS:\n{cert_str}\n"
              f"LANGUAGES: {lang_str}\n\n"
              f"Write a 2-3 sentence professional summary based on the above.\n"
              f"Polish each bullet point to start with a strong action verb and include quantified impact.\n"
              f"Return ONLY valid JSON with keys: summary (string), experience (array of objects with jobTitle, company, start, end, current (bool), description (string), bullets (array of strings)), "
              f"projects (array with name, description, tech (array), url), certifications (array with name, org, start), languages (array with lang, level).\n"
              f"Keep all real facts. Do NOT invent employers, dates, or metrics not provided above.")
    llm_out = _llm(prompt, system=SYSTEM_BUILDER, max_tokens=1200)

    provider = "rule-based"
    if llm_out:
        try:
            import json as _json
            match = re.search(r'\{[\s\S]*\}', llm_out)
            if match:
                data = _json.loads(match.group())
                provider = AI_PROVIDER
                # Normalize experience
                for e in data.get("experience", []):
                    e.setdefault("id", "")
                    e.setdefault("location", "")
                    e.setdefault("current", False)
                    e.setdefault("bullets", [])
                result = {
                    "personal": {"fullName": personal.get("name",""), "title": f"{level_label} {role}",
                                 "email": personal.get("email",""), "phone": personal.get("phone",""),
                                 "location": personal.get("location",""), "website": personal.get("website",""),
                                 "linkedin": personal.get("linkedin",""), "github": personal.get("github",""),
                                 "portfolio": "", "photo": ""},
                    "summary": data.get("summary", ""),
                    "experience": data.get("experience", [])[:5],
                    "skills": data.get("skills", {"technical": skills[:5], "tools": skills[5:8], "soft": ["Communication","Teamwork","Problem Solving"], "languages": []}),
                    "education": [{"institution": str(education.get("school",""))[:80], "degree": str(education.get("degree",""))[:30], "field": str(education.get("field",""))[:60], "start": str(education.get("startYear",""))[:10], "end": str(education.get("endYear",""))[:10]}] if education else [],
                    "projects": data.get("projects", [])[:5],
                    "certifications": data.get("certifications", [])[:5],
                    "languages": data.get("languages", user_langs),
                    "awards": [], "volunteering": [], "interests": "", "references": ""
                }
                return {"resume": result, "provider": provider}
        except Exception:
            pass

    # Rule-based fallback: use user's real data directly
    summary = (f"{level_label} {role} with {years} of experience"
               f"{', proficient in ' + ', '.join(skills[:4]) if skills else ''}."
               f"{' Proven track record delivering measurable results.' if any(e.get('bullets') for e in user_exp) else ''}")

    experience = []
    for e in user_exp[:5]:
        experience.append({
            "id": "", "jobTitle": e.get("title",""), "company": e.get("company",""),
            "location": "", "start": e.get("start",""), "end": e.get("end",""),
            "current": not e.get("end"), "description": "",
            "bullets": [b for b in (e.get("bullets") or []) if b][:5]
        })

    projects = [{"id":"", "name":pr.get("name",""), "description":pr.get("description",""),
                 "tech":[t.strip() for t in pr.get("tech","").split(",") if t.strip()],
                 "url":pr.get("url",""), "github":"", "date":""} for pr in user_projs[:5]]
    certs = [{"id":"", "name":c.get("name",""), "org":c.get("org",""),
              "start":c.get("start",""), "end":"", "credId":"", "url":""} for c in user_certs[:5]]

    edu = {}
    if education:
        edu = {"institution": str(education.get("school","University"))[:80], "degree": str(education.get("degree","B.Sc."))[:30],
               "field": str(education.get("field",role))[:60], "start": str(education.get("startYear",""))[:10], "end": str(education.get("endYear",""))[:10]}

    result = {
        "personal": {"fullName": personal.get("name",""), "title": f"{level_label} {role}",
                     "email": personal.get("email",""), "phone": personal.get("phone",""),
                     "location": personal.get("location",""), "website": personal.get("website",""),
                     "linkedin": personal.get("linkedin",""), "github": personal.get("github",""),
                     "portfolio": "", "photo": ""},
        "summary": summary,
        "experience": experience,
        "skills": {"technical": skills[:5], "tools": skills[5:8], "soft": ["Communication","Teamwork","Problem Solving"], "languages": []},
        "education": [edu] if edu else [],
        "projects": projects, "certifications": certs, "languages": user_langs,
        "awards": [], "volunteering": [], "interests": "", "references": ""
    }
    return {"resume": result, "provider": provider}


@app.get("/api/health")
def health(db: Session = Depends(get_db)):
    backend = "postgres" if DATABASE_URL.startswith("postgresql") else "sqlite"
    try:
        db.execute(__import__("sqlalchemy").text("SELECT 1"))
        db_ok = True
    except Exception:
        db_ok = False
    if not db_ok:
        raise HTTPException(503, "Database unreachable")
    return {"ok": True, "ai": AI_PROVIDER, "db": backend, "env": ENV}

@app.get("/")
def root(): return {"ok": True, "docs": "/docs"}

if __name__ == "__main__":
    import uvicorn
    init_db()
    uvicorn.run(app, host="127.0.0.1", port=8000)
