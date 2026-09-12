# MONO Studio — Resume Builder

![ci](https://github.com/Scodos1/CV-Builder/actions/workflows/ci.yml/badge.svg)

A black-and-white professional CV studio: live A4 preview, 4 ATS-friendly templates,
AI writing coach, job-match analysis, and one-click PDF export.

- **Frontend:** single-file `index.html` (no build step) — landing, auth, dashboard,
  3-pane builder (Sections → Preview → Design), AI drawer, ATS + JD analyzers.
- **Backend (optional):** FastAPI + SQLAlchemy (`backend/`) — JWT auth, ownership-verified
  resume CRUD, server-side export, guarded AI endpoints. Runs local-first on
  `localStorage` when the API is offline.

## Quickstart

### Frontend only (fastest)

Just open `index.html` in a browser — or serve it:

```powershell
# any static server, e.g.
py -3 -m http.server 5500
# -> http://localhost:5500/index.html
```

Sign up (local account), or use the demo login on the auth page.

### Full stack

```powershell
cd backend
py -3 -m pip install -r requirements.txt
copy .env.example .env   # optional, defaults work for dev
py -3 main.py            # -> http://localhost:8000/docs
```

The frontend auto-detects the API at `http://localhost:8000` (nav badge flips to
`API · Connected`). Override with `?api=https://your-api` or Profile → Backend API.
Auth mirrors to the backend; autosave syncs; AI tries the backend first with local fallback.

### Postgres (prod)

```powershell
# docker run -d --name mono-pg -e POSTGRES_PASSWORD=secret -e POSTGRES_DB=mono -p 5432:5432 postgres:16
# setx DATABASE_URL "postgresql+psycopg2://postgres:secret@localhost:5432/mono"
py -3 main.py        # creates tables, Ctrl+C after boot
py -3 migrate_json_to_sql.py   # one-time import of old db.json, if any
```

## Project layout

```
index.html                  # entire frontend (landing/auth/dashboard/builder)
backend/
  main.py                   # FastAPI app: auth, resumes, export, AI
  db.py                     # SQLAlchemy models (SQLite dev, Postgres prod)
  migrate_json_to_sql.py    # one-time db.json -> SQL import
  backup.py                 # dump/restore (hashes excluded by design)
  requirements.txt
  .env.example
Dockerfile                  # prod API image (2 uvicorn workers)
docker-compose.yml          # API + Postgres 16
render.yaml                 # Render blueprint
.github/workflows/ci.yml    # backend smoke test + frontend node --check
```

## API

| Method | Route | Auth |
|---|---|---|
| POST | `/api/auth/register/` | no (20/min, 8–128 char pw) |
| POST | `/api/auth/login/` | no (20/min) |
| POST | `/api/auth/refresh/` | refresh token |
| GET | `/api/resumes/?limit&offset` | Bearer JWT → `{items,total}` |
| POST | `/api/resumes/` | Bearer JWT |
| GET / PATCH / DELETE | `/api/resumes/{id}/` | Bearer JWT (owner only) |
| POST | `/api/resumes/{id}/duplicate/` | Bearer JWT |
| GET/POST | `/api/resumes/{id}/export/?format=html\|txt\|pdf` | Bearer JWT (pdf needs `weasyprint`) |
| POST | `/api/ai/improve-summary/`, `/api/ai/improve-bullet/` | 30/min, LLM or rule-based |
| POST | `/api/ai/analyze-resume/`, `/api/ai/analyze-job/` | 30/min |
| GET | `/api/health` | `{ok, db, ai, env}` |

AI guardrail: wording refinement only — never invents employers, dates, metrics or
skills. Without `OPENAI_API_KEY`, a rule-based fallback is used.

## Production notes

- `MONO_ENV=prod` fail-fasts on a default/short `MONO_JWT_SECRET` and `CORS *`,
  disables `/docs`, and adds security headers + payload caps. See `backend/README.md`
  for the full checklist (secrets, CORS domain, backups, Redis limits for multi-worker).
- `docker-compose.yml` runs API + Postgres locally; `render.yaml` targets Render.
- Backups: `py -3 backup.py` (run on a schedule in prod; restores force password reset).
