# MONO Studio — backend (FastAPI + SQLAlchemy, runs in 2 minutes)

Storage is SQLAlchemy: SQLite file by default, Postgres in prod.
Old `db.json` imports once via `migrate_json_to_sql.py`.

## 1. Run

```powershell
cd backend
py -3 -m pip install -r requirements.txt
copy .env.example .env   # optional, defaults work for dev
py -3 main.py
```

Open http://localhost:8000/docs for interactive API docs.
`GET /api/health` returns `{"db":"sqlite"|"postgres"}`.

## 1b. Postgres migration

```powershell
# 1. Start Postgres (Docker example):
# docker run -d --name mono-pg -e POSTGRES_PASSWORD=secret -e POSTGRES_DB=mono -p 5432:5432 postgres:16
# 2. Point backend at it:
# setx DATABASE_URL "postgresql+psycopg2://postgres:secret@localhost:5432/mono"
# 3. Install + init + import old JSON (if any):
py -3 -m pip install -r requirements.txt
py -3 main.py        # creates tables via init_db(), Ctrl+C after boot
py -3 migrate_json_to_sql.py
```

Tables: `users(id, name, email UNIQUE, pw, created_at)`,
`resumes(id, owner_id FK, data JSONB/JSON, created_at, updated_at)` + index on `(owner_id, updated_at)`.
Resumes keep the full frontend dict in `data` so no frontend rewrite is needed.
Passwords now use stdlib PBKDF2 (200k iterations); old prototype bcrypt hashes
import as-is but won't verify — re-register those dev accounts once.
For schema evolution later, add Alembic (`pip install alembic; alembic init alembic`).

## 2. Connect frontend (already wired)

Frontend is local-first with backend-optional sync (`index.html: API_BASE`, `api()`, `checkBackend()`):

- Nav badge shows `API · Connected` vs `Offline (local mode)` via `GET /api/health`.
- Auth mirrors to backend non-blocking (`mirrorAuthToBackend()`), token in `mono_api_token`.
- Autosave pushes via `PATCH /api/resumes/{id}/` debounced (`queueBackendPush()`).
- AI tries backend first (`aiViaBackend()`), falls back to rule-based.
- Export menu → Server export uses `GET /api/resumes/{id}/export/`.
- Profile modal → Backend API lets you set `mono_api_base` (empty = offline).

## 3. Endpoints

| Method | Route | Auth |
|---|---|---|
| POST | /api/auth/register/ | no (20/min, 8+ char pw) |
| POST | /api/auth/login/ | no (20/min) |
| POST | /api/auth/refresh/ | refresh token |
| GET | /api/resumes/ | Bearer JWT |
| POST | /api/resumes/ | Bearer JWT |
| GET | /api/resumes/{id}/ | Bearer JWT |
| PATCH | /api/resumes/{id}/ | Bearer JWT |
| DELETE | /api/resumes/{id}/ | Bearer JWT |
| POST | /api/resumes/{id}/duplicate/ | Bearer JWT |
| GET/POST | /api/resumes/{id}/export/?format=html\|txt\|pdf | Bearer JWT (pdf needs weasyprint) |
| POST | /api/ai/improve-summary/ | 30/min, LLM or rule-based |
| POST | /api/ai/improve-bullet/ | 30/min, LLM or rule-based |
| POST | /api/ai/analyze-resume/ | 30/min |
| POST | /api/ai/analyze-job/ | 30/min |

Env: `MONO_JWT_SECRET`, `MONO_DB_PATH`, `MONO_CORS_ORIGINS`, `MONO_ACCESS_TTL`,
`MONO_REFRESH_TTL`, `DATABASE_URL` (Postgres-ready hook), `OPENAI_API_KEY` + `MONO_AI_MODEL` (real AI).

AI guardrail: system prompt forbids inventing employers, dates, metrics, skills.
Without `OPENAI_API_KEY`, `provider: rule-based` fallback is used — same guarantee as frontend.

## 4. Production checklist

- [x] `MONO_ENV=prod` fail-fasts on default/short `MONO_JWT_SECRET` and `CORS *`; docs disabled in prod; security headers on all responses
- [x] SQLAlchemy store (SQLite dev, Postgres prod via `DATABASE_URL`); `migrate_json_to_sql.py` imports old `db.json`
- [x] Rate limiting on auth + AI (in-memory; use Redis/slowapi for multi-worker); 500KB resume cap, AI text caps
- [x] Paginated `GET /api/resumes/?limit&offset` (`{items,total}` — frontend accepts both shapes); DB-backed `/api/health`
- [x] `backup.py` dump/restore (hashes excluded; restores force password reset); `Dockerfile`, `docker-compose.yml`, `render.yaml`, CI smoke test
- [ ] Set `MONO_CORS_ORIGINS` to your domain, `OPENAI_API_KEY` for real AI, provider backups/snapshots, Redis limits for multi-worker
- [x] Server export HTML/TXT live; install `weasyprint` for `format=pdf`
