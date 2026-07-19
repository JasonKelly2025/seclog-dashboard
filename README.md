# SecLog Dashboard

A full-stack security log analysis dashboard. Upload raw CSV / JSON / NDJSON logs, parse them into a normalized searchable table, and automatically calculate a **Severity Score** (0–100) for every event based on threat indicators.

## Stack

- **Frontend:** Next.js 15 (App Router) + React 19 + Tailwind CSS 4
- **Backend:** FastAPI + SQLAlchemy + SQLite

## Severity scoring

Each parsed log entry is scored by combining triggered indicators:

| Indicator | Points |
| --- | --- |
| Failed login / access denied | +25 |
| Known bad IP (demo blocklist + Tor exit ranges) | +45 |
| Privilege escalation activity (sudo/root/admin grants) | +30 |
| Suspicious keywords (malware, SQL injection, exfiltration, C2…) | +35 |
| Off-hours activity (11pm–5am) | +10 |
| Repeated failures from one IP in the batch (≥5 / ≥10) | +15 / +25 |
| Password spraying (one IP, ≥3 usernames) | +20 |

Scores are capped at 100 and mapped to labels: **Critical** (80+), **High** (60+), **Medium** (40+), **Low** (20+), **Info** (<20).

## Getting started

### Backend

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate     # Windows (source .venv/bin/activate on macOS/Linux)
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8010
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

Open http://localhost:3000. The Next.js dev server proxies `/api/*` to the FastAPI backend on port 8010, so no CORS or env configuration is needed.

> Note: port 8010 is used instead of the usual 8000 because binding to 8000 is blocked on some Windows machines.

### Try it

Sample log files live in `backend/sample_logs/`:

- `auth_events.csv` — authentication logs including a brute-force burst from a known bad IP
- `firewall_events.json` — firewall/IDS events with port scans and a C2 alert

Drag either file onto the upload zone and watch the table populate with scored events.

## Parser

The parser accepts generic CSV, JSON arrays, wrapped JSON (`{"logs": [...]}`), and NDJSON. Common field aliases (`src_ip`, `@timestamp`, `msg`, `result`, …) are mapped onto a normalized schema: timestamp, source IP, username, event type, status, message. If no IP field exists, one is scraped from the message text. Unmapped fields are preserved in the raw payload.

## Deployment (Vercel + Render)

The app deploys as two services that auto-update on every `git push` to `main`:

1. **Backend on Render** — the included `render.yaml` blueprint defines the FastAPI service. In the Render dashboard choose *New → Blueprint*, pick this repo, and deploy. Note the service URL (e.g. `https://seclog-dashboard-api.onrender.com`).
2. **Frontend on Vercel** — import the repo in Vercel, set the **Root Directory** to `frontend`, and add an environment variable `BACKEND_URL` pointing at the Render URL. The Next.js server proxies all `/api/*` calls to it, so no CORS changes are needed.

> The free Render tier has an ephemeral disk: uploaded logs are lost when the service restarts or redeploys. Re-upload the sample files, or switch to hosted Postgres for persistence.

## API

| Method | Route | Description |
| --- | --- | --- |
| POST | `/api/upload` | Multipart file upload; parses, scores, and stores entries |
| GET | `/api/logs` | Search/filter/sort/paginate entries (`q`, `severity`, `min_score`, `sort_by`, `page`…) |
| GET | `/api/stats` | Severity breakdown, riskiest IPs and accounts |
| DELETE | `/api/logs` | Clear all entries (requires `X-Admin-Key` header when `ADMIN_KEY` is set) |

## Admin key

Set an `ADMIN_KEY` environment variable on the backend (Render dashboard → the service → Environment) to protect the "Clear all" action. When set, deleting logs requires entering that key in the UI prompt. When unset (local development), clearing stays open.
