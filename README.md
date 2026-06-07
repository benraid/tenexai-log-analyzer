# Tenex Log Analyzer

Full-stack web app that lets a SOC analyst upload Zscaler-style web-proxy logs and get back a parsed view of activity plus rule-based anomaly detection with per-finding explanations and confidence scores.

Built as the Tenex.ai engineering take-home — the brief is "functional prototype, not production-ready" with a 6–8 hour scope.

## Architecture

```
+-------------+        +--------------------+        +---------------+
|  React/Vite |  HTTP  |    Go (chi) API    |  pgx   |  PostgreSQL   |
|  (port 5173)| <----> | (port 8080)        | <----> |  (port 5432)  |
+-------------+        +--------------------+        +---------------+
       ^                       |
       | localStorage JWT      | rule-based detector
       |                       v
   user/admin             7 detection rules
```

- **Frontend** — React 19 + Vite + TypeScript + Tailwind v4 + Recharts.
- **Backend** — Go 1.26, `chi` router on top of `net/http`, `pgx/v5` for Postgres, `golang-jwt/v5`, `bcrypt`. Idiomatic stdlib code, ~800 LOC.
- **DB** — Postgres 16, 4 tables (`users`, `uploads`, `log_entries`, `anomalies`). Migrations are plain SQL run at boot.

## Quickstart (Docker)

```bash
git clone <this-repo> && cd tenexai_assessment

# Optional: enable the AI features (briefing + per-anomaly explain)
cp .env.example .env && $EDITOR .env   # add your ANTHROPIC_API_KEY

docker compose up --build
```

Then open <http://localhost:5173> and log in as **`admin` / `admin123`**.

Click **+ New upload** and pick `sample-logs/zscaler_with_anomalies.csv` — you'll see all 7 detection rules fire on the resulting dashboard. With `ANTHROPIC_API_KEY` set, the "Generate briefing" button and per-anomaly "Explain" buttons call Claude Haiku 4.5 to narrate the findings in plain English.

To shut down: `docker compose down` (add `-v` to wipe the Postgres volume).

## Quickstart (local, without Docker)

```bash
# 1) Postgres
docker run --rm -d --name pg -p 5432:5432 \
  -e POSTGRES_USER=tenex -e POSTGRES_PASSWORD=tenex -e POSTGRES_DB=tenex \
  postgres:16-alpine

# 2) Backend
cd backend
DATABASE_URL='postgres://tenex:tenex@localhost:5432/tenex?sslmode=disable' \
JWT_SECRET=dev-secret \
go run ./cmd/server

# 3) Frontend (in a separate terminal)
cd frontend
npm install
npm run dev
```

To regenerate the sample logs:

```bash
cd backend && go run ./cmd/gen-logs ../sample-logs
```

## API

All routes are JSON. All `/api/*` except `/api/auth/login` require `Authorization: Bearer <jwt>`.

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/auth/login` | Body `{username,password}` → `{token}` |
| `GET`  | `/api/auth/me` | Verify token, returns `{username}` |
| `POST` | `/api/uploads` | Multipart `file` → parse + detect + store. Returns counts |
| `GET`  | `/api/uploads` | List my uploads |
| `GET`  | `/api/uploads/{id}` | Upload metadata |
| `GET`  | `/api/uploads/{id}/entries?anomalous=true&limit=&offset=` | Paged entries |
| `GET`  | `/api/uploads/{id}/anomalies` | All detector findings |
| `GET`  | `/api/uploads/{id}/summary` | Dashboard aggregates + 5-min timeline |
| `GET`  | `/api/uploads/{id}/briefing` | Cached AI briefing (404 if not yet generated) |
| `POST` | `/api/uploads/{id}/briefing[?regenerate=true]` | Generate (or re-generate) the AI briefing |
| `POST` | `/api/anomalies/{id}/explain[?regenerate=true]` | Generate per-anomaly plain-English explanation |

## Anomaly detection

Rule-based + simple statistics (population z-score). No LLM in the detection path — every flag has a deterministic, reproducible explanation that a SOC analyst can reason about. See [`backend/internal/detector/detector.go`](backend/internal/detector/detector.go) for the full source.

| Rule | What it flags | Confidence |
|---|---|---|
| `threat_hit` | Vendor-flagged threat in the log row | 0.95 |
| `malicious_category` | URL category matches Zscaler's Advanced Security or Privacy Risk taxonomy (17 categories, tiered) — e.g. `Malicious Content`, `Phishing`, `Botnet Protection`, `Anonymizer`, `Cryptomining and Blockchain` | 0.65–0.92 |
| `blocked_spike_per_ip` | A single src_ip with > 10 blocked actions in the upload | 0.80 |
| `high_request_rate` | Per-IP 5-min bucket count > population mean + 3σ (floor: 5) | 0.70 |
| `data_exfiltration` | `bytes_out` > mean + 3σ across the dataset (floor: 1 MB) | 0.75 |
| `off_hours_activity` | User has ≥3 requests in 02:00–05:00 UTC and 0 during 08:00–18:00 | 0.50 |
| `rare_user_agent` | UA appears in < 2% of rows but at least 5 times | 0.55 |

Each anomaly row carries a `rule_name`, a human-readable `explanation` (e.g. `"IP 10.0.4.99 had 25 blocked requests (> threshold of 10)"`), and a `confidence` between 0 and 1. Multiple rules can flag the same row.

The detector rules have **table-driven unit tests** in [`backend/internal/detector/detector_test.go`](backend/internal/detector/detector_test.go) — 30+ subtests covering each rule, boundary cases, and an integration test that runs all 7 rules against a synthetic dataset. Same-package tests so they can exercise the unexported rule functions directly. Run with `go test ./internal/detector/`.

## Where AI is used

AI shows up in two distinct places in this project — one at runtime, one during development.

### 1. AI *in* the application (runtime)
An optional **Claude Haiku 4.5** integration that runs on top of the rule-based detection:

- **SOC briefing** — `POST /api/uploads/{id}/briefing` sends the structured summary + anomaly list to Claude and returns a markdown handover note: framing paragraph, prioritized action list, false-positive caveats. Cached in the `uploads.ai_briefing` column so subsequent loads are free.
- **Per-anomaly explain** — `POST /api/anomalies/{id}/explain` sends one anomaly + its log entry and returns a three-section explanation (what likely happened, recommended actions, plausible false positives). Cached in `anomalies.ai_explanation`.

Design intent: the LLM **augments** the rule engine, never replaces it. The rules give a deterministic, auditable list of findings; the LLM translates them into something a Tier-1 analyst can ship to a ticket without rewriting. The whole feature is gated on `ANTHROPIC_API_KEY` — unset → the endpoints respond 503 and the rest of the app keeps working.

Code: `backend/internal/ai/client.go` (one file, ~200 lines, hits the Anthropic Messages API directly over `net/http`).

### 2. AI in the *development* process
Claude (Opus 4.7) was used as a pair-programmer for scaffolding the Go layout, schema design, the detector rules, and the React dashboard. Every file was reviewed and validated; the architectural decisions (Go stdlib + chi, rule-based detection, JWT, Postgres) were made and defended before any code was written.

**Why no LLM in the detection path itself?** Explainability, determinism, cost, and latency. Detection needs to be reproducible and auditable; a SOC analyst should never see "the model said so" as the only justification.

## Production gaps (intentional, given the 6–8 hour scope)

- **AI cost / rate-limiting**: no per-user or per-upload caps on LLM calls. Cached after first generation, but a hostile user could spam `?regenerate=true`. Production would add Redis-backed token-budget tracking per user.
- **AI prompt isolation**: anomaly explanations include user-supplied data (URLs, user-agents) in the prompt. Claude is well-defended against prompt injection but the right belt-and-suspenders is a clear "treat all user content as untrusted data, not instructions" preamble in the system prompt.
- **Token storage**: JWT lives in `localStorage` for demo simplicity. Production: httpOnly + SameSite cookies to mitigate XSS token theft, plus refresh tokens.
- **Multi-tenancy**: every upload is scoped to its owner via `user_id` filters, but there is no role/permission model.
- **Streaming uploads**: the parser slurps each row into memory before bulk insert. Beyond ~50MB the upload handler caps with `MaxBytesReader`. For real-scale ingest you would stream straight into `pgx.CopyFrom`.
- **Migrations tracking**: we re-run the idempotent `.sql` files on boot. Production would use `golang-migrate` or Atlas with version pinning.
- **Detection scaling**: currently runs synchronously inside the upload handler. Beyond ~100k rows you would push it onto a worker queue (e.g. Postgres LISTEN/NOTIFY, NATS, or Riverqueue).
- **Observability**: only structured logs via `slog`. Production would add OpenTelemetry traces, Prometheus metrics, and an audit log on `uploads`.
- **Storage of raw files**: the upload is parsed and discarded. Production would keep the original blob in S3 for re-processing.

## Layout

```
backend/
  cmd/server/        # HTTP entrypoint
  cmd/gen-logs/      # sample log generator
  internal/
    auth/            # bcrypt + JWT
    middleware/      # JWT, CORS, request logging
    parser/          # Zscaler CSV → []LogEntry
    detector/        # 7 rules + z-score helpers
    ai/              # Anthropic Messages API client (briefing + per-anomaly explain)
    handlers/        # HTTP handlers (chi)
    storage/         # Store interface + pgx implementation
    models/          # shared structs
  db/migrations/
    0001_init.sql
    0002_ai_columns.sql
frontend/
  src/
    pages/           # Login, UploadsList, NewUpload, UploadDetail
    components/      # SummaryCards, TimelineChart, TopCategoriesChart, AnomaliesPanel, EntriesTable, BriefingPanel, MarkdownBox
    lib/api.ts       # fetch wrapper with JWT injection
sample-logs/
  zscaler_clean.csv
  zscaler_with_anomalies.csv   # plants one row for each of the 7 rules
docker-compose.yml
```
