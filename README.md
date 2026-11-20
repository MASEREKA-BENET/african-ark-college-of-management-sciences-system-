# AFRICAN ARK COLLEGE OF MANAGEMENT SCIENCES Management System

ACMS is a single-page HTML/CSS/vanilla JavaScript frontend and a Python HTTP API. The Vercel deployment serves the frontend and runs the API as a Python Function. The API stores accounts, sessions, records, and uploaded documents in Neon PostgreSQL.

## Local run

Requires Python 3.10 or newer. Copy `.env.example` to `.env`, then paste the Neon connection string into `DATABASE_URL`:

```powershell
Copy-Item .env.example .env
npm install
node deploy/build-vercel.mjs
python -m pip install -r requirements.txt
python server.py
```

Put the full Neon PostgreSQL connection string in `.env`, including `sslmode=require` as supplied by Neon. `NEON_AUTH_BASE_URL` and `NEON_AUTH_JWKS_URL` are added by `neon deploy` / `neon env pull`; these are also required in Vercel's server environment. Restart the server after changing `.env`. The local server listens on <http://127.0.0.1:8000> by default; `NUU_PORT` and `NUU_HOST` can override the port and host. Without `DATABASE_URL`, local development and tests use volatile in-memory data.

`.env` is ignored by Git and must never be committed or pasted into chat. It is for local development only; Vercel does not receive it.

## Vercel + Neon deployment

1. Copy the PostgreSQL connection string from the Neon dashboard. Use Neon's pooled connection string for serverless deployments when available.
2. In Vercel project settings, add these environment variables for **Production** (and Preview if desired):
   - `DATABASE_URL`: the Neon connection string.
   - `NUU_COOKIE_SECURE`: `1`.
   - `NUU_ALLOWED_ORIGINS`: the exact public Vercel origin, such as `https://your-project.vercel.app`; add custom domains as comma-separated origins.
   - `NEON_AUTH_BASE_URL` and `NEON_AUTH_JWKS_URL`: copy the values from the local `.env` after `neon deploy` or `neon env pull`.
3. Keep the Vercel project root at the repository root and deploy. `vercel.json` builds the static frontend and routes `/api/*` to the Python Function in `api/router.py`. `requirements.txt` installs the PostgreSQL driver and local `.env` loader.
4. Add the deployed Vercel origin as a trusted domain in Neon Auth. Visit `/api/health` and confirm it reports `"storage":"postgresql"` and `"persistent":true`. Sign in with an email that has an active application role, then verify records persist after a new deployment.

The API creates `app_tables`, `sessions`, `uploads`, `application_documents`, and `student_sequences` in Neon when it starts. Application records are currently stored as JSON rows in `app_tables`; session and uploaded-file data use separate PostgreSQL tables. The backend enforces role and student-scope checks. Do not put database credentials in `project.html` or commit them to Git.

The previous Render service is no longer used by this repository, but removing its configuration does not stop a service that is already deployed. After the Vercel deployment passes the checks above, delete the old API service in the Render dashboard.

## Data migration and security

Existing data in `data/nuu.sqlite3` is not imported automatically and was left untouched. Back up any data you need and migrate it separately before relying on Neon.

Neon Managed Better Auth handles email/password signup, sign-in, password changes, and sign-out. The API verifies Neon JWTs before issuing its short-lived, HTTP-only application session, then matches verified Neon email addresses to active application-role records. Signup alone does not grant a portal role. The API rejects cross-origin mutations, checks operations by role, and scopes student records. Uploaded submissions and admission credentials are stored in Neon, with an 8 MB per-file/application limit. Enable Neon backups appropriate to your project, restrict database credentials to the server environment, and rotate any credentials that have been exposed.

Admissions, student records, courses, registrations, results, manual fee-payment recording, hostels, announcements, messages, assignments, the library catalogue, notifications, settings, and audit records are supported. Finance staff can record payments; no external payment gateway is configured.
