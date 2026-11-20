# AFRICAN ARK COLLEGE OF MANAGEMENT SCIENCES Management System

ACMS is a single-page HTML/CSS/vanilla JavaScript frontend and a Python HTTP API. The Vercel deployment serves the frontend and runs the API as a Python Function. The API stores accounts, sessions, records, and uploaded documents in Supabase PostgreSQL.

## Local run

Requires Python 3.10 or newer. Install the API dependency and start the server:

```powershell
python -m pip install -r requirements.txt
python server.py
```

Set `DATABASE_URL` in the shell before starting to use the Supabase database locally. Without it, the local server uses volatile in-memory data for tests and development. Open <http://127.0.0.1:8000>. On an empty database, the API creates its schema and reference data. Set `NUU_ADMIN_PASSWORD` before first startup to choose the initial admin password; it must be at least 10 characters. Otherwise, the generated initial password is printed to the server console.

```powershell
$env:DATABASE_URL = "<private Supabase PostgreSQL connection URI>"
$env:NUU_ADMIN_PASSWORD = "<initial admin password>"
python server.py
```

Keep the connection URI out of source control and browser code. The local server listens on `127.0.0.1` by default; `NUU_PORT` and `NUU_HOST` can override the port and host.

## Vercel + Supabase deployment

1. In Supabase, open **Project Settings → Database → Connect** and copy a PostgreSQL connection URI. For Vercel Functions, use Supabase's transaction pooler URI when available and require SSL (`sslmode=require`).
2. In Vercel project settings, add these environment variables for **Production** (and Preview if desired):
   - `DATABASE_URL`: the private Supabase URI.
   - `NUU_ADMIN_PASSWORD`: a strong initial password (at least 10 characters).
   - `NUU_COOKIE_SECURE`: `1`.
   - `NUU_ALLOWED_ORIGINS`: the exact public Vercel origin, such as `https://your-project.vercel.app`; add custom domains as comma-separated origins.
3. Keep the Vercel project root at the repository root and deploy. `vercel.json` builds the static frontend and routes `/api/*` to the Python Function in `api/router.py`. `requirements.txt` installs the PostgreSQL driver.
4. Visit `/api/health` on the deployed site and confirm it reports `"storage":"postgresql"` and `"persistent":true`. Then sign in as `admin`, change the temporary password, create a test record, and verify it remains after a new deployment.

The API creates `app_tables`, `sessions`, `uploads`, `application_documents`, and `student_sequences` in the Supabase database when it starts. Application records are currently stored as JSON rows in `app_tables`; session and uploaded-file data use separate PostgreSQL tables. The backend enforces role and student-scope checks. Do not put Supabase database credentials or service keys in `project.html`.

The previous Render service is no longer used by this repository, but removing its configuration does not stop a service that is already deployed. After the Vercel deployment passes the checks above, delete the old API service in the Render dashboard.

## Data migration and security

Existing data in `data/nuu.sqlite3` is not imported automatically and was left untouched. Back up any data you need and migrate it separately before relying on Supabase.

The backend hashes passwords, uses server-side eight-hour sessions, rejects cross-origin mutations, checks operations by role, and scopes student records. Login attempts are not throttled. Uploaded submissions and admission credentials are stored in Supabase, with an 8 MB per-file/application limit. Enable Supabase backups/PITR appropriate to your project, restrict database credentials to the server environment, and rotate any credentials that have been exposed.

Admissions, student records, courses, registrations, results, manual fee-payment recording, hostels, announcements, messages, assignments, the library catalogue, notifications, settings, and audit records are supported. Finance staff can record payments; no external payment gateway is configured.
