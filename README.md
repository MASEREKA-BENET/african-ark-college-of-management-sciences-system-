# AFRICAN ARK COLLEGE OF MANAGEMENT SCIENCES Management System

ACMS runs as a single-page HTML/CSS/vanilla JavaScript frontend and a Python HTTP API. Local development uses Python's standard-library HTTP server and SQLite. Production can use the same API with Neon PostgreSQL by setting `DATABASE_URL`; `requirements.txt` installs the PostgreSQL driver. Accounts, sessions, role checks, student-specific access, admissions, and uploaded documents are handled by the API.

## Local run

Requires Python 3.10 or newer. From this folder:

```powershell
python server.py
```

Open <http://127.0.0.1:8000>. The server creates `data/nuu.sqlite3` and seeds reference data. On a new database it prints a randomly generated, one-time admin password in the server console. Sign in as `admin` and change that temporary password immediately; new passwords must be at least 10 characters. User passwords are stored as salted PBKDF2 hashes. Existing plaintext demo passwords are migrated to hashes and marked for change.

To provide the initial admin password yourself, set `NUU_ADMIN_PASSWORD` before the first start. It must be at least 10 characters. It does not reset an existing account.

Useful settings:

```powershell
$env:NUU_PORT = "8000"
$env:NUU_DB_PATH = "D:\NUU-data\nuu.sqlite3"
$env:NUU_BACKUP_DIR = "E:\NUU-backups"
python server.py
```

The app binds to `127.0.0.1` by default. Keep it loopback-only when using the HTTPS proxy below.

## HTTPS deployment with Caddy

The included `Caddyfile` is an optional TLS reverse-proxy configuration. Install Caddy separately, point a DNS name at the host, and allow inbound TCP 80 and 443 so Caddy can obtain and renew its certificate. In one PowerShell window, start NUU:

```powershell
$env:NUU_HOST = "127.0.0.1"
$env:NUU_COOKIE_SECURE = "1"
python server.py
```

In a second PowerShell window, set the public DNS name and run Caddy from this folder:

```powershell
$env:NUU_DOMAIN = "ums.example.org"
caddy run --config .\Caddyfile --adapter caddyfile
```

Replace `ums.example.org` with your actual domain. Caddy terminates HTTPS and forwards to the loopback-only Python listener. NUU sets secure, HttpOnly, SameSite session cookies in this mode. Keep the Python port off the public firewall. For an always-on host, run both processes under dedicated, least-privilege service accounts and configure them to start on boot.

## Render + Neon + Vercel deployment

The deployment is split into three services: Vercel serves the static frontend, Vercel rewrites `/api/*` requests to the Python service on Render, and the Render API stores data in Neon PostgreSQL. The repository includes `render.yaml`, `vercel.json`, and a small Vercel static build script.

1. **Create Neon PostgreSQL.** Create a Neon project and copy its PostgreSQL connection string (include `sslmode=require`). Keep the connection string private.
2. **Deploy the API to Render.** In Render, create a Blueprint from this repository and provide the requested `DATABASE_URL` and `NUU_ALLOWED_ORIGINS` values. The Blueprint runs `python server.py`, binds to `0.0.0.0`, uses Render's `PORT`, enables secure cookies, and generates an initial `NUU_ADMIN_PASSWORD`.
3. **Deploy the frontend to Vercel.** Import the same repository with the repository root as the project root and the `Other` framework preset. `vercel.json` builds the static `dist` folder and proxies API paths to `https://acms-api.onrender.com`. If Render assigns the API a different URL, update the rewrite destination in `vercel.json` and redeploy Vercel.
4. **Set the allowed frontend origin.** In Render, set `NUU_ALLOWED_ORIGINS` to the exact Vercel origin, for example `https://your-project.vercel.app`. Add any custom domain as another comma-separated origin. Redeploy the API after changing it.
5. **Complete the first sign-in.** Read the generated `NUU_ADMIN_PASSWORD` from the Render environment settings and sign in as `admin`. Change the temporary password after signing in.

`DATABASE_URL` switches the API from local SQLite to PostgreSQL. A fresh Neon database is initialized automatically. Existing records in a local `data/nuu.sqlite3` file are **not** transferred automatically. Use one Render API instance with this application. For production backups, use Neon backup/PITR facilities; `backup.py` is for local SQLite databases.

## Backups and restore

Create and verify an online SQLite backup (including committed WAL data):

```powershell
python backup.py backup --retention-days 30
python backup.py verify .\data\backups\nuu-YYYYMMDDTHHMMSSffffffZ.sqlite3
```

By default, backups and a rotating log are written to `data\backups`. **The backup files themselves are not encrypted.** For real records, target a separate BitLocker-protected volume or another encrypted backup target. Run a daily 2:00 AM task for the current Windows account with the actual database and backup paths:

```powershell
.\install-backup-task.ps1 -DatabasePath "D:\NUU-data\nuu.sqlite3" -BackupDirectory "E:\NUU-encrypted-backups" -RequireBitLocker
```

This registers a least-privilege Windows Scheduled Task; its results are logged to `backup.log` beside the backups. Remove the task with `remove-backup-task.ps1`. Verify backups periodically and replicate them to an encrypted off-site destination; a backup on the same disk is not disaster recovery. A network backup destination must be accessible to the scheduled-task account.

To restore, stop the NUU server first, then run:

```powershell
$env:NUU_DB_PATH = "D:\NUU-data\nuu.sqlite3"
$env:NUU_BACKUP_DIR = "E:\NUU-encrypted-backups"
python backup.py restore "E:\NUU-encrypted-backups\nuu-YYYYMMDDTHHMMSSffffffZ.sqlite3" --confirm
```

The restore command verifies the source and creates a pre-restore safety copy before replacing the live database. Start NUU again after restore.

## Security and current scope

The backend hashes passwords, uses server-side eight-hour sessions, rejects cross-origin mutation requests, validates data operations by role, and scopes students to their own records. Login attempts are not throttled or locked out. Assignment submissions are stored in SQLite, limited to 8 MB per file, and downloadable only by the student or the lecturer responsible for that assignment. Persisted text is sanitized because the legacy frontend renders some values through HTML templates.

Admissions accept academic credential uploads (PDF, DOC/DOCX, JPG, or PNG; 8 MB total per application). Admins and registrars can securely download the documents, record eligibility decisions and notes, recommend an alternative programme, and admit eligible applicants into the reviewed programme. Admissions, student records, courses, registrations, results, manual fee-payment recording, hostels, announcements, messages, assignments, the library catalogue, notifications, settings, and audit records are retained. Finance staff can record payments; **no external payment gateway is configured**. Connecting one requires the institution's chosen provider and merchant credentials.

Before processing real college records, review the final domain/proxy setup, exercise a full backup restoration, protect database and backup volumes with host-level access controls, and monitor disk space and backup logs. Do not expose the Python development listener directly to the internet.
