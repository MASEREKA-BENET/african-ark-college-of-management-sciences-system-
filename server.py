"""NUU application server with volatile in-memory data, password auth and RBAC."""

from __future__ import annotations

import hashlib
import hmac
import html
import io
import json
import logging
import os
import re
import base64
import binascii
import mimetypes
import secrets
import threading
import time
import uuid
import zipfile
from xml.sax.saxutils import escape as xml_escape
from datetime import datetime, timezone
from contextlib import contextmanager
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import URLError
from urllib.parse import parse_qsl, unquote, urlencode, urlparse, urlsplit

import jwt
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent
load_dotenv(ROOT / ".env")
DATABASE_URL = os.environ.get("DATABASE_URL")
NEON_AUTH_BASE_URL = os.environ.get("NEON_AUTH_BASE_URL", "").rstrip("/")
NEON_AUTH_JWKS_URL = os.environ.get("NEON_AUTH_JWKS_URL", "")
NEON_AUTH_JWKS_CLIENT = jwt.PyJWKClient(NEON_AUTH_JWKS_URL, timeout=5) if NEON_AUTH_JWKS_URL else None
POSTGRES_SCHEMA_READY = False
POSTGRES_SCHEMA_LOCK = threading.Lock()
MAX_BODY = 12 * 1024 * 1024
MAX_UPLOAD = 8 * 1024 * 1024
SESSION_SECONDS = 8 * 60 * 60
PBKDF2_ROUNDS = 310_000
COOKIE_SECURE = os.environ.get("NUU_COOKIE_SECURE", "0") == "1"
ALLOWED_ORIGINS = {origin.strip().rstrip("/").casefold() for origin in os.environ.get("NUU_ALLOWED_ORIGINS", "").split(",") if origin.strip()}
DUMMY_PASSWORD_HASH = None


def restore_vercel_api_path(request_path: str) -> str:
    parsed = urlsplit(request_path)
    if parsed.path != "/api/router":
        return request_path
    params = parse_qsl(parsed.query, keep_blank_values=True)
    forwarded_path = next((value for key, value in params if key == "nuu_path"), None)
    if forwarded_path is None:
        return request_path
    route = "/" + forwarded_path.lstrip("/")
    remaining = urlencode([(key, value) for key, value in params if key != "nuu_path"], doseq=True)
    return "/api" + route + ("?" + remaining if remaining else "")


class MemoryStore:
    def __init__(self):
        self.tables = {}
        self.sessions = {}
        self.uploads = {}
        self.application_documents = {}
        self.student_sequences = {}

    def clear(self):
        self.tables.clear()
        self.sessions.clear()
        self.uploads.clear()
        self.application_documents.clear()
        self.student_sequences.clear()

    def table_names(self):
        return set(self.tables)

    def read_table(self, name):
        return json.loads(json.dumps(self.tables.get(name, []), ensure_ascii=False))

    def write_table(self, name, encoded):
        self.tables[name] = json.loads(encoded)

    def get_session(self, token_hash):
        return self.sessions.get(token_hash)

    def put_session(self, token_hash, user_id, expires):
        self.sessions[token_hash] = {"user_id":user_id,"expires":expires}

    def delete_session(self, token_hash):
        self.sessions.pop(token_hash,None)

    def delete_expired_sessions(self, now):
        self.sessions = {key: session for key, session in self.sessions.items() if session["expires"] > now}

    def delete_sessions_for_user(self, user_id):
        self.sessions = {
            token: session for token, session in self.sessions.items()
            if session["user_id"] != user_id
        }

    def get_upload(self, upload_id):
        return self.uploads.get(upload_id)

    def create_upload(self, owner_id, assignment_id, filename, media_type, content, created_at):
        upload_id = max(self.uploads, default=0) + 1
        self.uploads[upload_id] = {
            "id": upload_id, "owner_id": owner_id, "assignment_id": assignment_id,
            "filename": filename, "media_type": media_type, "content": content,
            "created_at": created_at,
        }
        return upload_id

    def get_application_document(self, document_id):
        return self.application_documents.get(document_id)

    def create_application_document(self, application_id, filename, media_type, content, created_at):
        document_id = max(self.application_documents, default=0) + 1
        self.application_documents[document_id] = {
            "id": document_id, "application_id": application_id, "filename": filename,
            "media_type": media_type, "content": content, "created_at": created_at,
        }
        return document_id

    def get_student_sequence(self, department_id):
        return self.student_sequences.get(department_id,0)

    def set_student_sequence(self, department_id, number):
        self.student_sequences[department_id]=number

    def delete_student_sequence(self, department_id):
        self.student_sequences.pop(department_id,None)

    def delete_application_documents(self, application_id):
        self.application_documents={
            key:document for key,document in self.application_documents.items()
            if document["application_id"]!=application_id
        }

    def begin_write(self):
        return None

    def check(self):
        return None


class PostgreSQLStore:
    def __init__(self, connection):
        self.connection=connection

    def ensure_schema(self):
        statements=(
            "CREATE TABLE IF NOT EXISTS app_tables (name TEXT PRIMARY KEY, rows TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, user_id BIGINT NOT NULL, expires BIGINT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS uploads (id BIGSERIAL PRIMARY KEY, owner_id BIGINT NOT NULL, assignment_id BIGINT NOT NULL, filename TEXT NOT NULL, media_type TEXT NOT NULL, content BYTEA NOT NULL, created_at TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS application_documents (id BIGSERIAL PRIMARY KEY, application_id BIGINT NOT NULL, filename TEXT NOT NULL, media_type TEXT NOT NULL, content BYTEA NOT NULL, created_at TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS student_sequences (department_id BIGINT PRIMARY KEY, last_number BIGINT NOT NULL)",
        )
        for statement in statements:
            self.connection.execute(statement)

    def table_names(self):
        return {row["name"] for row in self.connection.execute("SELECT name FROM app_tables")}

    def read_table(self, name):
        row=self.connection.execute("SELECT rows FROM app_tables WHERE name=%s",(name,)).fetchone()
        return json.loads(row["rows"]) if row else []

    def write_table(self, name, encoded):
        self.connection.execute(
            "INSERT INTO app_tables(name,rows) VALUES(%s,%s) ON CONFLICT(name) DO UPDATE SET rows=excluded.rows",
            (name,encoded),
        )

    def begin_write(self):
        self.connection.execute("LOCK TABLE app_tables IN EXCLUSIVE MODE")

    def check(self):
        self.connection.execute("SELECT 1")

    def get_session(self, token_hash):
        return self.connection.execute(
            "SELECT user_id,expires FROM sessions WHERE token_hash=%s",(token_hash,)
        ).fetchone()

    def put_session(self, token_hash, user_id, expires):
        self.connection.execute(
            "INSERT INTO sessions(token_hash,user_id,expires) VALUES(%s,%s,%s) "
            "ON CONFLICT(token_hash) DO UPDATE SET user_id=excluded.user_id,expires=excluded.expires",
            (token_hash,user_id,expires),
        )

    def delete_session(self, token_hash):
        self.connection.execute("DELETE FROM sessions WHERE token_hash=%s",(token_hash,))

    def delete_expired_sessions(self, now):
        self.connection.execute("DELETE FROM sessions WHERE expires<=%s",(now,))

    def delete_sessions_for_user(self, user_id):
        self.connection.execute("DELETE FROM sessions WHERE user_id=%s",(user_id,))

    def get_upload(self, upload_id):
        return self.connection.execute(
            "SELECT filename,media_type,content FROM uploads WHERE id=%s",(upload_id,)
        ).fetchone()

    def create_upload(self, owner_id, assignment_id, filename, media_type, content, created_at):
        row=self.connection.execute(
            "INSERT INTO uploads(owner_id,assignment_id,filename,media_type,content,created_at) "
            "VALUES(%s,%s,%s,%s,%s,%s) RETURNING id",
            (owner_id,assignment_id,filename,media_type,content,created_at),
        ).fetchone()
        return row["id"]

    def get_application_document(self, document_id):
        return self.connection.execute(
            "SELECT application_id,filename,media_type,content FROM application_documents WHERE id=%s",
            (document_id,),
        ).fetchone()

    def create_application_document(self, application_id, filename, media_type, content, created_at):
        row=self.connection.execute(
            "INSERT INTO application_documents(application_id,filename,media_type,content,created_at) "
            "VALUES(%s,%s,%s,%s,%s) RETURNING id",
            (application_id,filename,media_type,content,created_at),
        ).fetchone()
        return row["id"]

    def get_student_sequence(self, department_id):
        row=self.connection.execute(
            "SELECT last_number FROM student_sequences WHERE department_id=%s",(department_id,)
        ).fetchone()
        return row["last_number"] if row else 0

    def set_student_sequence(self, department_id, number):
        self.connection.execute(
            "INSERT INTO student_sequences(department_id,last_number) VALUES(%s,%s) "
            "ON CONFLICT(department_id) DO UPDATE SET last_number=excluded.last_number",
            (department_id,number),
        )

    def delete_student_sequence(self, department_id):
        self.connection.execute("DELETE FROM student_sequences WHERE department_id=%s",(department_id,))

    def delete_application_documents(self, application_id):
        self.connection.execute("DELETE FROM application_documents WHERE application_id=%s",(application_id,))


STORE = MemoryStore()
STORE_LOCK = threading.RLock()


TABLES = (
    "roles departments programs users courses hostels settings audit_logs announcements notifications "
    "registrations results fee_payments assignments hostel_allocations students messages books applications submissions"
).split()
PUBLIC_TABLES = {"roles", "departments", "programs", "courses"}
READ_ROLES = {
    "admin": set(TABLES),
    "student": {"roles", "departments", "programs", "courses", "users", "students", "registrations", "results", "fee_payments", "assignments", "submissions", "hostels", "hostel_allocations", "announcements", "messages", "notifications", "books"},
    "lecturer": {"roles", "departments", "programs", "courses", "users", "students", "registrations", "results", "assignments", "submissions", "announcements", "messages"},
    "registrar": {"roles", "departments", "programs", "courses", "settings", "users", "students", "applications", "registrations", "results", "announcements", "messages"},
    "finance": {"roles", "departments", "users", "students", "fee_payments", "announcements", "messages"},
    "hostel": {"roles", "departments", "users", "students", "hostels", "hostel_allocations", "announcements", "messages"},
    "comms": {"roles", "departments", "users", "announcements", "messages", "notifications"},
    "librarian": {"roles", "departments", "users", "students", "books", "announcements"},
}
WRITE_ROLES = {
    "admin": set(TABLES),
    "student": {"registrations", "messages"},
    "lecturer": {"results", "assignments", "messages"},
    "registrar": {"students", "users", "applications", "registrations", "results", "courses", "announcements"},
    "finance": {"fee_payments"},
    "hostel": {"hostel_allocations"},
    "comms": {"announcements", "messages", "notifications"},
    "librarian": {"books"},
}


def password_hash(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ROUNDS)
    return f"pbkdf2_sha256${PBKDF2_ROUNDS}${salt.hex()}${digest.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, rounds, salt, expected = encoded.split("$")
        if algorithm != "pbkdf2_sha256":
            return False
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(rounds)).hex()
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


DUMMY_PASSWORD_HASH = password_hash(secrets.token_urlsafe(24))
LOGGER = logging.getLogger(__name__)


def verify_neon_auth_token(token):
    if not NEON_AUTH_BASE_URL or not NEON_AUTH_JWKS_CLIENT:
        return None
    auth_origin = urlparse(NEON_AUTH_BASE_URL)
    if auth_origin.scheme != "https" or not auth_origin.netloc:
        raise RuntimeError("NEON_AUTH_BASE_URL must be an HTTPS URL.")
    expected_origin = f"{auth_origin.scheme}://{auth_origin.netloc}"
    try:
        signing_key = NEON_AUTH_JWKS_CLIENT.get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=["EdDSA"],
            issuer=expected_origin,
            audience=expected_origin,
            options={"require": ["exp", "iss", "aud", "sub"]},
        )
    except (jwt.PyJWTError, URLError, TimeoutError, OSError) as error:
        LOGGER.warning("Neon Auth token verification failed (%s).", type(error).__name__)
        return None
    if claims.get("role") != "authenticated":
        return None
    return claims


@contextmanager
def connect():
    if DATABASE_URL:
        try:
            import psycopg
            from psycopg.rows import dict_row
        except ImportError as error:
            raise RuntimeError("Install the PostgreSQL driver from requirements.txt.") from error
        with psycopg.connect(DATABASE_URL,row_factory=dict_row,prepare_threshold=None) as connection:
            db=PostgreSQLStore(connection)
            global POSTGRES_SCHEMA_READY
            if not POSTGRES_SCHEMA_READY:
                with POSTGRES_SCHEMA_LOCK:
                    if not POSTGRES_SCHEMA_READY:
                        db.ensure_schema()
                        connection.commit()
                        POSTGRES_SCHEMA_READY=True
            yield db
    else:
        with STORE_LOCK:
            yield STORE


def reset_store():
    with STORE_LOCK:
        STORE.clear()


def read_table(db, name):
    return db.read_table(name)


def write_table(db, name, rows):
    def clean(value):
        if isinstance(value,str):
            # Existing views render records into HTML templates. Remove markup
            # delimiters even when supplied as encoded entities.
            for _ in range(3):
                decoded=html.unescape(value)
                if decoded==value:
                    break
                value=decoded
            return "".join(ch for ch in value if ch not in '<>"\x00' and (ch >= " " or ch in "\n\r\t"))
        if isinstance(value,list):
            return [clean(item) for item in value]
        if isinstance(value,dict):
            return {key:clean(item) for key,item in value.items()}
        return value
    rows=clean(rows)
    encoded = json.dumps(rows, ensure_ascii=False, separators=(",", ":"))
    db.write_table(name,encoded)


def seed_database(bootstrap_password=None):
    departments = [
        {"id":1,"name":"Computer Science & IT","code":"CS"},{"id":2,"name":"Business Administration","code":"BBA"},
        {"id":3,"name":"Engineering & Technology","code":"ENG"},{"id":4,"name":"Medicine & Health Sciences","code":"MED"},
        {"id":5,"name":"Law & Jurisprudence","code":"LAW"},{"id":6,"name":"Education","code":"EDU"},{"id":7,"name":"Agriculture","code":"AGR"},
    ]
    roles = [
        {"id":1,"name":"System Administrator","slug":"admin","color":"#fee2e2","tc":"#991b1b"},
        {"id":2,"name":"Student","slug":"student","color":"#d1f0e0","tc":"#065f46"},
        {"id":3,"name":"Lecturer","slug":"lecturer","color":"#dbeafe","tc":"#1e40af"},
        {"id":4,"name":"Registrar","slug":"registrar","color":"#ffedd5","tc":"#9a3412"},
        {"id":5,"name":"Finance Officer","slug":"finance","color":"#fef3c7","tc":"#92400e"},
        {"id":6,"name":"Hostel Manager","slug":"hostel","color":"#ccfbf1","tc":"#0f766e"},
        {"id":7,"name":"Communication Officer","slug":"comms","color":"#ede9fe","tc":"#5b21b6"},
        {"id":8,"name":"Librarian","slug":"librarian","color":"#fce7f3","tc":"#9d174d"},
    ]
    courses = [
        {"id":1,"code":"CS1101","name":"Introduction to Programming","dept_id":1,"year":1,"semester":1,"credits":4,"max":60,"status":"active"},
        {"id":2,"code":"CS1102","name":"Computer Fundamentals","dept_id":1,"year":1,"semester":1,"credits":3,"max":60,"status":"active"},
        {"id":3,"code":"CS2201","name":"Data Structures & Algorithms","dept_id":1,"year":2,"semester":1,"credits":4,"max":50,"status":"active"},
        {"id":4,"code":"BBA1101","name":"Principles of Management","dept_id":2,"year":1,"semester":1,"credits":3,"max":80,"status":"active"},
        {"id":5,"code":"BBA1102","name":"Business Mathematics","dept_id":2,"year":1,"semester":1,"credits":3,"max":80,"status":"active"},
        {"id":6,"code":"ENG1101","name":"Engineering Mathematics I","dept_id":3,"year":1,"semester":1,"credits":4,"max":45,"status":"active"},
        {"id":7,"code":"MED1101","name":"Anatomy & Physiology","dept_id":4,"year":1,"semester":1,"credits":5,"max":40,"status":"active"},
    ]
    programs = [
        {"id":1,"dept_id":1,"name":"BSc Computer Science"},{"id":2,"dept_id":1,"name":"BSc Information Technology"},
        {"id":3,"dept_id":2,"name":"Bachelor of Business Administration"},{"id":4,"dept_id":3,"name":"BSc Civil Engineering"},
        {"id":5,"dept_id":4,"name":"Bachelor of Medicine and Surgery"},{"id":6,"dept_id":5,"name":"Bachelor of Laws"},
        {"id":7,"dept_id":6,"name":"Bachelor of Education"},{"id":8,"dept_id":7,"name":"BSc Agriculture"},
    ]
    settings = [{"id":1,"site_name":"AFRICAN ARK COLLEGE OF MANAGEMENT SCIENCES","site_short":"ACMS","current_year":"2024/2025","current_semester":"I","email_domain":"acms.ac.ug","pass_mark":50,"dark_mode":False}]
    bootstrap_password=bootstrap_password or os.environ.get("NUU_ADMIN_PASSWORD") or secrets.token_urlsafe(20)
    now_user = {"id":1,"username":"admin","password":password_hash(bootstrap_password),"full_name":"System Administrator","email":"admin@nuu.ac.ug","role_id":1,"role_slug":"admin","department_id":None,"phone":"+256 414 000001","status":"active","must_change_pass":True}
    defaults = {
        "roles":roles,"departments":departments,"programs":programs,"courses":courses,
        "users":[now_user],"hostels":[{"id":1,"name":"Nile Hall","gender":"male","total_rooms":50,"occupied":0},{"id":2,"name":"Victoria Hall","gender":"female","total_rooms":40,"occupied":0},{"id":3,"name":"Freedom Hall","gender":"mixed","total_rooms":30,"occupied":0}],
        "settings":settings,"audit_logs":[],"announcements":[],"notifications":[],"registrations":[],"results":[],"fee_payments":[],"assignments":[],"hostel_allocations":[],"students":[],"messages":[],"books":[],"applications":[],"submissions":[],
    }
    with connect() as db:
        db.begin_write()
        existing = db.table_names()
        existing_users=read_table(db,"users") if "users" in existing else []
        created_admin=not existing_users
        if created_admin and len(bootstrap_password)<10:
            raise RuntimeError("NUU_ADMIN_PASSWORD must be at least 10 characters.")
        for name, rows in defaults.items():
            if name not in existing:
                write_table(db,name,rows)
        settings_rows = read_table(db, "settings")
        for setting in settings_rows:
            if setting.get("site_name") in {"Nexus University Uganda", "AFRICAN ARK"}:
                setting["site_name"] = "AFRICAN ARK COLLEGE OF MANAGEMENT SCIENCES"
                if setting.get("site_short") in {"NUU", "AA"}:
                    setting["site_short"] = "ACMS"
            elif setting.get("site_short") == "AA":
                setting["site_short"] = "ACMS"
            if setting.get("email_domain") == "nuu.ac.ug":
                setting["email_domain"] = "acms.ac.ug"
        write_table(db, "settings", settings_rows)
        users = read_table(db, "users")
        for user in users:
            if user.get("username") == "admin" and user.get("email") == "admin@nuu.ac.ug":
                user["email"] = "admin@acms.ac.ug"
        write_table(db, "users", users)
        if created_admin and "users" in existing:
            write_table(db,"users",[now_user])
        users=read_table(db,"users")
        migrated=False
        for user in users:
            stored=user.get("password","")
            if not stored.startswith("pbkdf2_sha256$"):
                user["password"]=password_hash(str(stored))
                user["must_change_pass"]=True
                migrated=True
        if migrated:
            write_table(db,"users",users)
        # Normalize records created by earlier browser-only builds as well as
        # the new backend, since several legacy views interpolate text in HTML.
        for name in defaults:
            write_table(db,name,read_table(db,name))
    return {"username":"admin","password":bootstrap_password} if created_admin else None


def sanitize_user(user):
    return {key: value for key, value in user.items() if key != "password"}


def department_workbook(departments, programs, courses):
    rows = [["Department", "Code", "Programs", "Courses"]]
    for department in departments:
        dept_id = department.get("id")
        rows.append([
            department.get("name", ""),
            department.get("code", ""),
            sum(1 for program in programs if program.get("dept_id") == dept_id),
            sum(1 for course in courses if course.get("dept_id") == dept_id),
        ])
    return xlsx_workbook("Departments", rows)


def xlsx_workbook(sheet_name, rows):
    def column_name(number):
        result = ""
        while number:
            number, remainder = divmod(number - 1, 26)
            result = chr(65 + remainder) + result
        return result

    sheet_rows = []
    for row_number, values in enumerate(rows, 1):
        cells = []
        for column_number, value in enumerate(values, 1):
            ref = f"{column_name(column_number)}{row_number}"
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                cells.append(f'<c r="{ref}"><v>{value}</v></c>')
            else:
                text = xml_escape(str(value if value is not None else ""), {"\"": "&quot;"})
                cells.append(f'<c r="{ref}" t="inlineStr"><is><t>{text}</t></is></c>')
        sheet_rows.append(f'<row r="{row_number}">{"".join(cells)}</row>')
    sheet = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
             '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
             f'<sheetData>{"".join(sheet_rows)}</sheetData></worksheet>')
    workbook = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
                'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
                f'<sheets><sheet name="{xml_escape(sheet_name)}" sheetId="1" r:id="rId1"/></sheets></workbook>')
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>')
        archive.writestr("_rels/.rels", '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>')
        archive.writestr("xl/workbook.xml", workbook)
        archive.writestr("xl/_rels/workbook.xml.rels", '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>')
        archive.writestr("xl/worksheets/sheet1.xml", sheet)
    return output.getvalue()


def results_workbook(results, students, users, courses, departments):
    students_by_id={student["id"]:student for student in students}
    users_by_id={user["id"]:user for user in users}
    courses_by_id={course["id"]:course for course in courses}
    departments_by_id={department["id"]:department for department in departments}
    rows=[["Student Number","Student Name","Department","Programme","Course Code","Course Name","Coursework","Exam","Total","Grade","Grade Points","Remark","Status"]]
    for result in results:
        student=students_by_id.get(result.get("student_id"),{})
        account=users_by_id.get(student.get("user_id"),{})
        course=courses_by_id.get(result.get("course_id"),{})
        department=departments_by_id.get(student.get("dept_id"),{})
        coursework=result.get("coursework",0) or 0
        exam=result.get("exam",0) or 0
        student_number=re.sub(r"^NUU(?=[0-9-])","ACMS",str(student.get("student_number", "")))
        rows.append([
            student_number,account.get("full_name", ""),department.get("name", ""),student.get("programme", ""),
            course.get("code", ""),course.get("name", ""),coursework,exam,coursework+exam,
            result.get("grade", ""),result.get("grade_points", ""),result.get("remark", ""),result.get("status", ""),
        ])
    return xlsx_workbook("Results", rows)


class Handler(BaseHTTPRequestHandler):
    server_version = "NUU/2.0"

    def respond(self, status, payload, headers=None, content_type="application/json; charset=utf-8"):
        body = payload if isinstance(payload, bytes) else json.dumps(payload, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "default-src 'self' https://fonts.googleapis.com https://fonts.gstatic.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; script-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'")
        if COOKIE_SECURE:
            self.send_header("Strict-Transport-Security", "max-age=31536000")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def read_json(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length > MAX_BODY:
                raise ValueError("Request body is too large.")
            return json.loads(self.rfile.read(length) or b"null")
        except (ValueError, json.JSONDecodeError) as error:
            raise ValueError("Invalid JSON request.") from error

    def origin_allowed(self):
        origin=self.headers.get("Origin")
        if not origin:
            return True
        parsed=urlparse(origin)
        origin_host=parsed.netloc.casefold()
        allowed=bool(parsed.scheme in {"http","https"} and parsed.netloc and parsed.path=="" and not parsed.query and not parsed.fragment and (origin_host==self.headers.get("Host","").casefold() or f"{parsed.scheme}://{origin_host}".casefold() in ALLOWED_ORIGINS))
        if not allowed:
            self.respond(403,{"error":"Cross-origin requests are not allowed."})
        return allowed

    def session_user(self, db):
        cookie = SimpleCookie(self.headers.get("Cookie", ""))
        morsel = cookie.get("nuu_session")
        if not morsel:
            return None
        token_hash = hashlib.sha256(morsel.value.encode()).hexdigest()
        session = db.get_session(token_hash)
        if not session or session["expires"] <= int(time.time()):
            return None
        return next((u for u in read_table(db, "users") if u["id"] == session["user_id"] and u.get("status") == "active"), None)

    def table_response(self, db, name, user):
        rows = read_table(db, name)
        role = user["role_slug"]
        if name not in READ_ROLES.get(role, set()):
            raise PermissionError("Your role cannot access this information.")
        if role == "student":
            student = next((s for s in read_table(db, "students") if s.get("user_id") == user["id"]), None)
            sid = student.get("id") if student else -1
            if name == "users":
                rows = [u for u in rows if u["id"] == user["id"]]
            elif name == "students":
                rows = [s for s in rows if s.get("id") == sid]
            elif name in {"registrations", "results", "fee_payments", "hostel_allocations"}:
                rows = [r for r in rows if r.get("student_id") == sid]
            elif name == "submissions":
                rows = [r for r in rows if r.get("student_id") == sid]
            elif name == "assignments":
                approved_courses={r.get("course_id") for r in read_table(db,"registrations") if r.get("student_id")==sid and r.get("status")=="approved"}
                rows=[a for a in rows if a.get("course_id") in approved_courses]
            elif name == "announcements":
                rows = [a for a in rows if a.get("status") == "published"]
            elif name == "messages":
                rows = [m for m in rows if m.get("to_all") or m.get("to_id") == user["id"] or m.get("from_id") == user["id"]]
            elif name == "notifications":
                rows = [n for n in rows if n.get("to_all") or n.get("user_id") == user["id"]]
        elif role == "lecturer":
            if name == "assignments":
                rows = [a for a in rows if a.get("created_by") == user["id"]]
            elif name == "results":
                rows = [r for r in rows if r.get("submitted_by") == user["id"]]
            elif name == "submissions":
                own_assignments={a["id"] for a in read_table(db,"assignments") if a.get("created_by")==user["id"]}
                rows = [s for s in rows if s.get("assignment_id") in own_assignments]
        elif role == "finance" and name == "students":
            users_by_id={account["id"]:account for account in read_table(db,"users")}
            rows=[student for student in rows if users_by_id.get(student.get("user_id"),{}).get("role_slug")=="student"]
        if name == "messages" and role not in {"admin","comms","student"}:
            rows=[m for m in rows if m.get("to_all") or m.get("to_id")==user["id"] or m.get("from_id")==user["id"]]
        if name == "notifications" and role not in {"admin","comms","student"}:
            rows=[n for n in rows if n.get("to_all") or n.get("user_id")==user["id"]]
        if name == "users":
            rows = [sanitize_user(row) for row in rows]
            if role in {"lecturer","hostel","librarian"}:
                rows=[{key:value for key,value in row.items() if key in {"id","username","full_name","role_slug","department_id","status"}} for row in rows]
        return rows

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/api/health":
            with connect() as db:
                db.check()
            self.respond(200, {"status":"ok","storage":"postgresql" if DATABASE_URL else "memory","persistent":bool(DATABASE_URL)})
            return
        if path == "/api/auth/config":
            if not NEON_AUTH_BASE_URL:
                self.respond(503, {"error":"Neon Auth is not configured on this server."})
                return
            self.respond(200, {"auth_url":NEON_AUTH_BASE_URL})
            return
        if path in ("/", "/project.html"):
            self.respond(200, (ROOT / "project.html").read_bytes(), content_type="text/html; charset=utf-8")
            return
        if path == "/neon-auth-client.js":
            bundle = ROOT / "dist" / "neon-auth-client.js"
            if not bundle.is_file():
                self.respond(503, {"error":"Build the Neon Auth client bundle before serving the app."})
                return
            self.respond(200, bundle.read_bytes(), content_type="text/javascript; charset=utf-8")
            return
        if unquote(path) == "/ark logo.JPG":
            logo = ROOT / "ark logo.JPG"
            if logo.is_file():
                self.respond(200, logo.read_bytes(), content_type="image/jpeg")
                return
        if path == "/api/auth/me":
            with connect() as db:
                user = self.session_user(db)
            if not user:
                self.respond(401, {"error":"Authentication required."})
            else:
                self.respond(200, {"user":sanitize_user(user)})
            return
        document_match=re.fullmatch(r"/api/applications/(\d+)/documents/(\d+)/download",path)
        if document_match:
            application_id,document_id=map(int,document_match.groups())
            with connect() as db:
                user=self.session_user(db)
                if not user:
                    self.respond(401,{"error":"Sign in to access application credentials."});return
                if user.get("must_change_pass") or user.get("role_slug") not in {"admin","registrar"}:
                    self.respond(403,{"error":"Only administrators and registrars can access application credentials."});return
                document=db.get_application_document(document_id)
                if document and document["application_id"] != application_id:
                    document=None
            if not document:
                self.respond(404,{"error":"Application credential not found."});return
            filename=re.sub(r'[\x00-\x1f\x7f"]',"",Path(document["filename"]).name)
            self.respond(200,bytes(document["content"]),{"Content-Disposition":f'attachment; filename="{filename}"'},document["media_type"])
            return
        if path == "/api/exports/departments.xlsx":
            with connect() as db:
                user = self.session_user(db)
                if not user:
                    self.respond(401, {"error":"Sign in to export the department directory."})
                    return
                if user.get("must_change_pass"):
                    self.respond(403, {"error":"Change your temporary password before exporting data."})
                    return
                if user.get("role_slug") not in {"admin", "registrar"}:
                    self.respond(403, {"error":"Your role cannot export the department directory."})
                    return
                workbook = department_workbook(read_table(db, "departments"), read_table(db, "programs"), read_table(db, "courses"))
            self.respond(200, workbook, {
                "Content-Disposition":"attachment; filename=department_directory.xlsx",
            }, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
            return
        if path == "/api/exports/results.xlsx":
            with connect() as db:
                user=self.session_user(db)
                if not user:
                    self.respond(401,{"error":"Sign in to export academic results."});return
                if user.get("must_change_pass"):
                    self.respond(403,{"error":"Change your temporary password before exporting data."});return
                if user.get("role_slug") not in {"admin","registrar"}:
                    self.respond(403,{"error":"Only administrators and academic registrars can export results."});return
                workbook=results_workbook(read_table(db,"results"),read_table(db,"students"),read_table(db,"users"),read_table(db,"courses"),read_table(db,"departments"))
            self.respond(200,workbook,{"Content-Disposition":"attachment; filename=acms_academic_results.xlsx"},"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
            return
        if path.startswith("/api/submissions/") and path.endswith("/download"):
            try:
                submission_id=int(path.removeprefix("/api/submissions/").removesuffix("/download").strip("/"))
            except ValueError:
                self.respond(404,{"error":"Submission not found."})
                return
            with connect() as db:
                user=self.session_user(db)
                submission=next((row for row in read_table(db,"submissions") if row.get("id")==submission_id),None)
                if not user:
                    self.respond(401,{"error":"Sign in to download this file."})
                    return
                student=next((s for s in read_table(db,"students") if s.get("user_id")==user["id"]),None)
                allowed=bool(submission and (user["role_slug"]=="admin" or (student and submission.get("student_id")==student["id"])))
                if submission and user["role_slug"]=="lecturer":
                    assignments=read_table(db,"assignments")
                    allowed=any(a.get("id")==submission.get("assignment_id") and a.get("created_by")==user["id"] for a in assignments)
                upload=db.get_upload(submission.get("upload_id")) if allowed else None
            if not upload:
                self.respond(404,{"error":"Submission not found."})
                return
            filename=re.sub(r"[\x00-\x1f\x7f]", "", re.split(r"[\\/]",upload["filename"])[-1]).replace('"','')
            self.respond(200,bytes(upload["content"]),{"Content-Disposition":f'attachment; filename="{filename}"','X-Content-Type-Options':'nosniff'},upload["media_type"])
            return
        if path.startswith("/api/tables/"):
            name = unquote(path.removeprefix("/api/tables/"))
            if name not in TABLES:
                self.respond(404, {"error":"Unknown data table."})
                return
            with connect() as db:
                user = self.session_user(db)
                if not user and name in PUBLIC_TABLES:
                    self.respond(200, read_table(db, name))
                    return
                if not user:
                    self.respond(401, {"error":"Sign in to access this information."})
                    return
                if user.get("must_change_pass") and name not in PUBLIC_TABLES:
                    self.respond(403,{"error":"Change your temporary password before accessing the portal."})
                    return
                try:
                    rows = self.table_response(db, name, user)
                except PermissionError as error:
                    self.respond(403, {"error":str(error)})
                    return
            self.respond(200, rows)
            return
        self.respond(404, {"error":"Not found."})

    def do_POST(self):
        if not self.origin_allowed():
            return
        path = urlparse(self.path).path
        try:
            data = self.read_json()
            if not isinstance(data, dict):
                raise ValueError("A JSON object is required.")
            if path == "/api/auth/login":
                if NEON_AUTH_BASE_URL:
                    self.respond(410, {"error":"Password sign-in is managed by Neon Auth."})
                    return
                username = str(data.get("username", "")).strip()[:128]
                password = str(data.get("password", ""))
                with connect() as db:
                    user = next((u for u in read_table(db, "users") if u.get("username", "").casefold() == username.casefold()), None)
                    password_ok=verify_password(password,user.get("password",DUMMY_PASSWORD_HASH) if user else DUMMY_PASSWORD_HASH)
                    if not user or user.get("status") != "active" or not password_ok:
                        self.respond(401, {"error":"Invalid username or password."})
                        return
                    db.begin_write()
                    token = secrets.token_urlsafe(32)
                    token_hash = hashlib.sha256(token.encode()).hexdigest()
                    now = int(time.time())
                    db.delete_expired_sessions(now)
                    db.put_session(token_hash,user["id"],now+SESSION_SECONDS)
                    user["last_login"] = datetime.now(timezone.utc).isoformat()
                    users = read_table(db,"users")
                    write_table(db,"users",[user if u["id"] == user["id"] else u for u in users])
                cookie = f"nuu_session={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={SESSION_SECONDS}" + ("; Secure" if COOKIE_SECURE else "")
                self.respond(200, {"user":sanitize_user(user)}, {"Set-Cookie":cookie})
                return
            if path == "/api/auth/exchange":
                if not NEON_AUTH_BASE_URL or not NEON_AUTH_JWKS_CLIENT:
                    self.respond(503, {"error":"Neon Auth is not fully configured on this server."})
                    return
                authorization = self.headers.get("Authorization", "")
                scheme, separator, token = authorization.partition(" ")
                if not separator or scheme.casefold() != "bearer" or not token.strip():
                    self.respond(401, {"error":"A Neon Auth token is required."})
                    return
                claims = verify_neon_auth_token(token.strip())
                if not claims:
                    self.respond(401, {"error":"The Neon Auth session is invalid or expired."})
                    return
                try:
                    neon_user_id = uuid.UUID(str(claims["sub"]))
                except (KeyError, ValueError, TypeError):
                    self.respond(401, {"error":"The Neon Auth session has an invalid user identity."})
                    return
                with connect() as db:
                    neon_user = db.connection.execute(
                        'SELECT email, "emailVerified", banned FROM neon_auth."user" WHERE id=%s',
                        (neon_user_id,),
                    ).fetchone()
                    if not neon_user or neon_user["banned"]:
                        self.respond(401, {"error":"The Neon Auth account is not active."})
                        return
                    if not neon_user["emailVerified"]:
                        self.respond(403, {"error":"Verify your email address before accessing the portal."})
                        return
                    email = str(neon_user["email"]).strip().casefold()
                    users = read_table(db, "users")
                    user = next(
                        (
                            row for row in users
                            if str(row.get("email", "")).strip().casefold() == email
                            and row.get("status") == "active"
                        ),
                        None,
                    )
                    if not user:
                        self.respond(403, {"error":"Your Neon account has no active portal role. Contact an administrator."})
                        return
                    db.begin_write()
                    now = int(time.time())
                    db.delete_expired_sessions(now)
                    app_token = secrets.token_urlsafe(32)
                    db.put_session(hashlib.sha256(app_token.encode()).hexdigest(), user["id"], now + SESSION_SECONDS)
                    user["last_login"] = datetime.now(timezone.utc).isoformat()
                    user["must_change_pass"] = False
                    user.pop("password", None)
                    write_table(
                        db,
                        "users",
                        [user if row["id"] == user["id"] else row for row in users],
                    )
                cookie = f"nuu_session={app_token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={SESSION_SECONDS}" + ("; Secure" if COOKIE_SECURE else "")
                self.respond(200, {"user":sanitize_user(user)}, {"Set-Cookie":cookie})
                return
            if path == "/api/auth/logout":
                with connect() as db:
                    cookie = SimpleCookie(self.headers.get("Cookie", ""))
                    morsel = cookie.get("nuu_session")
                    if morsel:
                        db.delete_session(hashlib.sha256(morsel.value.encode()).hexdigest())
                self.respond(200, {"ok":True}, {"Set-Cookie":"nuu_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0" + ("; Secure" if COOKIE_SECURE else "")})
                return
            if path == "/api/auth/password":
                if NEON_AUTH_BASE_URL:
                    self.respond(410, {"error":"Passwords are managed by Neon Auth. Use its password reset flow."})
                    return
                with connect() as db:
                    user = self.session_user(db)
                    if not user:
                        self.respond(401, {"error":"Sign in to change your password."})
                        return
                    current = str(data.get("current_password", ""))
                    new = str(data.get("new_password", ""))
                    if not verify_password(current, user["password"]):
                        self.respond(400, {"error":"Current password is incorrect."})
                        return
                    if len(new) < 10 or len(new) > 256:
                        self.respond(400, {"error":"New password must be 10–256 characters."})
                        return
                    db.begin_write()
                    users = read_table(db, "users")
                    for row in users:
                        if row["id"] == user["id"]:
                            row["password"] = password_hash(new)
                            row["must_change_pass"] = False
                    write_table(db, "users", users)
                self.respond(200, {"ok":True})
                return
            if path == "/api/audit":
                with connect() as db:
                    user = self.session_user(db)
                    if not user:
                        self.respond(401,{"error":"Sign in before recording an action."})
                        return
                    if user.get("must_change_pass"):
                        self.respond(403,{"error":"Change your temporary password first."})
                        return
                    db.begin_write()
                    rows=read_table(db,"audit_logs")
                    rows.append({"id":max([r["id"] for r in rows],default=0)+1,"user_id":user["id"],"action":str(data.get("action",""))[:80],"module":str(data.get("module",""))[:80],"target_id":data.get("target_id"),"detail":str(data.get("detail",""))[:500],"created_at":datetime.now(timezone.utc).isoformat()})
                    write_table(db,"audit_logs",rows[-10000:])
                self.respond(201,{"ok":True})
                return
            if path == "/api/submissions":
                with connect() as db:
                    user=self.session_user(db)
                    if not user:
                        self.respond(401,{"error":"Sign in before submitting work."})
                        return
                    if user.get("must_change_pass") or user.get("role_slug")!="student":
                        self.respond(403,{"error":"Only an active student can submit assignment work."})
                        return
                    db.begin_write()
                    student=next((s for s in read_table(db,"students") if s.get("user_id")==user["id"] and s.get("status")=="active"),None)
                    try:
                        assignment_id=int(data.get("assignment_id"))
                        content=base64.b64decode(data.get("content_base64",""),validate=True)
                    except (TypeError,ValueError,binascii.Error):
                        self.respond(400,{"error":"Choose a valid submission file."})
                        return
                    filename=re.split(r"[\\/]",str(data.get("filename","")))[-1].replace("\x00","").strip()
                    extension=Path(filename).suffix.lower()
                    if not student or not filename or extension not in {".pdf",".doc",".docx",".txt",".png",".jpg",".jpeg"} or not content or len(content)>MAX_UPLOAD:
                        self.respond(400,{"error":"Use a supported, non-empty file up to 8 MB."})
                        return
                    assignment=next((a for a in read_table(db,"assignments") if a.get("id")==assignment_id),None)
                    if not assignment:
                        self.respond(404,{"error":"Assignment not found."})
                        return
                    enrollment=any(r.get("student_id")==student["id"] and r.get("course_id")==assignment.get("course_id") and r.get("status")=="approved" for r in read_table(db,"registrations"))
                    if not enrollment:
                        self.respond(403,{"error":"You must be registered in the assignment's course to submit work."})
                        return
                    if assignment.get("due_date") and str(assignment["due_date"]) < datetime.now(timezone.utc).date().isoformat():
                        self.respond(400,{"error":"The deadline for this assignment has passed."})
                        return
                    duplicate=next((row for row in read_table(db,"submissions") if row.get("assignment_id")==assignment_id and row.get("student_id")==student["id"]),None)
                    if duplicate:
                        self.respond(409,{"error":"A submission already exists for this assignment."})
                        return
                    mime=mimetypes.guess_type(filename)[0] or "application/octet-stream"
                    uploads_id=db.create_upload(user["id"],assignment_id,filename,mime,content,datetime.now(timezone.utc).isoformat())
                    rows=read_table(db,"submissions")
                    row={"id":max([r["id"] for r in rows],default=0)+1,"assignment_id":assignment_id,"student_id":student["id"],"upload_id":uploads_id,"file_name":filename,"comments":str(data.get("comments",""))[:1000],"submitted_at":datetime.now(timezone.utc).isoformat()}
                    rows.append(row)
                    write_table(db,"submissions",rows)
                self.respond(201,{"submission":row})
                return
            if path == "/api/admissions":
                if not isinstance(data,dict):
                    self.respond(400,{"error":"Admission details are required."});return
                with connect() as db:
                    user=self.session_user(db)
                    if not user:
                        self.respond(401,{"error":"Sign in before admitting a student."});return
                    if user.get("must_change_pass") or user["role_slug"] not in {"admin","registrar"}:
                        self.respond(403,{"error":"Only an administrator or registrar can admit students."});return
                    db.begin_write()
                    fn=str(data.get("fn"," ")).strip()[:80]
                    ln=str(data.get("ln"," ")).strip()[:80]
                    try:
                        dept_id=int(data.get("dept_id")); year=int(data.get("year_of_study",1))
                    except (TypeError,ValueError):
                        self.respond(400,{"error":"Select a valid department and year."});return
                    dept=next((d for d in read_table(db,"departments") if d["id"]==dept_id),None)
                    program=next((p for p in read_table(db,"programs") if p["dept_id"]==dept_id and p["name"]==data.get("programme")),None)
                    if not fn or not ln or not dept or not program or year not in range(1,7):
                        self.respond(400,{"error":"Student name, department, programme and year are required."});return
                    if data.get("application_id"):
                        application=next((a for a in read_table(db,"applications") if a["id"]==int(data["application_id"]) and a.get("status")=="pending"),None)
                        if not application:
                            self.respond(409,{"error":"This application is no longer pending admission."});return
                        if application.get("review_status") not in {"eligible","alternative_recommended"}:
                            self.respond(409,{"error":"Review the applicant's credentials and mark them eligible before admission."});return
                        if application.get("review_status")=="alternative_recommended":
                            dept_id=int(application.get("recommended_dept_id") or 0)
                            selected_program=application.get("recommended_program")
                        else:
                            dept_id=int(application.get("dept_id") or 0)
                            selected_program=application.get("prog_name")
                        dept=next((d for d in read_table(db,"departments") if d["id"]==dept_id),None)
                        program=next((p for p in read_table(db,"programs") if p.get("dept_id")==dept_id and p.get("name")==selected_program),None)
                        if not dept or not program:
                            self.respond(409,{"error":"The reviewed programme is no longer available."});return
                    existing_numbers=[int(re.search(r"(\d+)$",str(s.get("student_number",""))).group(1)) for s in read_table(db,"students") if s.get("dept_id")==dept_id and re.search(r"(\d+)$",str(s.get("student_number","")))]
                    number=max(max(existing_numbers,default=0),db.get_student_sequence(dept_id))+1
                    db.set_student_sequence(dept_id,number)
                    student_number=f"ACMS{datetime.now(timezone.utc).year}-{dept['code']}-{number:03d}"
                    settings=next(iter(read_table(db,"settings")),{})
                    email_domain=str(settings.get("email_domain","acms.ac.ug"))
                    username=student_number
                    email=f"{re.sub('[^a-z]','',fn.lower())}.{re.sub('[^a-z]','',ln.lower())}{number:03d}@student.{email_domain}"
                    users=read_table(db,"users")
                    if any(u.get("username")==username for u in users):
                        self.respond(409,{"error":"A student account with this student number already exists."});return
                    user_id=max([u["id"] for u in users],default=0)+1
                    temporary_password=secrets.token_urlsafe(12)
                    new_user={"id":user_id,"username":username,"password":password_hash(temporary_password),"full_name":f"{fn} {ln}","email":email,"role_id":2,"role_slug":"student","department_id":dept_id,"phone":str(data.get("phone",""))[:32],"status":"active","must_change_pass":True,"created_at":datetime.now(timezone.utc).isoformat()}
                    users.append(new_user);write_table(db,"users",users)
                    students=read_table(db,"students")
                    student_id=max([s["id"] for s in students],default=0)+1
                    student={"id":student_id,"user_id":user_id,"student_number":student_number,"dept_id":dept_id,"programme":program["name"],"study_mode":str(data.get("study_mode","full_time")),"year_of_study":year,"semester":1,"dob":str(data.get("dob","")),"gender":str(data.get("gender","")),"enrollment_date":datetime.now(timezone.utc).date().isoformat(),"status":"active","academic_year":str(settings.get("current_year","2024/2025")),"created_at":datetime.now(timezone.utc).isoformat()}
                    students.append(student);write_table(db,"students",students)
                    if data.get("application_id"):
                        applications=read_table(db,"applications")
                        for app in applications:
                            if app["id"]==data["application_id"]:
                                app.update(status="approved",admitted_student_id=student_id)
                        write_table(db,"applications",applications)
                    logs=read_table(db,"audit_logs")
                    logs.append({"id":max([entry["id"] for entry in logs],default=0)+1,"user_id":user["id"],"action":"student_admitted","module":"students","target_id":student_id,"detail":f"no:{student_number}","created_at":datetime.now(timezone.utc).isoformat()})
                    write_table(db,"audit_logs",logs[-10000:])
                self.respond(201,{"student_number":student_number,"username":username,"email":email,"temporary_password":temporary_password,"student_id":student_id})
                return
            if path == "/api/applications":
                required = ("fn", "ln", "email", "phone", "dept_id", "prog_name")
                if not isinstance(data, dict) or any(not str(data.get(key, "")).strip() for key in required):
                    self.respond(400, {"error":"Complete all required application fields."})
                    return
                if not re.fullmatch(r"[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+",str(data.get("email",""))) or not re.fullmatch(r"[+0-9()\- ]{7,24}",str(data.get("phone",""))):
                    self.respond(400,{"error":"Enter a valid email address and phone number."})
                    return
                credential_files=data.get("credentials",[])
                if not isinstance(credential_files,list) or len(credential_files)>5:
                    self.respond(400,{"error":"Attach up to five academic credential files."});return
                decoded_credentials=[]
                total_upload=0
                for credential in credential_files:
                    if not isinstance(credential,dict):
                        self.respond(400,{"error":"Invalid academic credential upload."});return
                    filename=re.sub(r"[^A-Za-z0-9._ -]","_",Path(re.split(r"[\\/]",str(credential.get("filename","")))[-1]).name).strip()[:180]
                    extension=Path(filename).suffix.lower()
                    try:
                        content=base64.b64decode(credential.get("content_base64",""),validate=True)
                    except (TypeError,ValueError,binascii.Error):
                        self.respond(400,{"error":"One of the credential files could not be read."});return
                    signatures={".pdf":content.startswith(b"%PDF-"),".jpg":content.startswith(b"\xff\xd8\xff"),".jpeg":content.startswith(b"\xff\xd8\xff"),".png":content.startswith(b"\x89PNG\r\n\x1a\n"),".doc":content.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"),".docx":content.startswith(b"PK\x03\x04")}
                    if not filename or extension not in signatures or not content or not signatures[extension]:
                        self.respond(400,{"error":"Credentials must be valid PDF, DOC, DOCX, JPG, JPEG, or PNG files."});return
                    total_upload+=len(content)
                    if total_upload>MAX_UPLOAD:
                        self.respond(400,{"error":"Academic credential files must total 8 MB or less."});return
                    decoded_credentials.append((filename,content,mimetypes.guess_type(filename)[0] or "application/octet-stream"))
                with connect() as db:
                    db.begin_write()
                    rows = read_table(db,"applications")
                    row = {"id":max([r["id"] for r in rows],default=0)+1,"created_at":datetime.now(timezone.utc).isoformat(),"status":"pending","review_status":"pending_review","documents":[],**{k:str(data[k]).strip() for k in required if k not in {"dept_id"}}}
                    try:
                        row["dept_id"] = int(data["dept_id"])
                    except (TypeError, ValueError):
                        self.respond(400,{"error":"Choose a valid department."})
                        return
                    departments=read_table(db,"departments")
                    programs=read_table(db,"programs")
                    if not any(d["id"]==row["dept_id"] for d in departments) or not any(p["dept_id"]==row["dept_id"] and p["name"]==row["prog_name"] for p in programs):
                        self.respond(400,{"error":"Choose a valid programme for the selected department."})
                        return
                    for filename,content,media_type in decoded_credentials:
                        uploaded=datetime.now(timezone.utc).isoformat()
                        document_id=db.create_application_document(row["id"],filename,media_type,content,uploaded)
                        row["documents"].append({"id":document_id,"filename":filename,"uploaded_at":uploaded})
                    rows.append(row)
                    write_table(db,"applications",rows)
                self.respond(201,{"id":row["id"]})
                return
            if path.startswith("/api/tables/"):
                name=unquote(path.removeprefix("/api/tables/"))
                if not isinstance(data,dict):
                    self.respond(400,{"error":"A record object is required."})
                    return
                self.table_insert(name,data)
                return
            self.respond(404,{"error":"Not found."})
        except ValueError as error:
            self.respond(400,{"error":str(error)})

    def do_PUT(self):
        if not self.origin_allowed():
            return
        path = urlparse(self.path).path
        if not path.startswith("/api/tables/"):
            self.respond(404,{"error":"Not found."})
            return
        try:
            self.table_write(unquote(path.removeprefix("/api/tables/")), self.read_json())
        except ValueError as error:
            self.respond(400,{"error":str(error)})

    def do_PATCH(self):
        if not self.origin_allowed():
            return
        path=urlparse(self.path).path
        review_match=re.fullmatch(r"/api/applications/(\d+)/review",path)
        if review_match:
            try:
                self.review_application(int(review_match.group(1)),self.read_json())
            except (ValueError,TypeError) as error:
                self.respond(400,{"error":str(error)})
            return
        parts=path.removeprefix("/api/tables/").split("/")
        if len(parts)!=2:
            self.respond(404,{"error":"Not found."})
            return
        try:
            self.table_update(unquote(parts[0]),int(unquote(parts[1])),self.read_json())
        except (ValueError,TypeError) as error:
            self.respond(400,{"error":str(error)})

    def review_application(self,application_id,data):
        if not isinstance(data,dict):
            self.respond(400,{"error":"Application review details are required."});return
        with connect() as db:
            user=self.session_user(db)
            if not user:
                self.respond(401,{"error":"Sign in before reviewing applications."});return
            if user.get("must_change_pass") or user.get("role_slug") not in {"admin","registrar"}:
                self.respond(403,{"error":"Only administrators and registrars can review applications."});return
            db.begin_write()
            applications=read_table(db,"applications")
            application=next((row for row in applications if row.get("id")==application_id),None)
            if not application:
                self.respond(404,{"error":"Application not found."});return
            if application.get("status")!="pending":
                self.respond(409,{"error":"Only pending applications can be reviewed."});return
            review_status=str(data.get("review_status",""))
            if review_status not in {"eligible","not_eligible","alternative_recommended"}:
                self.respond(400,{"error":"Choose eligible, not eligible, or alternative course recommended."});return
            if review_status in {"eligible","alternative_recommended"} and not application.get("documents"):
                self.respond(400,{"error":"The applicant must upload academic credentials before being marked eligible."});return
            updates={
                "review_status":review_status,
                "review_note":str(data.get("review_note",""))[:1000].strip(),
                "reviewed_by":user["id"],
                "reviewed_at":datetime.now(timezone.utc).isoformat(),
                "recommended_dept_id":None,
                "recommended_program":None,
            }
            if review_status=="alternative_recommended":
                try:
                    recommended_dept_id=int(data.get("recommended_dept_id"))
                except (TypeError,ValueError):
                    self.respond(400,{"error":"Choose the alternative department and programme."});return
                recommended_program=str(data.get("recommended_program","" )).strip()
                valid_department=any(dept.get("id")==recommended_dept_id for dept in read_table(db,"departments"))
                valid_program=any(program.get("dept_id")==recommended_dept_id and program.get("name")==recommended_program for program in read_table(db,"programs"))
                if not valid_department or not valid_program:
                    self.respond(400,{"error":"Choose a valid alternative programme for the selected department."});return
                updates["recommended_dept_id"]=recommended_dept_id
                updates["recommended_program"]=recommended_program
            application.update(updates)
            write_table(db,"applications",applications)
            logs=read_table(db,"audit_logs")
            logs.append({"id":max([entry["id"] for entry in logs],default=0)+1,"user_id":user["id"],"action":"application_reviewed","module":"applications","target_id":application_id,"detail":review_status,"created_at":datetime.now(timezone.utc).isoformat()})
            write_table(db,"audit_logs",logs[-10000:])
        self.respond(200,application)

    def do_DELETE(self):
        if not self.origin_allowed():
            return
        parts=urlparse(self.path).path.removeprefix("/api/tables/").split("/")
        if len(parts)!=2:
            self.respond(404,{"error":"Not found."})
            return
        try:
            self.table_delete(unquote(parts[0]),int(unquote(parts[1])))
        except (ValueError,TypeError) as error:
            self.respond(400,{"error":str(error)})

    def mutation_user(self, db, name):
        user=self.session_user(db)
        if not user:
            self.respond(401,{"error":"Sign in before changing data."})
            return None
        if user.get("must_change_pass"):
            self.respond(403,{"error":"Change your temporary password before accessing the portal."})
            return None
        if name not in TABLES or name not in WRITE_ROLES.get(user["role_slug"],set()):
            self.respond(403,{"error":"Your role cannot change this information."})
            return None
        return user

    def table_insert(self,name,payload):
        if name not in TABLES or not isinstance(payload,dict):
            self.respond(404,{"error":"Unknown data table."})
            return
        with connect() as db:
            user=self.mutation_user(db,name)
            if not user:return
            role=user["role_slug"]
            db.begin_write()
            rows=read_table(db,name)
            row=dict(payload)
            row.pop("id",None); row.pop("created_at",None); row.pop("updated_at",None)
            row["id"]=max([item["id"] for item in rows],default=0)+1
            row["created_at"]=datetime.now(timezone.utc).isoformat()
            if name=="departments":
                department_name=str(row.get("name","")).strip()
                department_code=str(row.get("code","")).strip().upper()
                if not department_name or len(department_name)>120 or not re.fullmatch(r"[A-Z0-9_-]{2,12}",department_code):
                    self.respond(400,{"error":"Enter a department name (up to 120 characters) and a 2–12 character code using letters, numbers, hyphens or underscores."});return
                if any(str(department.get("name","")).casefold()==department_name.casefold() or str(department.get("code","")).casefold()==department_code.casefold() for department in rows):
                    self.respond(409,{"error":"A department with this name or code already exists."});return
                row={"id":row["id"],"name":department_name,"code":department_code,"created_at":row["created_at"]}
            elif name=="users":
                if role=="registrar" and row.get("role_slug")!="student":
                    self.respond(403,{"error":"Registrars may only create student accounts."});return
                if len(str(row.get("password","")))<10:
                    self.respond(400,{"error":"Passwords must be at least 10 characters."});return
                row["password"]=password_hash(str(row["password"]))
                row["must_change_pass"]=True
                valid_roles={r["slug"] for r in read_table(db,"roles")}
                if row.get("role_slug") not in valid_roles or not re.fullmatch(r"[A-Za-z0-9._-]{3,64}",str(row.get("username",""))):
                    self.respond(400,{"error":"User account fields are invalid."});return
                if any(str(u.get("username","")).casefold()==row["username"].casefold() or (row.get("email") and str(u.get("email","")).casefold()==str(row["email"]).casefold()) for u in rows):
                    self.respond(409,{"error":"Username or email is already in use."});return
            elif name=="registrations" and role=="student":
                student=next((s for s in read_table(db,"students") if s.get("user_id")==user["id"] and s.get("status")=="active"),None)
                course=next((c for c in read_table(db,"courses") if c["id"]==row.get("course_id")),None)
                if not student or not course or course.get("status")!="active" or course.get("dept_id")!=student.get("dept_id"):
                    self.respond(400,{"error":"Choose an available course in your department."});return
                if any(r.get("student_id")==student["id"] and r.get("course_id")==course["id"] and r.get("status")!="rejected" for r in rows):
                    self.respond(409,{"error":"You already have a registration request for this course."});return
                row.update(student_id=student["id"],status="pending")
            elif name=="messages":
                row["from_id"]=user["id"]
            elif name=="announcements":
                row["created_by"]=user["id"]
            elif name=="notifications":
                row["user_id"]=user["id"]
            elif name=="books":
                row["added_by"]=user["id"]
                if row.get("isbn") not in {None,"","N/A"} and any(book.get("isbn")==row.get("isbn") for book in rows):
                    self.respond(409,{"error":"A book with this ISBN is already in the catalogue."});return
                if int(row.get("copies",0))<1 or not str(row.get("title"," ")).strip() or not str(row.get("author"," ")).strip():
                    self.respond(400,{"error":"Book title, author and a positive copy count are required."});return
            elif name=="assignments" and role=="lecturer":
                if not any(c["id"]==row.get("course_id") for c in read_table(db,"courses")):
                    self.respond(400,{"error":"Choose a valid course."});return
                if int(row.get("max_marks",100))<=0:
                    self.respond(400,{"error":"Maximum marks must be positive."});return
                row["created_by"]=user["id"]
            elif name=="results" and role=="lecturer":
                row["submitted_by"]=user["id"]
                row["status"]="submitted"
                if not self.grade_result(db,row):return
                if any(result.get("student_id")==row.get("student_id") and result.get("course_id")==row.get("course_id") for result in rows):
                    self.respond(409,{"error":"A result already exists for this student and course."});return
            elif name=="courses":
                row["code"]=str(row.get("code","" )).strip().upper()
                if not row["code"] or not str(row.get("name"," ")).strip() or any(course.get("code")==row["code"] for course in rows):
                    self.respond(409,{"error":"Course code is required and must be unique."});return
            elif name=="fee_payments":
                try: amount=float(row.get("amount",0))
                except (TypeError,ValueError): amount=0
                if amount<=0 or not any(s["id"]==row.get("student_id") for s in read_table(db,"students")):
                    self.respond(400,{"error":"Payment must reference a student and have a positive amount."});return
                row["confirmed_by"]=user["id"]
            elif name=="hostel_allocations":
                hostel=next((h for h in read_table(db,"hostels") if h["id"]==row.get("hostel_id")),None)
                student=next((s for s in read_table(db,"students") if s["id"]==row.get("student_id")),None)
                occupied=sum(1 for a in rows if a.get("hostel_id")==row.get("hostel_id") and a.get("status")=="active")
                if not hostel or not student or occupied>=int(hostel.get("total_rooms",0)) or any(a.get("student_id")==student["id"] and a.get("status")=="active" for a in rows):
                    self.respond(400,{"error":"No available room or the student already has an active allocation."});return
                if hostel.get("gender") not in {"mixed",str(student.get("gender","")).lower()}:
                    self.respond(400,{"error":"Choose a hostel that matches the student's recorded gender."});return
                row["status"]="active"
            rows.append(row)
            write_table(db,name,rows)
            returned=sanitize_user(row) if name=="users" else row
        self.respond(201,returned)

    def grade_result(self,db,row):
        try:
            coursework=float(row.get("coursework",0)); exam=float(row.get("exam",0))
        except (TypeError,ValueError):
            self.respond(400,{"error":"Marks must be numeric."});return False
        if not 0<=coursework<=40 or not 0<=exam<=60 or not any(s["id"]==row.get("student_id") for s in read_table(db,"students")) or not any(c["id"]==row.get("course_id") for c in read_table(db,"courses")) or not any(r.get("student_id")==row.get("student_id") and r.get("course_id")==row.get("course_id") and r.get("status")=="approved" for r in read_table(db,"registrations")):
            self.respond(400,{"error":"Marks must be in range for a valid student enrolled in the course."});return False
        total=coursework+exam
        grade,gp,remark=next((g for minimum,g in [(80,("A",5.0,"Distinction")),(70,("B+",4.5,"Very Good")),(65,("B",4.0,"Good")),(60,("C+",3.5,"Credit")),(55,("C",3.0,"Credit")),(50,("D",2.0,"Pass"))] if total>=minimum),("F",0.0,"Fail"))
        row.update(coursework=coursework,exam=exam,grade=grade,grade_points=gp,remark="pass" if total>=50 else "fail")
        return True

    def table_update(self,name,record_id,updates):
        if name not in TABLES or not isinstance(updates,dict):
            self.respond(400,{"error":"Invalid record update."});return
        with connect() as db:
            user=self.mutation_user(db,name)
            if not user:return
            db.begin_write()
            rows=read_table(db,name)
            index=next((i for i,row in enumerate(rows) if row.get("id")==record_id),None)
            if index is None:
                self.respond(404,{"error":"Record not found."});return
            role=user["role_slug"]; old=rows[index]
            updates={key:value for key,value in updates.items() if key not in {"id","created_at","updated_at"}}
            if name=="departments":
                department_name=str(updates.get("name",old.get("name",""))).strip()
                department_code=str(updates.get("code",old.get("code",""))).strip().upper()
                if not department_name or len(department_name)>120 or not re.fullmatch(r"[A-Z0-9_-]{2,12}",department_code):
                    self.respond(400,{"error":"Enter a department name (up to 120 characters) and a 2–12 character code using letters, numbers, hyphens or underscores."});return
                if any(department.get("id")!=record_id and (str(department.get("name","")).casefold()==department_name.casefold() or str(department.get("code","")).casefold()==department_code.casefold()) for department in rows):
                    self.respond(409,{"error":"A department with this name or code already exists."});return
                updates={"name":department_name,"code":department_code}
            if name=="messages" and role!="admin" and old.get("from_id")!=user["id"]:
                self.respond(403,{"error":"You can only edit messages sent from your account."});return
            if name=="announcements" and role!="admin" and old.get("created_by")!=user["id"]:
                self.respond(403,{"error":"You can only edit announcements created by your account."});return
            if name=="notifications" and role!="admin" and old.get("user_id")!=user["id"]:
                self.respond(403,{"error":"You can only edit notifications created by your account."});return
            if name=="users" and role=="registrar":
                self.respond(403,{"error":"Registrars may create student accounts but cannot edit existing accounts."});return
            if name=="users" and "role_slug" in updates:
                selected_role=next((item for item in read_table(db,"roles") if item.get("slug")==updates["role_slug"]),None)
                if not selected_role:
                    self.respond(400,{"error":"Choose a valid account role."});return
                updates["role_id"]=selected_role["id"]
            elif name=="users" and "role_id" in updates:
                self.respond(400,{"error":"Update the account role using its role name."});return
            if name=="users" and "password" in updates:
                password=str(updates["password"])
                if len(password)<10:
                    self.respond(400,{"error":"Passwords must be at least 10 characters."});return
                updates={**updates,"password":password_hash(password),"must_change_pass":True}
                db.delete_sessions_for_user(record_id)
            if name=="registrations" and role=="student":
                self.respond(403,{"error":"Students cannot directly alter registration decisions."});return
            if name=="fee_payments" and role=="finance" and (set(updates)!={"status"} or updates.get("status")!="reversed"):
                self.respond(403,{"error":"Finance staff may reverse a payment but cannot rewrite its transaction details."});return
            if name=="results" and role=="lecturer":
                if old.get("submitted_by")!=user["id"] or old.get("status") in {"approved","locked"}:
                    self.respond(403,{"error":"This result cannot be changed."});return
                candidate={**old,**updates}
                candidate["submitted_by"]=user["id"];candidate["status"]="submitted"
                if not self.grade_result(db,candidate):return
                updates={**updates,"coursework":candidate["coursework"],"exam":candidate["exam"],"grade":candidate["grade"],"grade_points":candidate["grade_points"],"remark":candidate["remark"],"submitted_by":user["id"],"status":"submitted"}
            if name=="assignments" and role=="lecturer" and old.get("created_by")!=user["id"]:
                self.respond(403,{"error":"You can only edit your own assignments."});return
            if name=="hostel_allocations" and role=="hostel" and updates.get("status")!="checked_out":
                self.respond(400,{"error":"Only checking out an active allocation is supported."});return
            rows[index]={**old,**updates,"updated_at":datetime.now(timezone.utc).isoformat()}
            write_table(db,name,rows)
            returned=sanitize_user(rows[index]) if name=="users" else rows[index]
        self.respond(200,returned)

    def table_delete(self,name,record_id):
        if name not in TABLES:
            self.respond(404,{"error":"Unknown data table."});return
        with connect() as db:
            user=self.mutation_user(db,name)
            if not user:return
            db.begin_write()
            rows=read_table(db,name)
            target=next((row for row in rows if row.get("id")==record_id),None)
            if not target:
                self.respond(404,{"error":"Record not found."});return
            role=user["role_slug"]
            deletable={"admin":set(TABLES),"lecturer":{"assignments"},"registrar":{"courses","announcements"},"comms":{"announcements"},"librarian":{"books"}}
            if name not in deletable.get(role,set()):
                self.respond(403,{"error":"Your role cannot delete records from this table."});return
            if name=="users" and (user["role_slug"]!="admin" or record_id==user["id"]):
                self.respond(403,{"error":"Only administrators can remove another account."});return
            if name=="assignments" and user["role_slug"]=="lecturer" and target.get("created_by")!=user["id"]:
                self.respond(403,{"error":"You can only remove your own assignments."});return
            if name=="announcements" and user["role_slug"]!="admin" and target.get("created_by")!=user["id"]:
                self.respond(403,{"error":"You can only remove announcements created by your account."});return
            if name=="fee_payments" and user["role_slug"]!="admin":
                self.respond(403,{"error":"Payments cannot be deleted; use the reversal workflow."});return
            if name=="departments":
                referenced=any(
                    any(row.get(field)==record_id for row in read_table(db,table))
                    for table,field in (("users","department_id"),("students","dept_id"),("applications","dept_id"),("programs","dept_id"),("courses","dept_id"))
                )
                if referenced:
                    self.respond(409,{"error":"This department is in use. Reassign or remove its linked users, students, applications, programs, and courses before deleting it."});return
            write_table(db,name,[row for row in rows if row.get("id")!=record_id])
            if name=="departments":db.delete_student_sequence(record_id)
            if name=="users":db.delete_sessions_for_user(record_id)
            if name=="applications":
                db.delete_application_documents(record_id)
        self.respond(200,{"deleted":record_id})

    def table_write(self, name, rows):
        if name not in TABLES:
            self.respond(404,{"error":"Unknown data table."})
            return
        if not isinstance(rows,list) or any(not isinstance(row,dict) for row in rows):
            self.respond(400,{"error":"Table data must be an array of objects."})
            return
        ids=[row.get("id") for row in rows]
        if any(not isinstance(row_id,int) or isinstance(row_id,bool) for row_id in ids) or len(ids)!=len(set(ids)):
            self.respond(400,{"error":"Records must have unique integer ids."})
            return
        requested_rows=rows
        with connect() as db:
            user=self.session_user(db)
            if not user:
                self.respond(401,{"error":"Sign in before changing data."})
                return
            if user.get("must_change_pass"):
                self.respond(403,{"error":"Change your temporary password before accessing the portal."})
                return
            role=user["role_slug"]
            if name not in WRITE_ROLES.get(role,set()):
                self.respond(403,{"error":"Your role cannot change this information."})
                return
            db.begin_write()
            existing=read_table(db,name)
            if role == "student":
                student=next((s for s in read_table(db,"students") if s.get("user_id")==user["id"]),None)
                sid=student.get("id") if student else -1
                if name == "registrations":
                    old={r["id"]:r for r in existing}
                    for row in rows:
                        previous=old.get(row["id"])
                        if row.get("student_id") != sid or row.get("status") not in {"pending","rejected"} or (previous and previous.get("student_id") != sid):
                            self.respond(403,{"error":"Students may only request their own course registrations."})
                            return
                        course=next((c for c in read_table(db,"courses") if c["id"]==row.get("course_id")),None)
                        if not course or not student or course.get("dept_id")!=student.get("dept_id"):
                            self.respond(400,{"error":"Choose an available course in your department."})
                            return
                elif name == "submissions":
                    if any(row.get("student_id") != sid for row in rows):
                        self.respond(403,{"error":"Students may only submit their own work."})
                        return
                elif name == "messages":
                    if any(row.get("from_id") != user["id"] for row in rows):
                        self.respond(403,{"error":"Messages must be sent from the signed-in account."})
                        return
                # The student API exposes only the signed-in student's rows. Merge
                # those changes into the complete server table rather than deleting
                # every other student's records on a full-table UI update.
                if name in {"registrations", "submissions", "messages"}:
                    if name == "messages":
                        rows=[row for row in existing if row.get("from_id") != user["id"]]+[row for row in rows if row.get("from_id")==user["id"]]
                    else:
                        owned_ids={row["id"] for row in existing if row.get("student_id")==sid}
                        rows=[row for row in existing if row["id"] not in owned_ids]+rows
            if role == "lecturer" and name in {"assignments","results"}:
                owner_key="created_by" if name=="assignments" else "submitted_by"
                owned_ids={row["id"] for row in existing if row.get(owner_key)==user["id"]}
                rows=[row for row in existing if row["id"] not in owned_ids]+rows
            if name == "users":
                old={row["id"]:row for row in existing}
                normalized=[]
                for row in rows:
                    previous=old.get(row["id"],{})
                    if role == "registrar" and previous and any(row.get(key)!=previous.get(key) for key in ("username","role_slug","role_id","email","status","department_id")):
                        self.respond(403,{"error":"Registrars can create student accounts but cannot change existing accounts."})
                        return
                    if role == "registrar" and not previous and row.get("role_slug") != "student":
                        self.respond(403,{"error":"Registrars may only create student accounts."})
                        return
                    password=row.get("password")
                    if not password:
                        password=previous.get("password")
                    elif password != previous.get("password"):
                        if len(str(password)) < 10:
                            self.respond(400,{"error":"Passwords must be at least 10 characters."})
                            return
                        password=password_hash(str(password))
                    if not password:
                        self.respond(400,{"error":"A password must be set for every account."})
                        return
                    normalized.append({**row,"password":password,**({"must_change_pass":True} if not previous else {})})
                rows=normalized
                if role == "registrar" and any(uid not in {r["id"] for r in rows} for uid in old):
                    self.respond(403,{"error":"Registrars cannot delete user accounts."})
                    return
                usernames=[str(row.get("username","" )).casefold() for row in rows]
                emails=[str(row.get("email","" )).casefold() for row in rows if row.get("email")]
                if any(not value for value in usernames) or len(usernames)!=len(set(usernames)) or len(emails)!=len(set(emails)):
                    self.respond(400,{"error":"Usernames and email addresses must be unique."})
                    return
                valid_roles={row["slug"] for row in read_table(db,"roles")}
                if any(not re.fullmatch(r"[A-Za-z0-9._-]{3,64}",str(row.get("username",""))) or row.get("role_slug") not in valid_roles or row.get("status") not in {"active","inactive"} for row in rows):
                    self.respond(400,{"error":"User account fields are invalid."})
                    return
                for row in rows:
                    prior=old.get(row["id"])
                    if prior and prior.get("password") != row.get("password"):
                        db.delete_sessions_for_user(row["id"])
            if role == "lecturer" and name == "assignments":
                courses={course["id"] for course in read_table(db,"courses")}
                old_assignments={row["id"]:row for row in existing}
                if any(row.get("created_by")!=user["id"] or row.get("course_id") not in courses or (row["id"] in old_assignments and old_assignments[row["id"]].get("created_by")!=user["id"]) for row in requested_rows):
                    self.respond(403,{"error":"You may only create assignments for valid courses under your account."})
                    return
            if role == "lecturer" and name == "results":
                old={row["id"]:row for row in existing}
                students={row["id"] for row in read_table(db,"students")}
                courses={row["id"] for row in read_table(db,"courses")}
                for row in requested_rows:
                    previous=old.get(row["id"])
                    try:
                        marks=float(row.get("coursework",0))+float(row.get("exam",0))
                        coursework=float(row.get("coursework",0)); exam=float(row.get("exam",0))
                    except (TypeError,ValueError):
                        self.respond(400,{"error":"Marks must be numeric."})
                        return
                    if row.get("submitted_by")!=user["id"] or row.get("student_id") not in students or row.get("course_id") not in courses or not (0<=coursework<=40 and 0<=exam<=60) or row.get("status") not in {"submitted","draft"} or (previous and (previous.get("status") in {"approved","locked"} or previous.get("submitted_by")!=user["id"])):
                        self.respond(403,{"error":"Invalid or locked result submission."})
                        return
            if name == "fee_payments":
                student_ids={row["id"] for row in read_table(db,"students")}
                for row in rows:
                    try: amount=float(row.get("amount",0))
                    except (TypeError,ValueError): amount=0
                    if row.get("student_id") not in student_ids or amount<=0 or row.get("status") not in {"confirmed","pending","reversed"}:
                        self.respond(400,{"error":"Payment must reference a student and have a positive amount."})
                        return
            if role == "hostel" and name == "hostel_allocations":
                hostels={row["id"]:row for row in read_table(db,"hostels")}
                students={row["id"] for row in read_table(db,"students")}
                if any(row.get("student_id") not in students or row.get("hostel_id") not in hostels or row.get("status") not in {"active","checked_out"} for row in rows):
                    self.respond(400,{"error":"Allocation must reference a valid student and hostel."})
                    return
            if len(json.dumps(rows,ensure_ascii=False).encode()) > MAX_BODY:
                self.respond(413,{"error":"Table is too large."})
                return
            write_table(db,name,rows)
        self.respond(200,{"saved":len(rows)})

    def log_message(self, fmt, *args):
        print(f"{self.log_date_time_string()} {self.address_string()} {fmt % args}")


def main():
    bootstrap=seed_database()
    host=os.environ.get("NUU_HOST","127.0.0.1")
    port=int(os.environ.get("PORT",os.environ.get("NUU_PORT","8000")))
    server=ThreadingHTTPServer((host,port),Handler)
    storage="Neon PostgreSQL" if DATABASE_URL else "volatile in-memory storage"
    print(f"ACMS server running at http://{host}:{port} ({storage})")
    if bootstrap:
        print(f"Initial admin login — username: {bootstrap['username']}  password: {bootstrap['password']}")
        print("Change this temporary password at first sign-in. Save it securely; it is shown only during initial setup.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping NUU server.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
