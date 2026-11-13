import http.cookiejar
import base64
import io
import json
import tempfile
import threading
import unittest
import zipfile
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import HTTPCookieProcessor, Request, build_opener, urlopen

import server


class ServerTests(unittest.TestCase):
    ADMIN_PASSWORD="Bootstrap-Admin-Pass-55"
    @classmethod
    def setUpClass(cls):
        cls.temps=[]
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.httpd.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        for temp in cls.temps:
            temp.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.temps.append(self.temp)
        server.DB_PATH = Path(self.temp.name) / "test.sqlite3"
        server.seed_database(bootstrap_password=self.ADMIN_PASSWORD)
        self.opener = build_opener(HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def tearDown(self):
        pass

    def request(self, method, path, data=None, opener=None, headers=None):
        body = None if data is None else json.dumps(data).encode()
        request_headers={"Content-Type":"application/json",**(headers or {})}
        request = Request(self.base + path, data=body, method=method, headers=request_headers)
        with (opener or self.opener).open(request) as response:
            payload = json.loads(response.read()) if response.headers.get_content_type() == "application/json" else response.read()
            return response.status, payload, response.headers

    def login(self, username="admin", password=ADMIN_PASSWORD):
        return self.request("POST", "/api/auth/login", {"username":username,"password":password})

    def enable_admin_session(self):
        self.login()
        self.request("POST","/api/auth/password",{"current_password":self.ADMIN_PASSWORD,"new_password":"Admin-Password-55"})

    def test_bootstrap_password_is_hashed_and_forced_to_change(self):
        with server.connect() as db:
            user = server.read_table(db,"users")[0]
        self.assertNotEqual(user["password"],self.ADMIN_PASSWORD)
        self.assertTrue(server.verify_password(self.ADMIN_PASSWORD,user["password"]))
        self.assertTrue(user["must_change_pass"])

    def test_postgresql_compatibility_adapter_translates_types_and_parameters(self):
        class FakeConnection:
            def __init__(self):
                self.statements=[]
            def execute(self,statement,parameters=()):
                self.statements.append((statement,parameters))
            def commit(self): pass
            def rollback(self): pass
            def close(self): pass

        raw=FakeConnection()
        db=server.PostgreSQLConnection(raw)
        db.execute("CREATE TABLE files (id INTEGER PRIMARY KEY AUTOINCREMENT, content BLOB NOT NULL)")
        db.execute("SELECT id FROM files WHERE id=?",(9,))
        db.execute("BEGIN IMMEDIATE")
        self.assertIn("BIGSERIAL PRIMARY KEY",raw.statements[0][0])
        self.assertIn("BYTEA",raw.statements[0][0])
        self.assertEqual(raw.statements[1],("SELECT id FROM files WHERE id=%s",(9,)))
        self.assertEqual(raw.statements[2],("LOCK TABLE app_tables IN EXCLUSIVE MODE",()))
        self.assertEqual(len(raw.statements),3)

    def test_temporary_password_cannot_read_private_tables(self):
        self.login()
        with self.assertRaises(HTTPError) as error:
            self.request("GET","/api/tables/users")
        self.assertEqual(error.exception.code,403)

    def test_existing_plaintext_accounts_are_migrated(self):
        with server.connect() as db:
            user=server.read_table(db,"users")[0]
            user["password"]="Legacy-Plaintext"
            server.write_table(db,"users",[user])
        server.seed_database()
        with server.connect() as db:
            migrated=server.read_table(db,"users")[0]
        self.assertTrue(server.verify_password("Legacy-Plaintext",migrated["password"]))
        self.assertTrue(migrated["must_change_pass"])

    def test_login_sets_http_only_session_and_never_returns_password(self):
        status, payload, headers = self.login()
        self.assertEqual(status,200)
        self.assertNotIn("password",payload["user"])
        self.assertIn("HttpOnly",headers["Set-Cookie"])
        self.assertEqual(self.request("GET","/api/auth/me")[1]["user"]["username"],"admin")

    def test_login_attempts_are_not_rate_limited(self):
        for _ in range(12):
            with self.assertRaises(HTTPError) as error:
                self.login(password="wrong-password")
            self.assertEqual(error.exception.code,401)
        status, payload, _ = self.login()
        self.assertEqual(status,200)
        self.assertEqual(payload["user"]["username"],"admin")

    def test_department_excel_export_requires_authorized_session_and_is_valid_xlsx(self):
        with self.assertRaises(HTTPError) as error:
            self.request("GET", "/api/exports/departments.xlsx", opener=build_opener())
        self.assertEqual(error.exception.code,401)

        self.enable_admin_session()
        status, workbook, headers = self.request("GET", "/api/exports/departments.xlsx")
        self.assertEqual(status,200)
        self.assertIn("department_directory.xlsx",headers["Content-Disposition"])
        with zipfile.ZipFile(io.BytesIO(workbook)) as archive:
            self.assertIsNone(archive.testzip())
            sheet=archive.read("xl/worksheets/sheet1.xml").decode()
        self.assertIn("Department",sheet)
        self.assertIn("Computer Science &amp; IT",sheet)

    def test_admin_can_create_departments_and_other_roles_cannot(self):
        self.enable_admin_session()
        status, created, _ = self.request("POST", "/api/tables/departments", {"name":"Architecture and Design","code":"arch"})
        self.assertEqual(status,201)
        self.assertEqual(created["code"],"ARCH")
        with self.assertRaises(HTTPError) as error:
            self.request("POST", "/api/tables/departments", {"name":"Different Name","code":"ARCH"})
        self.assertEqual(error.exception.code,409)
        status, updated, _ = self.request("PATCH",f"/api/tables/departments/{created['id']}",{"name":"Architecture","code":"ARCD"})
        self.assertEqual(status,200)
        self.assertEqual(updated["name"],"Architecture")
        self.assertEqual(updated["code"],"ARCD")
        self.assertEqual(self.request("DELETE",f"/api/tables/departments/{created['id']}")[0],200)
        with self.assertRaises(HTTPError) as error:
            self.request("DELETE", "/api/tables/departments/1")
        self.assertEqual(error.exception.code,409)

        with server.connect() as db:
            users=server.read_table(db,"users")
            users.append({"id":2,"username":"registrar1","password":server.password_hash("Registrar-Password-55"),"full_name":"Test Registrar","email":"registrar@nuu.ac.ug","role_id":4,"role_slug":"registrar","department_id":None,"status":"active","must_change_pass":False})
            server.write_table(db,"users",users)
        registrar=build_opener(HTTPCookieProcessor(http.cookiejar.CookieJar()))
        self.request("POST","/api/auth/login",{"username":"registrar1","password":"Registrar-Password-55"},opener=registrar)
        with self.assertRaises(HTTPError) as error:
            self.request("POST", "/api/tables/departments", {"name":"Unauthorized Department","code":"UNAUTH"},opener=registrar)
        self.assertEqual(error.exception.code,403)

    def test_admin_role_edit_persists_and_finance_hides_nonstudent_profiles(self):
        self.enable_admin_session()
        _, account, _ = self.request("POST", "/api/tables/users", {
            "username":"nelson.kule","password":"Nelson-Password-55","full_name":"Kule Nelson",
            "email":"kule.nelson@lecturer.acms.ac.ug","role_id":2,"role_slug":"student","department_id":1,"status":"active",
        })
        with server.connect() as db:
            students=server.read_table(db,"students")
            students.append({"id":1,"user_id":account["id"],"student_number":"ACMS-001","dept_id":1,"status":"active"})
            users=server.read_table(db,"users")
            users.append({"id":3,"username":"finance1","password":server.password_hash("Finance-Password-55"),"full_name":"Finance User","email":"finance@acms.ac.ug","role_id":5,"role_slug":"finance","department_id":None,"status":"active","must_change_pass":False})
            server.write_table(db,"students",students)
            server.write_table(db,"users",users)

        _, updated, _ = self.request("PATCH",f"/api/tables/users/{account['id']}",{"role_slug":"lecturer","department_id":1})
        self.assertEqual(updated["role_slug"],"lecturer")
        self.assertEqual(updated["role_id"],3)

        finance=build_opener(HTTPCookieProcessor(http.cookiejar.CookieJar()))
        self.request("POST","/api/auth/login",{"username":"finance1","password":"Finance-Password-55"},opener=finance)
        _, visible_students, _ = self.request("GET","/api/tables/students",opener=finance)
        self.assertEqual(visible_students,[])

    def test_private_tables_require_session_and_public_reference_data_does_not(self):
        with self.assertRaises(HTTPError) as error:
            urlopen(self.base+"/api/tables/users")
        self.assertEqual(error.exception.code,401)
        self.assertEqual(self.request("GET","/api/tables/departments",opener=build_opener())[0],200)

    def test_mutations_reject_cross_origin_requests(self):
        with self.assertRaises(HTTPError) as error:
            self.request("POST","/api/applications",{},opener=build_opener(),headers={"Origin":"https://attacker.invalid"})
        self.assertEqual(error.exception.code,403)

    def test_configured_vercel_origin_can_submit_applications(self):
        allowed_origin="https://acms-portal.vercel.app"
        previous=server.ALLOWED_ORIGINS
        server.ALLOWED_ORIGINS=set(previous)|{allowed_origin}
        try:
            status,_,_=self.request("POST","/api/applications",{
                "fn":"Vercel","ln":"Applicant","email":"vercel@example.test","phone":"+256700000066",
                "dept_id":1,"prog_name":"BSc Computer Science",
            },opener=build_opener(),headers={"Origin":allowed_origin})
            self.assertEqual(status,201)
        finally:
            server.ALLOWED_ORIGINS=previous

    def test_security_headers_are_set_on_app_response(self):
        with urlopen(self.base+"/") as response:
            self.assertEqual(response.headers["X-Frame-Options"],"DENY")
            self.assertIn("frame-ancestors 'none'",response.headers["Content-Security-Policy"])

    def test_college_logo_is_served_for_branding(self):
        with urlopen(self.base+"/ark%20logo.JPG") as response:
            self.assertEqual(response.headers.get_content_type(),"image/jpeg")
            self.assertTrue(response.read().startswith(b"\xff\xd8"))

    def test_password_change_revokes_default_and_accepts_new_password(self):
        self.login()
        status, _, _ = self.request("POST","/api/auth/password",{"current_password":self.ADMIN_PASSWORD,"new_password":"Correct-Horse-88"})
        self.assertEqual(status,200)
        with self.assertRaises(HTTPError):
            self.login()
        self.login(password="Correct-Horse-88")

    def test_student_data_is_scoped_and_role_writes_are_denied(self):
        self.enable_admin_session()
        with server.connect() as db:
            users=server.read_table(db,"users")
            users.append({"id":2,"username":"student1","password":server.password_hash("Student-Password-55"),"full_name":"Test Student","email":"student@nuu.ac.ug","role_id":2,"role_slug":"student","department_id":1,"status":"active","must_change_pass":False})
            students=server.read_table(db,"students")
            students.extend([{"id":1,"user_id":2,"student_number":"NUU-001","dept_id":1,"status":"active"},{"id":2,"user_id":3,"student_number":"NUU-002","dept_id":1,"status":"active"}])
            server.write_table(db,"users",users)
            server.write_table(db,"students",students)
        student_opener=build_opener(HTTPCookieProcessor(http.cookiejar.CookieJar()))
        # use an independent authenticated opener for the student account
        student_opener=build_opener(HTTPCookieProcessor(http.cookiejar.CookieJar()))
        request=Request(self.base+"/api/auth/login",data=json.dumps({"username":"student1","password":"Student-Password-55"}).encode(),method="POST",headers={"Content-Type":"application/json"})
        with student_opener.open(request) as response:
            self.assertEqual(response.status,200)
        _, students, _=self.request("GET","/api/tables/students",opener=student_opener)
        self.assertEqual([row["id"] for row in students],[1])
        _, users, _=self.request("GET","/api/tables/users",opener=student_opener)
        self.assertEqual([row["id"] for row in users],[2])
        self.assertNotIn("password",users[0])
        with self.assertRaises(HTTPError) as error:
            self.request("PUT","/api/tables/users",[],opener=student_opener)
        self.assertEqual(error.exception.code,403)

    def test_registrar_can_create_student_account_but_not_privileged_accounts(self):
        self.enable_admin_session()
        with server.connect() as db:
            users=server.read_table(db,"users")
        users.append({"id":2,"username":"registrar1","password":"Registrar-Password-55","full_name":"Registrar User","email":"registrar@nuu.ac.ug","role_id":4,"role_slug":"registrar","department_id":None,"status":"active","must_change_pass":True})
        self.request("PUT","/api/tables/users",users)
        registrar=build_opener(HTTPCookieProcessor(http.cookiejar.CookieJar()))
        self.request("POST","/api/auth/login",{"username":"registrar1","password":"Registrar-Password-55"},opener=registrar)
        self.request("POST","/api/auth/password",{"current_password":"Registrar-Password-55","new_password":"Registrar-New-Password-88"},opener=registrar)
        _,created,_=self.request("POST","/api/tables/users",{"username":"student.001","password":"Student-Password-55","full_name":"Student One","email":"student001@student.nuu.ac.ug","role_id":2,"role_slug":"student","department_id":1,"status":"active"},opener=registrar)
        with server.connect() as db:
            saved=server.read_table(db,"users")
        new_student=next(row for row in saved if row["id"]==created["id"])
        self.assertTrue(server.verify_password("Student-Password-55",new_student["password"]))
        self.assertTrue(new_student["must_change_pass"])
        with self.assertRaises(HTTPError) as error:
            self.request("POST","/api/tables/users",{"username":"badadmin","password":"Student-Password-55","full_name":"Bad Admin","email":"badadmin@nuu.ac.ug","role_id":1,"role_slug":"admin","status":"active"},opener=registrar)
        self.assertEqual(error.exception.code,403)

    def test_application_submission_is_public_but_validated(self):
        with self.assertRaises(HTTPError) as error:
            self.request("POST","/api/applications",{"fn":"A"},opener=build_opener())
        self.assertEqual(error.exception.code,400)
        status, payload, _=self.request("POST","/api/applications",{"fn":"<script>alert(1)</script>","ln":"Student","email":"a@example.test","phone":"+256700000000","dept_id":1,"prog_name":"BSc Computer Science"},opener=build_opener())
        self.assertEqual(status,201)
        self.assertEqual(payload["id"],1)
        with server.connect() as db:
            application=server.read_table(db,"applications")[0]
        self.assertNotIn("<",application["fn"])

    def test_admission_creates_hashed_account_student_and_approves_application_atomically(self):
        app_opener=build_opener()
        pdf=base64.b64encode(b"%PDF-1.4\ncredential\n%%EOF").decode()
        _,application,_=self.request("POST","/api/applications",{"fn":"Amina","ln":"Test","email":"amina@example.test","phone":"+256700000001","dept_id":1,"prog_name":"BSc Computer Science","credentials":[{"filename":"transcript.pdf","content_base64":pdf}]},opener=app_opener)
        self.enable_admin_session()
        self.request("PATCH",f"/api/applications/{application['id']}/review",{"review_status":"eligible","review_note":"Transcript reviewed."})
        status,result,_=self.request("POST","/api/admissions",{"fn":"Amina","ln":"Test","dept_id":1,"programme":"BSc Computer Science","year_of_study":1,"study_mode":"full_time","application_id":application["id"]})
        self.assertEqual(status,201)
        with server.connect() as db:
            users=server.read_table(db,"users")
            students=server.read_table(db,"students")
            apps=server.read_table(db,"applications")
        new_user=next(row for row in users if row["username"]==result["username"])
        self.assertTrue(server.verify_password(result["temporary_password"],new_user["password"]))
        self.assertTrue(new_user["must_change_pass"])
        self.assertEqual(students[-1]["student_number"],result["student_number"])
        self.assertTrue(result["student_number"].startswith("ACMS"))
        self.assertEqual(result["username"],result["student_number"])
        self.assertEqual(apps[0]["status"],"approved")

    def test_online_application_credentials_are_private_and_reviewable(self):
        pdf_content=b"%PDF-1.4\nacademic transcript\n%%EOF"
        encoded=base64.b64encode(pdf_content).decode()
        _,application,_=self.request("POST","/api/applications",{
            "fn":"Jane","ln":"Applicant","email":"jane@example.test","phone":"+256700000099","dept_id":1,
            "prog_name":"BSc Computer Science","credentials":[{"filename":"results.pdf","content_base64":encoded}],
        },opener=build_opener())
        with server.connect() as db:
            saved=server.read_table(db,"applications")[0]
            self.assertEqual(saved["documents"][0]["filename"],"results.pdf")
            self.assertNotIn("content_base64",json.dumps(saved))
        with self.assertRaises(HTTPError) as error:
            self.request("GET",f"/api/applications/{application['id']}/documents/1/download",opener=build_opener())
        self.assertEqual(error.exception.code,401)

        self.enable_admin_session()
        with self.assertRaises(HTTPError) as error:
            self.request("POST","/api/admissions",{"fn":"Jane","ln":"Applicant","dept_id":1,"programme":"BSc Computer Science","year_of_study":1,"application_id":application["id"]})
        self.assertEqual(error.exception.code,409)
        status,review,_=self.request("PATCH",f"/api/applications/{application['id']}/review",{"review_status":"eligible","review_note":"Credentials confirmed."})
        self.assertEqual(status,200)
        self.assertEqual(review["review_status"],"eligible")
        status,download,_=self.request("GET",f"/api/applications/{application['id']}/documents/1/download")
        self.assertEqual(status,200)
        self.assertEqual(download,pdf_content)

    def test_application_without_credentials_cannot_be_marked_eligible(self):
        _,application,_=self.request("POST","/api/applications",{
            "fn":"Sam","ln":"Applicant","email":"sam@example.test","phone":"+256700000077","dept_id":1,
            "prog_name":"BSc Computer Science",
        },opener=build_opener())
        self.enable_admin_session()
        with self.assertRaises(HTTPError) as error:
            self.request("PATCH",f"/api/applications/{application['id']}/review",{"review_status":"eligible"})
        self.assertEqual(error.exception.code,400)

    def test_application_can_be_recommended_for_an_alternative_programme(self):
        pdf=base64.b64encode(b"%PDF-1.4\ntranscript\n%%EOF").decode()
        _,application,_=self.request("POST","/api/applications",{
            "fn":"Alex","ln":"Candidate","email":"alex@example.test","phone":"+256700000088","dept_id":1,
            "prog_name":"BSc Computer Science","credentials":[{"filename":"certificate.pdf","content_base64":pdf}],
        },opener=build_opener())
        self.enable_admin_session()
        _,review,_=self.request("PATCH",f"/api/applications/{application['id']}/review",{
            "review_status":"alternative_recommended","recommended_dept_id":2,
            "recommended_program":"Bachelor of Business Administration","review_note":"Recommended based on qualifications.",
        })
        self.assertEqual(review["review_status"],"alternative_recommended")
        _,admission,_=self.request("POST","/api/admissions",{
            "fn":"Alex","ln":"Candidate","dept_id":1,"programme":"BSc Computer Science","year_of_study":1,
            "application_id":application["id"],
        })
        with server.connect() as db:
            student=server.read_table(db,"students")[0]
        self.assertEqual(student["dept_id"],2)
        self.assertEqual(student["programme"],"Bachelor of Business Administration")

    def test_student_can_upload_and_download_own_assignment_file(self):
        with server.connect() as db:
            users=server.read_table(db,"users")
            users.append({"id":2,"username":"student1","password":server.password_hash("Student-Password-55"),"full_name":"Test Student","email":"student@nuu.ac.ug","role_id":2,"role_slug":"student","department_id":1,"status":"active","must_change_pass":False})
            server.write_table(db,"users",users)
            server.write_table(db,"students",[{"id":1,"user_id":2,"student_number":"NUU-001","dept_id":1,"status":"active"}])
            server.write_table(db,"assignments",[{"id":1,"title":"Lab report","course_id":1,"created_by":3,"due_date":"2099-01-01"}])
            server.write_table(db,"registrations",[{"id":1,"student_id":1,"course_id":1,"status":"approved"}])
        student=build_opener(HTTPCookieProcessor(http.cookiejar.CookieJar()))
        self.request("POST","/api/auth/login",{"username":"student1","password":"Student-Password-55"},opener=student)
        payload={"assignment_id":1,"filename":"report.txt","content_base64":base64.b64encode(b"completed work").decode(),"comments":"Ready for review"}
        status,result,_=self.request("POST","/api/submissions",payload,opener=student)
        self.assertEqual(status,201)
        download=self.request("GET",f"/api/submissions/{result['submission']['id']}/download",opener=student)
        self.assertEqual(download[1],b"completed work")
        with self.assertRaises(HTTPError) as error:
            self.request("POST","/api/submissions",payload,opener=student)
        self.assertEqual(error.exception.code,409)

    def test_rejects_invalid_table_payload(self):
        self.enable_admin_session()
        with self.assertRaises(HTTPError) as error:
            self.request("PUT","/api/tables/books",{"id":1})
        self.assertEqual(error.exception.code,400)

    def test_record_create_update_delete_are_server_side(self):
        self.enable_admin_session()
        status,created,_=self.request("POST","/api/tables/courses",{"code":"CS9901","name":"Server API Test","dept_id":1,"year":4,"semester":2,"credits":3,"max":30,"status":"active"})
        self.assertEqual(status,201)
        updated=self.request("PATCH",f"/api/tables/courses/{created['id']}",{"status":"inactive"})
        self.assertEqual(updated[1]["status"],"inactive")
        self.assertIn(created["id"],[row["id"] for row in self.request("GET","/api/tables/courses")[1]])
        deleted=self.request("DELETE",f"/api/tables/courses/{created['id']}")
        self.assertEqual(deleted[1]["deleted"],created["id"])

    def test_serves_existing_frontend(self):
        with urlopen(self.base + "/") as response:
            self.assertEqual(response.status,200)
            html=response.read()
            self.assertIn(b"AFRICAN ARK COLLEGE OF MANAGEMENT SCIENCES",html)
            self.assertNotIn(b"admin123",html)


if __name__ == "__main__":
    unittest.main()
