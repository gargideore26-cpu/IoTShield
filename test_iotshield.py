"""
Automated tests for the IoTShield back end.   Run:  python test_iotshield.py

Uses a temporary database, so your real data is never touched.
"""
import base64
import os
import re
import sqlite3
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

_tmp = tempfile.mkdtemp()
os.environ["IOTSHIELD_DB_PATH"] = os.path.join(_tmp, "test.db")
os.environ["IOTSHIELD_INSTANCE_DIR"] = os.path.join(_tmp, "instance")
os.environ["IOTSHIELD_ADMIN_USER"] = "tester"
os.environ["IOTSHIELD_ADMIN_PASSWORD"] = "test-password"
# Force email OTP into its no-Gmail-configured fallback path regardless of what the real .env
# file has in it (app.py's load_env_file() only fills in variables that aren't already set, so
# setting these - even to empty strings - stops your real Gmail credentials from ever being used
# here, and keeps every test run offline and deterministic).
os.environ["IOTSHIELD_ADMIN_EMAIL"] = ""
os.environ["IOTSHIELD_SMTP_EMAIL"] = ""
os.environ["IOTSHIELD_SMTP_PASSWORD"] = ""

import io  # noqa: E402
import sqlite3  # noqa: E402

import app as iotshield  # noqa: E402
from utils import crypto  # noqa: E402
from utils import custody, shamir  # noqa: E402
from utils import database as dbu  # noqa: E402
from utils import database as dbu  # noqa: E402


class IoTShieldTests(unittest.TestCase):
    def setUp(self):
        # every test gets a clean slate, so one test's failed attempts never lock out the next
        iotshield.failed_logins.clear()
        iotshield.failed_device_auth.clear()
        iotshield.failed_custody.clear()
        iotshield.pending_email_codes.clear()
        self.client = iotshield.app.test_client()
        self.login()

    # -- helpers ----------------------------------------------------------
    def login(self, password="test-password"):
        """Log in through BOTH steps: password, then the code shown in the fallback box
        (no real Gmail is configured in tests, so the code always ends up on the page)."""
        page = self.client.get("/login").get_data(as_text=True)
        token = re.search(r'name="csrf_token" value="([0-9a-f]+)"', page).group(1)
        response = self.client.post("/login", data={"username": "tester", "password": password,
                                                    "csrf_token": token})
        if password == "test-password":
            code = self.current_fallback_code(self.client)
            response = self.client.post("/login", data={"code": code, "csrf_token": token})
        # logging in starts a fresh session, so read the new CSRF token from a page
        page = self.client.get("/dashboard").get_data(as_text=True)
        match = re.search(r'name="csrf-token" content="([0-9a-f]+)"', page)
        self.token = match.group(1) if match else token
        return response

    @staticmethod
    def current_fallback_code(client):
        page = client.get("/login").get_data(as_text=True)
        match = re.search(r'class="fallback-code-value">(\d{6})<', page)
        return match.group(1) if match else None

    def post(self, url, payload=None, delete=False):
        method = self.client.delete if delete else self.client.post
        return method(url, json=payload or {}, headers={"X-CSRF-Token": self.token})

    def secret_of(self, device_id):
        with iotshield.app.app_context():
            row = iotshield.find_device(iotshield.get_db(), device_id)
            return iotshield.vault.decrypt(row["secret_key"])

    def challenge_for(self, device_id):
        return self.post("/api/device/challenge", {"device_id": device_id}).get_json()["challenge"]

    def stats(self):
        return self.client.get("/api/stats").get_json()

    # -- tests ------------------------------------------------------------
    def test_01_login_and_dashboard(self):
        self.assertEqual(self.client.get("/dashboard").status_code, 200)
        anonymous = iotshield.app.test_client()
        self.assertEqual(anonymous.get("/dashboard").status_code, 302)
        self.assertEqual(anonymous.get("/api/devices").status_code, 401)

    def test_02_wrong_password_rejected(self):
        client = iotshield.app.test_client()
        page = client.get("/login").get_data(as_text=True)
        token = re.search(r'name="csrf_token" value="([0-9a-f]+)"', page).group(1)
        response = client.post("/login", data={"username": "tester", "password": "nope",
                                               "csrf_token": token})
        self.assertIn("Invalid username or password", response.get_data(as_text=True))

    def test_03_demo_data_present(self):
        devices = self.client.get("/api/devices").get_json()["devices"]
        self.assertGreaterEqual(len(devices), 4)
        self.assertTrue(all(device["is_demo"] for device in devices[:4]))
        self.assertGreater(self.stats()["success_attempts"], 10)

    def test_04_add_device_and_no_secret_leak(self):
        response = self.post("/api/devices", {"device_id": "lock-005",
                                              "device_name": "Door Lock", "device_type": "Smart Lock"})
        self.assertEqual(response.status_code, 201)
        with iotshield.app.app_context():
            row = iotshield.find_device(iotshield.get_db(), "LOCK-005")
            self.assertIsNotNone(row)
            plain = iotshield.vault.decrypt(row["secret_key"])
            self.assertNotEqual(row["secret_key"], plain)        # encrypted at rest
            self.assertEqual(len(plain), 64)
        for url in ("/api/devices", "/api/devices/LOCK-005", "/api/stats", "/api/logs",
                    "/devices", "/devices/LOCK-005", "/dashboard", "/authenticate", "/logs"):
            self.assertNotIn(plain, self.client.get(url).get_data(as_text=True), url)
        duplicate = self.post("/api/devices", {"device_id": "LOCK-005", "device_name": "X1",
                                               "device_type": "Y1"})
        self.assertEqual(duplicate.status_code, 409)
        self.assertEqual(self.post("/api/devices", {"device_id": "", "device_name": "",
                                                    "device_type": ""}).status_code, 400)

    def test_05_challenges_are_random(self):
        first, second = self.challenge_for("TEMP-001"), self.challenge_for("TEMP-001")
        self.assertRegex(first, r"^[0-9a-f]{64}$")
        self.assertNotEqual(first, second)

    def test_06_hmac_matches_reference_implementation(self):
        import hashlib
        import hmac
        challenge = self.challenge_for("CAM-002")
        response = self.post("/api/simulate/hmac", {"device_id": "CAM-002", "challenge": challenge})
        reference = hmac.new(bytes.fromhex(self.secret_of("CAM-002")), challenge.encode(),
                             hashlib.sha256).hexdigest()
        self.assertEqual(response.get_json()["hmac"], reference)

    def test_07_correct_hmac_succeeds_and_is_logged(self):
        before = self.stats()
        challenge = self.challenge_for("TEMP-001")
        digest = crypto.compute_hmac(self.secret_of("TEMP-001"), challenge)
        response = self.post("/api/device/verify", {"device_id": "TEMP-001",
                                                    "challenge": challenge, "hmac": digest})
        body = response.get_json()
        self.assertEqual((response.status_code, body["success"], body["access"]), (200, True, "GRANTED"))
        after = self.stats()
        self.assertEqual(after["success_attempts"], before["success_attempts"] + 1)
        latest = self.client.get("/api/logs").get_json()["logs"][0]
        self.assertEqual((latest["device_id"], latest["result"], latest["challenge"]),
                         ("TEMP-001", "SUCCESS", challenge))
        device = self.client.get("/api/devices/TEMP-001").get_json()["device"]
        self.assertEqual(device["status"], "online")

    def test_08_wrong_hmac_fails(self):
        before = self.stats()
        challenge = self.challenge_for("MOT-003")
        response = self.post("/api/device/verify", {"device_id": "MOT-003", "challenge": challenge,
                                                    "hmac": "ab" * 32})
        body = response.get_json()
        self.assertEqual((response.status_code, body["success"], body["access"]), (403, False, "DENIED"))
        self.assertEqual(body["hmac"], "Invalid")
        self.assertEqual(self.stats()["failed_attempts"], before["failed_attempts"] + 1)
        self.assertEqual(self.client.get("/api/logs?result=failed").get_json()["logs"][0]["result"], "FAILED")

    def test_09_wrong_key_fails(self):
        challenge = self.challenge_for("GPS-004")
        forged = crypto.compute_hmac(crypto.generate_secret_key(), challenge)
        response = self.post("/api/device/verify", {"device_id": "GPS-004", "challenge": challenge,
                                                    "hmac": forged})
        self.assertEqual(response.status_code, 403)

    def test_10_replay_is_blocked(self):
        challenge = self.challenge_for("TEMP-001")
        digest = crypto.compute_hmac(self.secret_of("TEMP-001"), challenge)
        payload = {"device_id": "TEMP-001", "challenge": challenge, "hmac": digest}
        self.assertEqual(self.post("/api/device/verify", payload).status_code, 200)
        replay = self.post("/api/device/verify", payload)
        self.assertEqual(replay.status_code, 403)
        self.assertIn("replay", replay.get_json()["reason"].lower())

    def test_11_challenge_bound_to_device(self):
        challenge = self.challenge_for("TEMP-001")
        digest = crypto.compute_hmac(self.secret_of("CAM-002"), challenge)
        response = self.post("/api/device/verify", {"device_id": "CAM-002", "challenge": challenge,
                                                    "hmac": digest})
        self.assertEqual(response.status_code, 403)

    def test_12_expired_challenge_rejected(self):
        challenge = self.challenge_for("TEMP-001")
        with iotshield.app.app_context():
            db = iotshield.get_db()
            db.execute("UPDATE challenges SET created_at = '2000-01-01T00:00:00' WHERE challenge = ?",
                       (challenge,))
            db.commit()
        digest = crypto.compute_hmac(self.secret_of("TEMP-001"), challenge)
        response = self.post("/api/device/verify", {"device_id": "TEMP-001", "challenge": challenge,
                                                    "hmac": digest})
        self.assertEqual(response.status_code, 403)
        self.assertIn("expired", response.get_json()["reason"].lower())

    def test_13_disabled_device_denied_then_enabled(self):
        self.post("/api/devices/CAM-002/toggle")
        self.assertEqual(self.post("/api/device/challenge", {"device_id": "CAM-002"}).status_code, 403)
        self.post("/api/devices/CAM-002/toggle")
        self.assertEqual(self.post("/api/device/challenge", {"device_id": "CAM-002"}).status_code, 200)

    def test_14_errors_are_friendly(self):
        self.assertEqual(self.post("/api/device/challenge", {"device_id": "NOPE-999"}).get_json()["error"],
                         "Device not found.")
        self.assertEqual(self.post("/api/device/verify", {"device_id": "TEMP-001"}).get_json()["error"],
                         "Please enter all required fields.")
        self.assertEqual(self.client.get("/devices/NOPE-999").status_code, 404)
        self.assertNotIn("Traceback", self.client.get("/nothing-here").get_data(as_text=True))

    def test_15_csrf_enforced(self):
        response = self.client.post("/api/devices", json={"device_id": "EVIL-1", "device_name": "xx",
                                                          "device_type": "yy"})
        self.assertEqual(response.status_code, 400)

    def test_16_clear_logs_last(self):
        self.assertEqual(self.post("/api/logs", delete=True).status_code, 200)
        self.assertEqual(self.client.get("/api/logs").get_json()["logs"], [])


    # -- idle timeout / session rules -----------------------------------------
    def set_last_active(self, seconds_ago):
        with self.client.session_transaction() as sess:
            sess["last_active"] = time.time() - seconds_ago

    def get_last_active(self):
        with self.client.session_transaction() as sess:
            return sess.get("last_active")

    def test_17_idle_for_5_minutes_signs_out(self):
        self.set_last_active(301)
        response = self.client.get("/api/devices")
        self.assertEqual(response.status_code, 401)
        self.assertIn("inactivity", response.get_json()["error"])
        page = self.client.get("/dashboard")                 # session was cleared
        self.assertEqual(page.status_code, 302)
        self.assertIn("/login", page.headers["Location"])

    def test_18_idle_page_load_redirects_with_notice(self):
        self.set_last_active(400)
        response = self.client.get("/devices")
        self.assertEqual(response.status_code, 302)
        self.assertIn("expired=1", response.headers["Location"])
        login = self.client.get("/login?expired=1").get_data(as_text=True)
        self.assertIn("5 minutes of inactivity", login)

    def test_19_background_polling_does_not_extend_session(self):
        self.set_last_active(200)
        self.assertEqual(self.client.get("/api/stats").status_code, 200)     # dashboard auto-refresh
        self.assertEqual(self.client.get("/api/devices").status_code, 200)
        self.assertGreaterEqual(time.time() - self.get_last_active(), 199)   # unchanged
        self.assertEqual(self.post("/api/activity").status_code, 200)        # real activity
        self.assertLess(time.time() - self.get_last_active(), 5)

    def test_20_opening_a_page_counts_as_activity(self):
        self.set_last_active(250)
        self.assertEqual(self.client.get("/logs").status_code, 200)
        self.assertLess(time.time() - self.get_last_active(), 5)

    def test_21_session_cookie_is_not_persistent(self):
        client = iotshield.app.test_client()
        page = client.get("/login").get_data(as_text=True)
        token = re.search(r'name="csrf_token" value="([0-9a-f]+)"', page).group(1)
        response = client.post("/login", data={"username": "tester", "password": "test-password",
                                               "csrf_token": token})
        cookies = " ".join(response.headers.getlist("Set-Cookie")).lower()
        self.assertIn("session=", cookies)
        self.assertNotIn("expires=", cookies)                # browser-session cookie: gone when the browser closes

    def test_22_logout_ends_session(self):
        self.client.get("/logout")
        self.assertEqual(self.client.get("/api/devices").status_code, 401)

    # -- two-factor authentication (a code emailed to the admin) -----------------------
    def test_23_correct_password_then_wrong_code_is_rejected(self):
        client = iotshield.app.test_client()
        page = client.get("/login").get_data(as_text=True)
        token = re.search(r'name="csrf_token" value="([0-9a-f]+)"', page).group(1)
        client.post("/login", data={"username": "tester", "password": "test-password", "csrf_token": token})
        response = client.post("/login", data={"code": "000000", "csrf_token": token})
        body = response.get_data(as_text=True)
        self.assertIn("Invalid code", body)
        self.assertIn("6-digit code", body)          # still on the code-entry stage, not back to credentials
        self.assertEqual(client.get("/api/devices").status_code, 401)   # not logged in yet

    def test_24_correct_password_and_code_logs_in(self):
        client = iotshield.app.test_client()
        page = client.get("/login").get_data(as_text=True)
        token = re.search(r'name="csrf_token" value="([0-9a-f]+)"', page).group(1)
        client.post("/login", data={"username": "tester", "password": "test-password", "csrf_token": token})
        code = self.current_fallback_code(client)
        response = client.post("/login", data={"code": code, "csrf_token": token})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(client.get("/api/devices").status_code, 200)

    def test_25_a_used_code_does_not_work_for_a_later_login(self):
        client = iotshield.app.test_client()
        page = client.get("/login").get_data(as_text=True)
        token = re.search(r'name="csrf_token" value="([0-9a-f]+)"', page).group(1)
        client.post("/login", data={"username": "tester", "password": "test-password", "csrf_token": token})
        old_code = self.current_fallback_code(client)
        self.assertEqual(client.post("/login", data={"code": old_code, "csrf_token": token}).status_code, 302)
        client.get("/logout")
        # log in again: a fresh random code is issued, so the old (already-used) one must not work
        page = client.get("/login").get_data(as_text=True)
        token = re.search(r'name="csrf_token" value="([0-9a-f]+)"', page).group(1)
        client.post("/login", data={"username": "tester", "password": "test-password", "csrf_token": token})
        response = client.post("/login", data={"code": old_code, "csrf_token": token})
        self.assertIn("Invalid code", response.get_data(as_text=True))
        self.assertEqual(client.get("/api/devices").status_code, 401)

    def test_26_wrong_code_counts_towards_the_lockout(self):
        client = iotshield.app.test_client()
        page = client.get("/login").get_data(as_text=True)
        token = re.search(r'name="csrf_token" value="([0-9a-f]+)"', page).group(1)
        client.post("/login", data={"username": "tester", "password": "test-password", "csrf_token": token})
        for _ in range(iotshield.MAX_LOGIN_FAILURES):
            client.post("/login", data={"code": "000000", "csrf_token": token})
        response = client.post("/login", data={"code": "111111", "csrf_token": token})
        self.assertIn("Too many failed attempts", response.get_data(as_text=True))

    def test_27_cancel_returns_to_credentials_stage(self):
        client = iotshield.app.test_client()
        page = client.get("/login").get_data(as_text=True)
        token = re.search(r'name="csrf_token" value="([0-9a-f]+)"', page).group(1)
        client.post("/login", data={"username": "tester", "password": "test-password", "csrf_token": token})
        client.post("/login", data={"cancel": "1", "csrf_token": token})
        page = client.get("/login").get_data(as_text=True)
        self.assertIn('name="password"', page)   # credentials stage again
        self.assertNotIn("6-digit code", page)

    # -- rate limiting on device authentication -------------------------------------------
    def test_28_device_auth_locks_after_repeated_failures(self):
        for _ in range(iotshield.MAX_DEVICE_AUTH_FAILURES):
            challenge = self.challenge_for("TEMP-001")
            response = self.post("/api/device/verify", {"device_id": "TEMP-001", "challenge": challenge, "hmac": "ab" * 32})
            self.assertEqual(response.status_code, 403)
        locked = self.post("/api/device/verify", {"device_id": "TEMP-001",
                                                  "challenge": self.challenge_for("TEMP-001"), "hmac": "ab" * 32})
        self.assertEqual(locked.status_code, 429)
        self.assertIn("Too many failed attempts", locked.get_json()["message"])
        # even the CORRECT hmac is refused while locked
        challenge = self.challenge_for("TEMP-001")
        digest = crypto.compute_hmac(self.secret_of("TEMP-001"), challenge)
        still_locked = self.post("/api/device/verify", {"device_id": "TEMP-001", "challenge": challenge, "hmac": digest})
        self.assertEqual(still_locked.status_code, 429)

    def test_29_device_lockout_is_independent_per_device(self):
        for _ in range(iotshield.MAX_DEVICE_AUTH_FAILURES):
            challenge = self.challenge_for("TEMP-001")
            self.post("/api/device/verify", {"device_id": "TEMP-001", "challenge": challenge, "hmac": "ab" * 32})
        # CAM-002 is untouched and should authenticate normally
        challenge = self.challenge_for("CAM-002")
        digest = crypto.compute_hmac(self.secret_of("CAM-002"), challenge)
        response = self.post("/api/device/verify", {"device_id": "CAM-002", "challenge": challenge, "hmac": digest})
        self.assertEqual(response.status_code, 200)

    def test_30_device_lockout_clears_after_a_success(self):
        for _ in range(iotshield.MAX_DEVICE_AUTH_FAILURES - 1):
            challenge = self.challenge_for("MOT-003")
            self.post("/api/device/verify", {"device_id": "MOT-003", "challenge": challenge, "hmac": "ab" * 32})
        challenge = self.challenge_for("MOT-003")
        digest = crypto.compute_hmac(self.secret_of("MOT-003"), challenge)
        self.assertEqual(self.post("/api/device/verify",
                                   {"device_id": "MOT-003", "challenge": challenge, "hmac": digest}).status_code, 200)
        self.assertNotIn("MOT-003", iotshield.failed_device_auth)
        challenge = self.challenge_for("MOT-003")            # the counter reset, so this is not locked
        response = self.post("/api/device/verify", {"device_id": "MOT-003", "challenge": challenge, "hmac": "ab" * 32})
        self.assertEqual(response.status_code, 403)

    # -- the on-page fallback code (used whenever no real Gmail is configured) -----------------
    def test_31_fallback_code_shown_when_email_not_configured(self):
        client = iotshield.app.test_client()
        page = client.get("/login").get_data(as_text=True)
        token = re.search(r'name="csrf_token" value="([0-9a-f]+)"', page).group(1)
        client.post("/login", data={"username": "tester", "password": "test-password", "csrf_token": token})
        page = client.get("/login").get_data(as_text=True)
        self.assertIn("Could not send the email", page)
        code = self.current_fallback_code(client)
        self.assertIsNotNone(code)
        self.assertEqual(len(code), 6)

    def test_32_fallback_code_can_be_hidden(self):
        original = iotshield.EMAIL_OTP_SHOW_FALLBACK
        iotshield.EMAIL_OTP_SHOW_FALLBACK = False
        try:
            client = iotshield.app.test_client()
            page = client.get("/login").get_data(as_text=True)
            token = re.search(r'name="csrf_token" value="([0-9a-f]+)"', page).group(1)
            response = client.post("/login", data={"username": "tester", "password": "test-password",
                                                    "csrf_token": token}, follow_redirects=True)
            body = response.get_data(as_text=True)
            self.assertNotIn("fallback-code-value", body)
            self.assertIn("Could not send the login code by email", body)
        finally:
            iotshield.EMAIL_OTP_SHOW_FALLBACK = original

    def test_33_resend_gives_a_new_code_and_has_a_cooldown(self):
        client = iotshield.app.test_client()
        page = client.get("/login").get_data(as_text=True)
        token = re.search(r'name="csrf_token" value="([0-9a-f]+)"', page).group(1)
        client.post("/login", data={"username": "tester", "password": "test-password", "csrf_token": token})
        first_code = self.current_fallback_code(client)

        cooldown_response = client.post("/login", data={"resend": "1", "csrf_token": token}, follow_redirects=True)
        self.assertIn("wait a few seconds", cooldown_response.get_data(as_text=True))

        with client.session_transaction() as sess:
            pending_id = sess["pending_id"]
        iotshield.pending_email_codes[pending_id]["last_sent"] -= iotshield.CODE_RESEND_COOLDOWN_SECONDS + 1
        resend_response = client.post("/login", data={"resend": "1", "csrf_token": token}, follow_redirects=True)
        self.assertIn("here is your new code", resend_response.get_data(as_text=True))

        second_code = self.current_fallback_code(client)
        self.assertNotEqual(first_code, second_code)
        self.assertIn("Invalid code", client.post("/login", data={"code": first_code, "csrf_token": token})
                      .get_data(as_text=True))
        self.assertEqual(client.post("/login", data={"code": second_code, "csrf_token": token}).status_code, 302)

    def test_34_code_expires_after_its_lifetime(self):
        client = iotshield.app.test_client()
        page = client.get("/login").get_data(as_text=True)
        token = re.search(r'name="csrf_token" value="([0-9a-f]+)"', page).group(1)
        client.post("/login", data={"username": "tester", "password": "test-password", "csrf_token": token})
        with client.session_transaction() as sess:
            pending_id = sess["pending_id"]
        entry = iotshield.pending_email_codes[pending_id]
        code, entry["expires"] = entry["code"], time.time() - 1
        response = client.post("/login", data={"code": code, "csrf_token": token})
        self.assertIn('name="password"', response.get_data(as_text=True))   # bounced back to credentials
        self.assertEqual(client.get("/api/devices").status_code, 401)

    def test_35_mask_email_hides_most_of_the_local_part(self):
        self.assertEqual(iotshield.mask_email("gargi@gmail.com"), "ga***@gmail.com")
        self.assertEqual(iotshield.mask_email("ab@gmail.com"), "a*@gmail.com")

    def test_36_email_is_sent_via_gmail_smtp_when_configured(self):
        original = (iotshield.ADMIN_EMAIL, iotshield.SMTP_EMAIL, iotshield.SMTP_PASSWORD)
        iotshield.ADMIN_EMAIL, iotshield.SMTP_EMAIL, iotshield.SMTP_PASSWORD = \
            "admin@example.com", "sender@gmail.com", "app-password"
        try:
            with mock.patch("smtplib.SMTP") as smtp_class:
                server = smtp_class.return_value.__enter__.return_value
                client = iotshield.app.test_client()
                page = client.get("/login").get_data(as_text=True)
                token = re.search(r'name="csrf_token" value="([0-9a-f]+)"', page).group(1)
                client.post("/login", data={"username": "tester", "password": "test-password",
                                            "csrf_token": token})
                server.login.assert_called_once_with("sender@gmail.com", "app-password")
                self.assertTrue(server.send_message.called)
                page = client.get("/login").get_data(as_text=True)
                self.assertNotIn("Could not send the email", page)   # sent -> no fallback needed
        finally:
            iotshield.ADMIN_EMAIL, iotshield.SMTP_EMAIL, iotshield.SMTP_PASSWORD = original

    def test_37_email_send_failure_falls_back_to_showing_the_code(self):
        original = (iotshield.ADMIN_EMAIL, iotshield.SMTP_EMAIL, iotshield.SMTP_PASSWORD)
        iotshield.ADMIN_EMAIL, iotshield.SMTP_EMAIL, iotshield.SMTP_PASSWORD = \
            "admin@example.com", "sender@gmail.com", "wrong-password"
        try:
            with mock.patch("smtplib.SMTP", side_effect=OSError("network is unreachable")):
                client = iotshield.app.test_client()
                page = client.get("/login").get_data(as_text=True)
                token = re.search(r'name="csrf_token" value="([0-9a-f]+)"', page).group(1)
                client.post("/login", data={"username": "tester", "password": "test-password",
                                            "csrf_token": token})
                page = client.get("/login").get_data(as_text=True)
                self.assertIn("Could not send the email", page)
        finally:
            iotshield.ADMIN_EMAIL, iotshield.SMTP_EMAIL, iotshield.SMTP_PASSWORD = original

    def test_38_password_success_redirects_and_a_refresh_never_resends_the_email(self):
        # Regression test: a real Gmail send takes a few seconds, and this route used to render
        # the "check your email" page directly from the password POST - so simply reloading that
        # page (F5) re-submitted the password form and fired off another email every time.
        original = (iotshield.ADMIN_EMAIL, iotshield.SMTP_EMAIL, iotshield.SMTP_PASSWORD)
        iotshield.ADMIN_EMAIL, iotshield.SMTP_EMAIL, iotshield.SMTP_PASSWORD = \
            "admin@example.com", "sender@gmail.com", "app-password"
        try:
            with mock.patch("smtplib.SMTP") as smtp_class:
                server = smtp_class.return_value.__enter__.return_value
                client = iotshield.app.test_client()
                page = client.get("/login").get_data(as_text=True)
                token = re.search(r'name="csrf_token" value="([0-9a-f]+)"', page).group(1)
                response = client.post("/login", data={"username": "tester", "password": "test-password",
                                                        "csrf_token": token})
                self.assertEqual(response.status_code, 302)   # Post/Redirect/Get, not a direct render
                self.assertEqual(server.send_message.call_count, 1)
                for _ in range(3):                            # simulate refreshing the page a few times
                    client.get("/login")
                self.assertEqual(server.send_message.call_count, 1)   # still only the one email
        finally:
            iotshield.ADMIN_EMAIL, iotshield.SMTP_EMAIL, iotshield.SMTP_PASSWORD = original



    # -- signed firmware updates (Ed25519) --------------------------------------
    def firmware(self):
        return self.client.get("/api/firmware").get_json()

    def add_device(self, device_id):
        self.post("/api/devices", {"device_id": device_id, "device_name": "Firmware Test", "device_type": "Sensor"})

    def publish(self, version, image=b"new firmware image", notes="test"):
        return self.client.post("/api/firmware", headers={"X-CSRF-Token": self.token},
                                data={"version": version, "notes": notes,
                                      "file": (io.BytesIO(image), f"fw-{version}.bin")},
                                content_type="multipart/form-data")

    def next_version(self):
        major = crypto.parse_version(self.firmware()["latest"])[0]
        return f"{major + 1}.0.0"

    def simulate(self, device_id, version="", attack="none"):
        return self.post("/api/simulate/firmware-install",
                         {"device_id": device_id, "version": version, "attack": attack}).get_json()

    def installed(self, device_id):
        return self.client.get(f"/api/devices/{device_id}").get_json()["device"]["firmware_version"]

    def report(self, device_id, version, outcome="installed", key=None, challenge=None):
        challenge = challenge or self.challenge_for(device_id)
        proof = crypto.compute_hmac(key or self.secret_of(device_id),
                                    crypto.firmware_report_message(challenge, version, outcome))
        return self.client.post("/api/device/firmware/report", json={
            "device_id": device_id, "version": version, "outcome": outcome,
            "challenge": challenge, "hmac": proof}), challenge

    def test_39_signatures_detect_any_change(self):
        signer = crypto.FirmwareSigner.generate()
        image = b"firmware bytes" * 100
        signed = signer.sign_release("2.1.0", image)
        public = signer.public_key_hex
        self.assertTrue(crypto.verify_firmware(public, "2.1.0", image, signed["signature"])[0])
        tampered = image[:50] + bytes([image[50] ^ 1]) + image[51:]
        self.assertFalse(crypto.verify_firmware(public, "2.1.0", tampered, signed["signature"])[0])
        self.assertFalse(crypto.verify_firmware(public, "2.2.0", image, signed["signature"])[0])   # relabel
        other = crypto.FirmwareSigner.generate().public_key_hex
        self.assertFalse(crypto.verify_firmware(other, "2.1.0", image, signed["signature"])[0])     # wrong key
        self.assertFalse(crypto.verify_firmware(public, "2.1.0", image, "zz")[0])                   # malformed

    def test_40_versions_compare_numerically(self):
        self.assertGreater(crypto.parse_version("1.10.0"), crypto.parse_version("1.9.9"))
        for bad in ("1.2", "v1.2.3", "1.2.3.4", "01.2.3", "", "1.2.x"):
            self.assertIsNone(crypto.parse_version(bad), bad)

    def test_41_demo_releases_are_genuinely_signed(self):
        data = self.firmware()
        self.assertTrue({"1.0.0", "1.1.0", "1.2.0"} <= {r["version"] for r in data["releases"]})
        for release in data["releases"]:
            image = self.client.get(f"/api/device/firmware/{release['version']}/image").data
            self.assertEqual(crypto.sha256_hex(image), release["sha256"])
            self.assertTrue(crypto.verify_firmware(data["public_key"], release["version"], image,
                                                   release["signature"])[0])

    def test_42_private_key_is_never_exposed(self):
        with open(os.path.join(os.environ["IOTSHIELD_INSTANCE_DIR"], "firmware_signing.key")) as key_file:
            pem = key_file.read()
        self.assertIn("PRIVATE KEY", pem)
        body = self.client.get("/api/firmware").get_data(as_text=True)
        body += self.client.get("/api/device/firmware/latest").get_data(as_text=True)
        self.assertNotIn("PRIVATE", body)
        self.assertNotIn(pem.splitlines()[1], body)

    def test_43_publish_signs_and_becomes_latest(self):
        version = self.next_version()
        response = self.publish(version, b"\x7fELF fake firmware")
        self.assertEqual(response.status_code, 201)
        manifest = iotshield.app.test_client().get("/api/device/firmware/latest").get_json()  # no login needed
        self.assertEqual(manifest["version"], version)
        image = iotshield.app.test_client().get(manifest["image_url"]).data
        self.assertEqual(image, b"\x7fELF fake firmware")
        self.assertTrue(crypto.verify_firmware(self.firmware()["public_key"], version, image, manifest["signature"])[0])

    def test_44_publish_validation(self):
        latest = self.firmware()["latest"]
        self.assertEqual(self.publish(latest).status_code, 409)       # duplicate
        self.assertEqual(self.publish("0.0.1").status_code, 409)      # older than latest
        self.assertEqual(self.publish("1.2").status_code, 400)        # bad format
        self.assertEqual(self.publish(self.next_version(), b"").status_code, 400)   # empty file
        no_csrf = self.client.post("/api/firmware", data={"version": "99.0.0",
                                   "file": (io.BytesIO(b"x"), "x.bin")}, content_type="multipart/form-data")
        self.assertEqual(no_csrf.status_code, 400)
        anonymous = iotshield.app.test_client().get("/api/firmware")
        self.assertEqual(anonymous.status_code, 401)

    def test_45_genuine_update_installs(self):
        self.add_device("FW-001")
        latest = self.firmware()["latest"]
        result = self.simulate("FW-001", latest)
        self.assertTrue(result["success"], result)
        self.assertEqual(self.installed("FW-001"), latest)
        event = self.firmware()["events"][0]
        self.assertEqual((event["device_id"], event["result"]), ("FW-001", "INSTALLED"))

    def test_46_malicious_updates_are_refused(self):
        self.add_device("FW-002")
        latest = self.firmware()["latest"]
        for attack in ("tamper", "forged", "relabel"):
            result = self.simulate("FW-002", latest, attack)
            self.assertFalse(result["success"], attack)
            self.assertIn("Signature check failed", result["reason"])
            self.assertIsNone(self.installed("FW-002"), attack)
            self.assertEqual(self.firmware()["events"][0]["result"], "REJECTED")

    def test_47_downgrade_is_blocked_even_with_a_valid_signature(self):
        self.add_device("FW-003")
        self.simulate("FW-003", self.firmware()["latest"])
        current = self.installed("FW-003")
        result = self.simulate("FW-003", attack="downgrade")
        self.assertFalse(result["success"])
        self.assertIn("Rollback blocked", result["reason"])
        self.assertTrue(any("signature valid" in step["text"] for step in result["steps"]))
        self.assertEqual(self.installed("FW-003"), current)

    def test_48_device_report_needs_a_valid_hmac(self):
        self.add_device("FW-004")
        response, challenge = self.report("FW-004", "1.1.0")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.installed("FW-004"), "1.1.0")
        # replaying the same signed report is refused
        replay = self.client.post("/api/device/firmware/report", json={
            "device_id": "FW-004", "version": "1.1.0", "outcome": "installed", "challenge": challenge,
            "hmac": crypto.compute_hmac(self.secret_of("FW-004"),
                                        crypto.firmware_report_message(challenge, "1.1.0", "installed"))})
        self.assertEqual(replay.status_code, 403)
        # someone without the device key cannot claim it was patched
        forged, _ = self.report("FW-004", "1.2.0", key=crypto.generate_secret_key())
        self.assertEqual(forged.status_code, 403)
        self.assertEqual(self.installed("FW-004"), "1.1.0")

    def test_49_device_report_enforces_rollback_and_known_versions(self):
        self.add_device("FW-005")
        self.report("FW-005", "1.2.0")
        self.assertEqual(self.report("FW-005", "1.0.0")[0].status_code, 409)    # downgrade
        self.assertEqual(self.report("FW-005", "77.7.7")[0].status_code, 409)   # never published
        self.assertEqual(self.installed("FW-005"), "1.2.0")
        rejected, _ = self.report("FW-005", "1.2.0", outcome="rejected")
        self.assertEqual(rejected.get_json()["recorded"], "REJECTED")
        self.assertEqual(self.firmware()["events"][0]["result"], "REJECTED")

    def test_50_fleet_status_and_old_database_upgrade(self):
        fleet = {d["device_id"]: d for d in self.firmware()["devices"]}
        self.assertEqual(fleet["MOT-003"]["firmware_status"], "outdated")
        self.add_device("FW-006")
        self.assertEqual({d["device_id"]: d for d in self.firmware()["devices"]}["FW-006"]["firmware_status"],
                         "unknown")
        path = os.path.join(_tmp, "old.db")
        old = sqlite3.connect(path)
        old.execute("CREATE TABLE devices (id INTEGER PRIMARY KEY, device_id TEXT NOT NULL UNIQUE,"
                    " device_name TEXT NOT NULL, device_type TEXT NOT NULL, secret_key TEXT NOT NULL,"
                    " status TEXT NOT NULL DEFAULT 'active', is_demo INTEGER NOT NULL DEFAULT 0,"
                    " created_at TEXT NOT NULL, last_authenticated TEXT)")
        old.commit()
        old.close()
        dbu.init_db(path, iotshield.vault, iotshield.signer)
        upgraded = dbu.connect(path)
        columns = {row["name"] for row in upgraded.execute("PRAGMA table_info(devices)")}
        releases = upgraded.execute("SELECT COUNT(*) FROM firmware_releases").fetchone()[0]
        upgraded.close()
        self.assertIn("firmware_version", columns)
        self.assertEqual(releases, 3)

    def test_52_refreshing_signs_out_and_returns_to_the_opening_screen(self):
        # base.html sends a reloaded page to /logout?reason=reload ...
        self.assertIn("reason=reload", self.client.get("/dashboard").get_data(as_text=True))
        response = self.client.get("/logout?reason=reload")
        self.assertEqual((response.status_code, response.headers["Location"]), (302, "/"))   # ... which lands on the splash
        self.assertEqual(self.client.get("/").status_code, 200)
        self.assertEqual(self.client.get("/dashboard").status_code, 302)                     # and the admin is signed out
        # the login page itself also bounces a reload back to the opening screen
        self.assertIn("nav.type === 'reload'", self.client.get("/login").get_data(as_text=True))
        # an idle sign-out still goes to the login page with its notice
        self.assertIn("/login", self.client.get("/logout?reason=idle").headers["Location"])

    def test_53_login_page_has_a_light_dark_toggle_on_every_stage(self):
        # the toggle script must not live inside a conditional block (it once only rendered on the
        # "email failed" screen), so check both login stages
        guest = iotshield.app.test_client()
        page = guest.get("/login").get_data(as_text=True)
        self.assertIn('id="themeToggle"', page)
        self.assertIn("localStorage.setItem('iotshield-theme'", page)
        token = re.search(r'name="csrf_token" value="([0-9a-f]+)"', page).group(1)
        guest.post("/login", data={"username": "tester", "password": "test-password", "csrf_token": token})
        code_stage = guest.get("/login").get_data(as_text=True)
        self.assertIn('id="code"', code_stage)                       # really is the 2FA stage
        self.assertIn('id="themeToggle"', code_stage)
        self.assertIn("localStorage.setItem('iotshield-theme'", code_stage)

    # -- key custody: Shamir shares, sealing, unsealing -------------------------
    PASSWORD = "test-password"

    def split(self, threshold=3, total=5, password=PASSWORD):
        return self.post("/api/custody/split", {"threshold": threshold, "total": total, "password": password})

    def test_54_split_needs_the_password_and_returns_shares_once(self):
        self.assertEqual(self.split(password="wrong").status_code, 403)
        self.assertEqual(self.split(threshold=1).status_code, 400)           # a threshold of 1 would make every share the key
        self.assertEqual(self.split(threshold=6, total=5).status_code, 400)  # cannot need more shares than exist
        response = self.split()
        body = response.get_json()
        self.assertEqual((response.status_code, body["threshold"], len(body["shares"])), (200, 3, 5))
        self.assertTrue(all(share.startswith("IOTS1-3-5-") for share in body["shares"]))
        status = self.client.get("/api/custody").get_json()                  # only counts are remembered, never the shares
        self.assertEqual((status["state"], status["shares"]["threshold"], status["shares"]["total"]), ("normal", 3, 5))
        self.assertNotIn(body["shares"][0], str(status))

    def test_55_any_three_shares_match_but_two_do_not(self):
        shares = self.split().get_json()["shares"]
        for combo in ([0, 1, 2], [0, 2, 4], [1, 3, 4]):
            result = self.post("/api/custody/verify", {"shares": "\n".join(shares[i] for i in combo)}).get_json()
            self.assertTrue(result["match"], combo)
        too_few = self.post("/api/custody/verify", {"shares": "\n".join(shares[:2])}).get_json()
        self.assertFalse(too_few["match"])
        self.assertIn("needs 3", too_few["message"])
        self.assertEqual(self.post("/api/custody/verify", {"shares": shares[0][:-3] + "abc"}).status_code, 400)   # typo caught
        self.assertEqual(self.post("/api/custody/verify", {"shares": "nothing here"}).status_code, 400)

    def test_56_verify_never_returns_the_key(self):
        shares = self.split().get_json()["shares"]
        raw = iotshield.vault.raw_key()
        text = self.post("/api/custody/verify", {"shares": "\n".join(shares[:3])}).get_data(as_text=True)
        for form in (raw.hex(), base64.urlsafe_b64encode(raw).decode(), str(int.from_bytes(raw, "big"))):
            self.assertNotIn(form, text)

    def test_57_seal_unseal_lifecycle(self):
        shares = self.split().get_json()["shares"]
        key_file = os.path.join(_tmp, "instance", "master.key")
        sealed_body = lambda items, **extra: {"shares": "\n".join(items), "password": self.PASSWORD, "confirm": "SEAL", **extra}
        try:
            # every safety check must stop the seal, and the key file must survive each refusal
            self.assertEqual(self.post("/api/custody/seal", sealed_body(shares[:3], confirm="seal")).status_code, 400)
            self.assertEqual(self.post("/api/custody/seal", sealed_body(shares[:3], password="nope")).status_code, 403)
            self.assertEqual(self.post("/api/custody/seal", sealed_body(shares[:2])).status_code, 400)       # cannot prove it can be undone
            stranger = shamir.format_share(shamir.split_secret(os.urandom(32), 3, 5)[0])
            self.assertEqual(self.post("/api/custody/seal", sealed_body(shares[:2] + [stranger])).status_code, 400)
            self.assertTrue(os.path.exists(key_file) and not iotshield.vault.sealed)

            self.assertEqual(self.post("/api/custody/seal", sealed_body(shares[1:4])).status_code, 200)
            self.assertTrue(iotshield.vault.sealed)
            self.assertFalse(os.path.exists(key_file))                                   # the key is off the disk

            # sealed: anything needing the key is refused up front, the rest of the app still works
            for url, payload in (("/api/device/challenge", {"device_id": "TEMP-001"}),
                                 ("/api/device/verify", {"device_id": "TEMP-001", "challenge": "a" * 64, "hmac": "b" * 64}),
                                 ("/api/devices", {"device_id": "LOCK-900", "device_name": "Door", "device_type": "Lock"})):
                response = self.post(url, payload)
                self.assertEqual(response.status_code, 503, url)
                self.assertTrue(response.get_json()["sealed"])
            self.assertEqual(self.client.get("/dashboard").status_code, 200)
            self.assertIn("sealed", self.client.get("/dashboard").get_data(as_text=True))   # the warning banner
            self.assertEqual(self.client.get("/api/custody").get_json()["state"], "sealed")
            self.assertEqual(self.split().status_code, 503)                              # nothing to split while sealed

            # unsealing: too few, wrong key and typos all fail; the right shares work
            self.assertEqual(self.post("/api/custody/unseal", {"shares": "\n".join(shares[:2])}).status_code, 400)
            self.assertEqual(self.post("/api/custody/unseal", {"shares": "\n".join(shares[:2] + [stranger])}).status_code, 400)
            self.assertTrue(iotshield.vault.sealed)
            self.assertEqual(self.post("/api/custody/unseal", {"shares": "\n".join(shares[2:5])}).status_code, 200)
            self.assertFalse(iotshield.vault.sealed)
            self.assertFalse(os.path.exists(key_file))                                   # unsealed in memory only
            self.assertEqual(self.client.get("/api/custody").get_json()["state"], "unsealed")
            challenge = self.challenge_for("TEMP-001")                                   # devices work again
            digest = crypto.compute_hmac(self.secret_of("TEMP-001"), challenge)
            self.assertEqual(self.post("/api/device/verify", {"device_id": "TEMP-001", "challenge": challenge,
                                                              "hmac": digest}).get_json()["access"], "GRANTED")
        finally:
            if iotshield.vault.sealed:
                self.post("/api/custody/unseal", {"shares": "\n".join(shares[:3])})
            if iotshield.vault.status()["state"] == "unsealed":
                self.post("/api/custody/restore-file", {"password": self.PASSWORD})
        self.assertEqual(self.client.get("/api/custody").get_json()["state"], "normal")   # back to the normal setup
        self.assertTrue(os.path.exists(key_file))
        self.assertEqual(self.post("/api/custody/restore-file", {"password": self.PASSWORD}).status_code, 400)   # already normal

    def test_58_wrong_passwords_lock_custody_actions(self):
        for _ in range(iotshield.MAX_LOGIN_FAILURES):
            self.assertEqual(self.split(password="wrong").status_code, 403)
        self.assertEqual(self.split().status_code, 429)           # even the right password is refused for a minute

    def test_59_custody_page_needs_login_and_is_in_the_menu(self):
        self.assertIn("/custody", self.client.get("/dashboard").get_data(as_text=True))
        self.assertEqual(self.client.get("/custody").status_code, 200)
        guest = iotshield.app.test_client()
        self.assertEqual(guest.get("/custody").status_code, 302)
        self.assertEqual(guest.get("/api/custody").status_code, 401)
        self.assertEqual(guest.post("/api/custody/split", json={}).status_code, 400)     # blocked by CSRF before anything else


    # -- master-key rotation -------------------------------------------------------
    def key_lines(self):
        with open(os.path.join(_tmp, "instance", "master.key"), "rb") as key_file:
            return key_file.read().split()

    def rotate(self, threshold=3, total=5, password="test-password", backup=True):
        return self.post("/api/custody/rotate", {"threshold": threshold, "total": total, "password": password,
                                                  "backup": backup})

    def test_60_rotation_replaces_the_key_and_the_old_shares_open_nothing(self):
        old_shares = self.split().get_json()["shares"]
        old_vault = crypto.SecretVault.from_key_bytes(iotshield.vault.raw_key())
        old_fingerprint = self.client.get("/api/custody").get_json()["fingerprint"]
        with iotshield.app.app_context():
            device_count = iotshield.get_db().execute("SELECT COUNT(*) FROM devices").fetchone()[0]

        response = self.rotate(threshold=2, total=3)
        body = response.get_json()
        self.assertEqual((response.status_code, body["devices"], len(body["shares"])), (200, device_count, 3))
        self.assertNotEqual(body["fingerprint"], old_fingerprint)
        self.assertEqual(body["old_fingerprint"], old_fingerprint)
        self.assertEqual(len(self.key_lines()), 1)                                # the old key is gone from the file

        # the OLD shares now rebuild a key that opens nothing; the NEW ones rebuild the real key
        self.assertFalse(self.post("/api/custody/verify", {"shares": "\n".join(old_shares[:3])}).get_json()["match"])
        self.assertTrue(self.post("/api/custody/verify", {"shares": "\n".join(body["shares"][:2])}).get_json()["match"])
        with iotshield.app.app_context():
            for (stored,) in iotshield.get_db().execute("SELECT secret_key FROM devices").fetchall():
                with self.assertRaises(crypto.SecretVaultError):
                    old_vault.decrypt(stored)                                      # the live database no longer opens with the old key
        status = self.client.get("/api/custody").get_json()
        self.assertEqual((status["state"], status["rotations"], status["shares"]["threshold"]), ("normal", 1, 2))

        # devices carry on working, with the very same secret keys as before
        challenge = self.challenge_for("TEMP-001")
        digest = crypto.compute_hmac(self.secret_of("TEMP-001"), challenge)
        self.assertEqual(self.post("/api/device/verify", {"device_id": "TEMP-001", "challenge": challenge,
                                                          "hmac": digest}).get_json()["access"], "GRANTED")

        # the safety copy still opens with the OLD key only, and is private to the owner
        backups = os.path.join(_tmp, "instance", "backups")
        copy = os.path.join(backups, body["backup"])
        self.assertEqual(oct(os.stat(copy).st_mode & 0o777), "0o600")
        rows = sqlite3.connect(copy).execute("SELECT secret_key FROM devices").fetchall()
        self.assertEqual(len(rows), device_count)
        for (stored,) in rows:
            old_vault.decrypt(stored)

    def test_61_rotation_can_skip_the_safety_copy_and_validates_everything_first(self):
        before = set(os.listdir(os.path.join(_tmp, "instance", "backups"))) if os.path.isdir(os.path.join(_tmp, "instance", "backups")) else set()
        key_before = self.key_lines()
        self.assertEqual(self.rotate(password="wrong").status_code, 403)
        self.assertEqual(self.rotate(threshold=1).status_code, 400)               # nonsense settings are refused
        self.assertEqual(self.rotate(threshold=5, total=3).status_code, 400)
        self.assertEqual(self.key_lines(), key_before)                            # none of that changed the key
        self.assertIsNone(self.rotate(backup=False).get_json()["backup"])
        after = set(os.listdir(os.path.join(_tmp, "instance", "backups"))) if os.path.isdir(os.path.join(_tmp, "instance", "backups")) else set()
        self.assertEqual(before, after)

    def test_62_a_failed_rotation_changes_nothing(self):
        key_before = self.key_lines()
        shares = self.split().get_json()["shares"]
        with mock.patch.object(iotshield.dbu, "reencrypt_device_keys", side_effect=dbu.RotationError("A device key is broken.")):
            response = self.rotate()
        self.assertEqual(response.status_code, 400)
        self.assertIn("Nothing was changed", response.get_json()["error"])
        self.assertEqual(self.key_lines(), key_before)                             # still the old key, still one line
        self.assertEqual(self.client.get("/api/custody").get_json()["rotations"],
                         self.client.get("/api/custody").get_json()["rotations"])
        self.assertTrue(self.post("/api/custody/verify", {"shares": "\n".join(shares[:3])}).get_json()["match"])   # old shares still valid
        challenge = self.challenge_for("TEMP-001")                                 # and devices still authenticate
        digest = crypto.compute_hmac(self.secret_of("TEMP-001"), challenge)
        self.assertEqual(self.post("/api/device/verify", {"device_id": "TEMP-001", "challenge": challenge,
                                                          "hmac": digest}).get_json()["access"], "GRANTED")

    def test_63_only_new_shares_can_seal_and_unseal_after_a_rotation(self):
        old_shares = self.split().get_json()["shares"]
        new_shares = self.rotate().get_json()["shares"]
        body = lambda items: {"shares": "\n".join(items), "password": "test-password", "confirm": "SEAL"}
        try:
            self.assertEqual(self.post("/api/custody/seal", body(old_shares[:3])).status_code, 400)   # old shares are refused
            self.assertEqual(self.post("/api/custody/seal", body(new_shares[:3])).status_code, 200)
            self.assertEqual(self.post("/api/custody/unseal", {"shares": "\n".join(old_shares[:3])}).status_code, 400)
            self.assertTrue(iotshield.vault.sealed)
            self.assertEqual(self.post("/api/custody/unseal", {"shares": "\n".join(new_shares[2:5])}).status_code, 200)
        finally:
            if iotshield.vault.sealed:
                self.post("/api/custody/unseal", {"shares": "\n".join(new_shares[:3])})
            if iotshield.vault.status()["state"] == "unsealed":
                self.post("/api/custody/restore-file", {"password": "test-password"})
        self.assertEqual(self.client.get("/api/custody").get_json()["state"], "normal")

    def test_64_rotation_is_refused_unless_the_key_is_in_its_file(self):
        shares = self.split().get_json()["shares"]
        try:
            self.post("/api/custody/seal", {"shares": "\n".join(shares[:3]), "password": "test-password", "confirm": "SEAL"})
            self.assertIn("sealed", self.rotate().get_json()["error"])
            self.post("/api/custody/unseal", {"shares": "\n".join(shares[:3])})
            self.assertIn("Write key back", self.rotate().get_json()["error"])      # unsealed = in memory only
            self.assertEqual(len(shares), 5)
        finally:
            if iotshield.vault.sealed:
                self.post("/api/custody/unseal", {"shares": "\n".join(shares[:3])})
            if iotshield.vault.status()["state"] == "unsealed":
                self.post("/api/custody/restore-file", {"password": "test-password"})

    def test_65_devices_authenticating_during_a_rotation_are_never_broken(self):
        secret = self.secret_of("TEMP-001")           # the plaintext never changes, so read it once
        outcomes, stop, running = [], threading.Event(), threading.Event()

        def authenticate_nonstop():
            client = iotshield.app.test_client()
            while not stop.is_set():
                challenge = client.post("/api/device/challenge", json={"device_id": "TEMP-001"})
                answer = client.post("/api/device/verify", json={
                    "device_id": "TEMP-001", "challenge": challenge.get_json().get("challenge", "0" * 64),
                    "hmac": crypto.compute_hmac(secret, challenge.get_json().get("challenge", "0" * 64))})
                outcomes.append((challenge.status_code, answer.status_code, answer.get_json().get("access")))
                running.set()

        worker = threading.Thread(target=authenticate_nonstop)
        worker.start()
        try:
            self.assertTrue(running.wait(10))
            first = len(outcomes)
            responses = [self.rotate(threshold=2, total=3) for _ in range(3)]
            time.sleep(0.1)
        finally:
            stop.set()
            worker.join(15)
        self.assertEqual([r.status_code for r in responses], [200, 200, 200])
        self.assertGreater(len(outcomes), first)       # logins kept happening around (and between) the rotations
        self.assertTrue(all(outcome == (200, 200, "GRANTED") for outcome in outcomes), set(outcomes))


class ShamirTests(unittest.TestCase):
    """The maths in utils/shamir.py."""

    def test_every_group_of_k_shares_rebuilds_the_secret_and_k_minus_1_never_does(self):
        import itertools
        secret = os.urandom(32)
        for threshold, total in ((2, 2), (2, 3), (3, 5), (5, 5), (4, 8)):
            parts = shamir.split_secret(secret, threshold, total)
            for group in itertools.combinations(parts, threshold):
                self.assertEqual(shamir.combine(list(group)), secret)
            for group in itertools.combinations(parts, threshold - 1):
                self.assertNotEqual(shamir.interpolate(list(group)), int.from_bytes(secret, "big"))

    def test_too_few_shares_give_a_number_that_is_not_even_a_key(self):
        parts = shamir.split_secret(os.urandom(32), 3, 5)
        with self.assertRaises(shamir.NotEnoughShares):
            shamir.combine(parts[:2])
        self.assertGreaterEqual(shamir.interpolate(parts[:2]), 2 ** 256)    # random 521-bit value, not a 256-bit key

    def test_splitting_is_random_every_time(self):
        secret = os.urandom(32)
        first, second = shamir.split_secret(secret, 3, 5), shamir.split_secret(secret, 3, 5)
        self.assertNotEqual([p.value for p in first], [p.value for p in second])
        self.assertNotEqual(first[0].split_id, second[0].split_id)
        self.assertEqual(shamir.combine(first[:3]), shamir.combine(second[:3]))   # ...yet both rebuild the same secret

    def test_shares_from_different_splits_cannot_be_mixed(self):
        secret = os.urandom(32)
        one, two = shamir.split_secret(secret, 3, 5), shamir.split_secret(secret, 3, 5)
        with self.assertRaises(shamir.ShamirError):
            shamir.combine([one[0], one[1], two[2]])

    def test_the_same_share_twice_does_not_count_twice(self):
        parts = shamir.split_secret(os.urandom(32), 3, 5)
        with self.assertRaises(shamir.ShamirError):
            shamir.combine([parts[0], parts[0], parts[1]])

    def test_text_format_round_trips_and_catches_typos(self):
        parts = shamir.split_secret(os.urandom(32), 3, 5)
        for part in parts:
            text = shamir.format_share(part)
            self.assertEqual(shamir.parse_share(text), part)
            self.assertEqual(shamir.parse_share(text.upper()), part)
        text = shamir.format_share(parts[0])
        changed = text[:40] + ("a" if text[40] != "a" else "b") + text[41:]
        for bad in (changed, text[:-1], "IOTS1-3-5", "hello"):
            with self.assertRaises(shamir.ShamirError):
                shamir.parse_share(bad)

    def test_pasted_text_is_forgiving_about_layout(self):
        secret = os.urandom(32)
        parts = shamir.split_secret(secret, 3, 5)
        text = "Share 1: %s,\n  second -> %s\n\n%s\n" % tuple(shamir.format_share(p) for p in parts[:3])
        self.assertEqual(shamir.combine(shamir.parse_shares(text)), secret)

    def test_settings_are_validated(self):
        for threshold, total in ((1, 3), (4, 3), (2, 11), (0, 0)):
            with self.assertRaises(shamir.ShamirError):
                shamir.split_secret(os.urandom(32), threshold, total)
        with self.assertRaises(shamir.ShamirError):
            shamir.split_secret(b"too short", 2, 3)


class VaultGuardTests(unittest.TestCase):
    """utils/custody.py: when is the vault open, and it must never invent a new key."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.key_path = os.path.join(self.dir, "master.key")
        os.environ.pop("IOTSHIELD_MASTER_KEY", None)

    def test_first_run_creates_a_key_and_it_encrypts(self):
        guard = custody.VaultGuard.open(self.dir)
        self.assertTrue(os.path.exists(self.key_path) and not guard.sealed)
        self.assertEqual(guard.decrypt(guard.encrypt("secret")), "secret")

    def test_sealed_marker_with_no_key_file_stays_sealed_and_does_not_make_a_new_key(self):
        guard = custody.VaultGuard.open(self.dir)
        encrypted = guard.encrypt("device key")
        guard.record_split("aabbccdd", 3, 5)
        guard.seal()
        self.assertFalse(os.path.exists(self.key_path))
        reopened = custody.VaultGuard.open(self.dir)                  # a restart
        self.assertTrue(reopened.sealed)
        self.assertFalse(os.path.exists(self.key_path))               # no invented replacement key
        with self.assertRaises(custody.VaultSealed):
            reopened.decrypt(encrypted)

    def test_unseal_needs_the_right_key_and_never_writes_it_to_disk(self):
        guard = custody.VaultGuard.open(self.dir)
        raw = guard.raw_key()
        encrypted = guard.encrypt("device key")
        guard.record_split("aabbccdd", 3, 5)
        guard.seal()
        reopened = custody.VaultGuard.open(self.dir)
        with self.assertRaises(custody.CustodyError):
            reopened.unseal(os.urandom(32))
        self.assertTrue(reopened.sealed)
        reopened.unseal(raw)
        self.assertEqual(reopened.decrypt(encrypted), "device key")   # the same key, so old data still opens
        self.assertFalse(os.path.exists(self.key_path))
        self.assertEqual(reopened.status()["state"], "unsealed")

    def test_a_stray_key_file_of_the_wrong_key_is_ignored_while_sealed(self):
        guard = custody.VaultGuard.open(self.dir)
        guard.record_split("aabbccdd", 3, 5)
        guard.seal()
        crypto.SecretVault.from_key_bytes(os.urandom(32)).write_key_file(self.key_path)    # e.g. a tool created one
        self.assertTrue(custody.VaultGuard.open(self.dir).sealed)

    def test_putting_the_right_key_file_back_opens_the_vault(self):
        guard = custody.VaultGuard.open(self.dir)
        raw = guard.raw_key()
        guard.record_split("aabbccdd", 3, 5)
        guard.seal()
        crypto.SecretVault.from_key_bytes(raw).write_key_file(self.key_path)
        reopened = custody.VaultGuard.open(self.dir)
        self.assertEqual((reopened.sealed, reopened.status()["state"]), (False, "normal"))

    def test_a_key_from_the_environment_cannot_be_sealed(self):
        with mock.patch.dict(os.environ, {"IOTSHIELD_MASTER_KEY": crypto.Fernet.generate_key().decode()}):
            guard = custody.VaultGuard.open(self.dir)
            self.assertEqual(guard.status()["state"], "environment")
            with self.assertRaises(custody.CustodyError):
                guard.seal()

    def test_simulator_style_loading_refuses_to_invent_a_key(self):
        with self.assertRaises(crypto.SecretVaultError):
            crypto.SecretVault.from_key_file(self.key_path, create=False)
        self.assertFalse(os.path.exists(self.key_path))



class RotationTests(unittest.TestCase):
    """utils/database.py + utils/custody.py: rotating the master key must never lose a device key."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.key_path = os.path.join(self.dir, "master.key")
        os.environ.pop("IOTSHIELD_MASTER_KEY", None)
        self.guard = custody.VaultGuard.open(self.dir)
        self.db = os.path.join(self.dir, "t.db")
        connection = dbu.connect(self.db)
        connection.executescript(dbu.SCHEMA)
        for number in range(4):
            connection.execute("INSERT INTO devices (device_id, device_name, device_type, secret_key, status, is_demo,"
                               " created_at) VALUES (?, 'n', 't', ?, 'active', 0, '2026-01-01T00:00:00')",
                               (f"DEV-{number}", self.guard.encrypt(f"secret-{number}")))
        connection.commit()
        connection.close()

    def stored(self):
        connection = dbu.connect(self.db)
        try:
            return [tuple(row) for row in connection.execute("SELECT device_id, secret_key FROM devices ORDER BY id")]
        finally:
            connection.close()

    def reencrypt(self, source, target):
        return dbu.reencrypt_device_keys(self.db, source, target)

    def snapshot(self):
        return dbu.snapshot_device_keys(self.db)

    def test_rotation_moves_every_key_to_the_new_key_and_keeps_the_plaintext(self):
        old = crypto.SecretVault.from_key_file(self.key_path, create=False)
        transition, count = self.guard.rotate(os.urandom(32), self.reencrypt, self.snapshot)
        self.guard.finish_rotation(transition, "aabbccdd", 3, 5)
        self.assertEqual(count, 4)
        self.assertEqual(self.guard.status()["rotations"], 1)
        self.assertEqual(len(open(self.key_path, "rb").read().split()), 1)
        for number, (device_id, token) in enumerate(self.stored()):
            self.assertEqual(self.guard.decrypt(token), f"secret-{number}")
            with self.assertRaises(crypto.SecretVaultError):
                old.decrypt(token)

    def test_one_unreadable_key_stops_the_whole_rotation_and_changes_nothing(self):
        connection = dbu.connect(self.db)
        connection.execute("UPDATE devices SET secret_key = 'not-a-real-token' WHERE device_id = 'DEV-2'")
        connection.commit()
        connection.close()
        before, key_before = self.stored(), open(self.key_path, "rb").read().split()
        with self.assertRaises(dbu.RotationError) as caught:
            self.guard.rotate(os.urandom(32), self.reencrypt, self.snapshot)
        self.assertIn("DEV-2", str(caught.exception))
        self.assertEqual(self.stored(), before)                              # not one row was touched
        self.assertEqual(open(self.key_path, "rb").read().split(), key_before)  # still the old key alone
        self.assertEqual(self.guard.status()["state"], "normal")

    def test_any_error_during_reencryption_rolls_back_and_restores_the_old_key(self):
        def explode(source, target):
            dbu.reencrypt_device_keys(self.db, source, target)
            raise RuntimeError("power cut")                                   # worst case: AFTER the database was committed
        old_vault = self.guard._vault
        before = self.stored()
        # database already changed + error: both keys must stay so that everything still opens
        with self.assertRaises(RuntimeError):
            self.guard.rotate(os.urandom(32), explode, self.snapshot)
        self.assertEqual(len(open(self.key_path, "rb").read().split()), 2)
        self.assertNotEqual(self.stored(), before)
        for number, (_, token) in enumerate(self.stored()):
            self.assertEqual(self.guard.decrypt(token), f"secret-{number}")
        self.assertEqual(self.guard.status()["rotation_unfinished"], True)
        self.assertFalse(self.guard.status()["can_rotate"])

    def test_error_before_the_database_changes_goes_back_to_the_old_key(self):
        def refuse(source, target):
            raise dbu.RotationError("busy")
        before, key_before = self.stored(), open(self.key_path, "rb").read().split()
        with self.assertRaises(dbu.RotationError):
            self.guard.rotate(os.urandom(32), refuse, self.snapshot)
        self.assertEqual(open(self.key_path, "rb").read().split(), key_before)
        self.assertEqual(self.stored(), before)
        self.assertTrue(self.guard.status()["can_rotate"])

    def test_a_rotation_cut_short_is_finished_on_the_next_start(self):
        # simulate a crash right after the two-key file was written, before any database change
        old = self.guard._vault
        new_raw = os.urandom(32)
        crypto.SecretVault.rotating(new_raw, old).write_key_file(self.key_path)
        reopened = custody.VaultGuard.open(self.dir)
        self.assertTrue(reopened.status()["rotation_unfinished"])
        for number, (_, token) in enumerate(self.stored()):                   # everything already opens
            self.assertEqual(reopened.decrypt(token), f"secret-{number}")
        reopened.record_split("deadbeef", 3, 5)                               # shares of a key that is about to change
        self.assertTrue(reopened.recover_rotation(self.reencrypt))
        self.assertFalse(reopened.status()["rotation_unfinished"])
        self.assertIsNone(reopened.status()["shares"])                        # stale shares are forgotten
        only_new = crypto.SecretVault.from_key_bytes(new_raw)
        for number, (_, token) in enumerate(self.stored()):
            self.assertEqual(only_new.decrypt(token), f"secret-{number}")      # now readable with the new key alone
        self.assertFalse(reopened.recover_rotation(self.reencrypt))           # nothing left to do

    def test_reencrypting_twice_is_harmless(self):
        new_only = crypto.SecretVault.from_key_bytes(os.urandom(32))
        both = crypto.SecretVault.rotating(new_only.key_bytes(), self.guard._vault)
        self.assertEqual(dbu.reencrypt_device_keys(self.db, both, new_only), 4)
        self.assertEqual(dbu.reencrypt_device_keys(self.db, both, new_only), 4)
        for number, (_, token) in enumerate(self.stored()):
            self.assertEqual(new_only.decrypt(token), f"secret-{number}")

    def test_the_safety_copy_is_complete_and_private(self):
        copy = dbu.backup_database(self.db, os.path.join(self.dir, "backups"))
        self.assertEqual(oct(os.stat(copy).st_mode & 0o777), "0o600")
        self.assertEqual(sqlite3.connect(copy).execute("SELECT device_id, secret_key FROM devices ORDER BY id").fetchall(),
                         self.stored())

    def test_rotation_is_refused_when_it_is_not_possible(self):
        with mock.patch.dict(os.environ, {"IOTSHIELD_MASTER_KEY": crypto.Fernet.generate_key().decode()}):
            with self.assertRaises(custody.CustodyError):
                custody.VaultGuard.open(self.dir).rotate(os.urandom(32), self.reencrypt, self.snapshot)
        self.guard.record_split("aabbccdd", 3, 5)
        self.guard.seal()
        with self.assertRaises(custody.VaultSealed):
            self.guard.rotate(os.urandom(32), self.reencrypt, self.snapshot)

    def test_two_key_vaults_encrypt_with_the_new_key_and_decrypt_with_either(self):
        old = crypto.SecretVault(crypto.Fernet.generate_key())
        new_raw = os.urandom(32)
        both, new_only = crypto.SecretVault.rotating(new_raw, old), crypto.SecretVault.from_key_bytes(new_raw)
        self.assertEqual(both.decrypt(old.encrypt("from old")), "from old")
        self.assertEqual(new_only.decrypt(both.encrypt("from new")), "from new")
        with self.assertRaises(crypto.SecretVaultError):
            old.decrypt(both.encrypt("from new"))


if __name__ == "__main__":
    sys.exit(0 if unittest.main(verbosity=2, exit=False).result.wasSuccessful() else 1)
