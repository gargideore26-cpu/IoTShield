"""
IoTShield - Secure Device Authentication Using HMAC
===================================================
Flask backend. Run with:  python app.py

Authentication protocol (Challenge-Response + HMAC-SHA256):

    1. Device  -> Server : "I am TEMP-001"                 POST /api/device/challenge
    2. Server  -> Device : random challenge (one-time)
    3. Device computes   : HMAC-SHA256(secret_key, challenge)
    4. Device  -> Server : the HMAC                        POST /api/device/verify
    5. Server recomputes the expected HMAC and compares in constant time
    6. Match -> ACCESS GRANTED, otherwise ACCESS DENIED. Both are logged.

Signed firmware updates (Ed25519 digital signatures, see utils/crypto.py section 4):

    1. Admin uploads an image  -> server signs (version, SHA-256) with its PRIVATE key
    2. Device  -> Server : "what is the latest firmware?"  GET /api/device/firmware/latest
    3. Device downloads the image and checks the signature with the PUBLIC key
       built into it, and refuses anything older than what it already runs
    4. Device  -> Server : result, authenticated with HMAC  POST /api/device/firmware/report
"""

import logging
import os
import re
import secrets
import smtplib
import sqlite3
import time
from datetime import timedelta
from email.message import EmailMessage
from functools import wraps

from flask import Flask, flash, g, get_flashed_messages, jsonify, redirect, render_template, request, session, url_for
from werkzeug.utils import secure_filename

from utils import crypto
from utils import custody, shamir
from utils import database as dbu

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


# ------------------------------------------------------------------ configuration

def load_env_file(path: str) -> None:
    """Tiny .env reader (KEY=VALUE per line). Real environment variables win."""
    if not os.path.exists(path):
        return
    with open(path, encoding="utf-8") as env_file:
        for line in env_file:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip().strip("\"'"))


load_env_file(os.path.join(BASE_DIR, ".env"))

# The two overrides below are only used by test_iotshield.py (throw-away database).
DB_PATH = os.environ.get("IOTSHIELD_DB_PATH", os.path.join(BASE_DIR, "database", "database.db"))
INSTANCE_DIR = os.environ.get("IOTSHIELD_INSTANCE_DIR", os.path.join(BASE_DIR, "instance"))

CHALLENGE_TTL_SECONDS = 120     # a challenge is valid for 2 minutes, once
ONLINE_WINDOW_MINUTES = 15      # "Online" = authenticated within this window
MAX_LOGIN_FAILURES = 5
LOGIN_LOCK_SECONDS = 60
PENDING_LOGIN_TIMEOUT_SECONDS = 180     # must enter the 2FA code within 3 minutes of the password
IDLE_TIMEOUT_SECONDS = 300      # 5 minutes without real activity -> signed out
MAX_DEVICE_AUTH_FAILURES = 5    # per-device rate limit on /api/device/verify (defense in depth:
DEVICE_AUTH_LOCK_SECONDS = 60   # HMAC-SHA256 cannot realistically be brute-forced, but this stops
                                # attack traffic, log spam and misbehaving clients from hammering a device)
EMAIL_OTP_LIFETIME_SECONDS = 600   # a mailed code is good for 10 minutes
MAX_CODE_ATTEMPTS = 5              # a single mailed code accepts at most this many wrong guesses
CODE_RESEND_COOLDOWN_SECONDS = 30  # minimum gap between "resend code" clicks
FIRMWARE_MAX_BYTES = 2 * 1024 * 1024   # largest firmware image the admin may upload

ADMIN_USER = os.environ.get("IOTSHIELD_ADMIN_USER", "admin")
ADMIN_PASSWORD = os.environ.get("IOTSHIELD_ADMIN_PASSWORD")
if not ADMIN_PASSWORD:
    # No password configured: make a random one instead of using a default.
    ADMIN_PASSWORD = secrets.token_urlsafe(9)
    print(f"\n[IoTShield] IOTSHIELD_ADMIN_PASSWORD is not set. "
          f"Temporary login -> {ADMIN_USER} / {ADMIN_PASSWORD}\n")

EMAIL_OTP_ENABLED = os.environ.get("IOTSHIELD_EMAIL_OTP_ENABLED", "true").strip().lower() not in ("0", "false", "no")
ADMIN_EMAIL = os.environ.get("IOTSHIELD_ADMIN_EMAIL", "").strip()      # where the code is sent
SMTP_EMAIL = os.environ.get("IOTSHIELD_SMTP_EMAIL", "").strip()        # Gmail account that sends it
SMTP_PASSWORD = os.environ.get("IOTSHIELD_SMTP_PASSWORD", "")          # Gmail App Password, not the normal password
SMTP_HOST = os.environ.get("IOTSHIELD_SMTP_HOST", "smtp.gmail.com").strip()
SMTP_PORT = int(os.environ.get("IOTSHIELD_SMTP_PORT", "587"))
# Classroom convenience: if the email cannot be sent (Gmail not configured, wrong app password, no
# internet, ...) show the code on the login page instead of getting stuck. Turn this off for
# anything resembling a real deployment (IOTSHIELD_EMAIL_OTP_SHOW_FALLBACK=false) - a real second
# factor should never be visible on the same screen you are logging into.
EMAIL_OTP_SHOW_FALLBACK = os.environ.get("IOTSHIELD_EMAIL_OTP_SHOW_FALLBACK", "true").strip().lower() not in ("0", "false", "no")


def load_flask_secret() -> str:
    """Key used to sign the login session cookie (created once, kept on disk)."""
    env_value = os.environ.get("IOTSHIELD_SECRET_KEY")
    if env_value:
        return env_value
    path = os.path.join(INSTANCE_DIR, "flask_secret.key")
    if not os.path.exists(path):
        os.makedirs(INSTANCE_DIR, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as key_file:
            key_file.write(secrets.token_hex(32))
    with open(path, encoding="utf-8") as key_file:
        return key_file.read().strip()


app = Flask(__name__)
app.config.update(
    SECRET_KEY=load_flask_secret(),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    TEMPLATES_AUTO_RELOAD=True,
    MAX_CONTENT_LENGTH=FIRMWARE_MAX_BYTES + 64 * 1024,   # image + form fields
)
logging.basicConfig(level=logging.INFO)

vault = custody.VaultGuard.open(INSTANCE_DIR)     # behaves like a SecretVault; raises VaultSealed while sealed
signer = crypto.FirmwareSigner.from_key_file(os.path.join(INSTANCE_DIR, "firmware_signing.key"))
try:
    dbu.init_db(DB_PATH, vault, signer)
except custody.VaultSealed:
    pass     # only possible on a brand-new database while sealed; demo data is added after unsealing
try:
    if vault.recover_rotation(lambda source, target: dbu.reencrypt_device_keys(DB_PATH, source, target)):
        print("\n[IoTShield] A master-key rotation had been interrupted and was finished now."
              "\n  Its new shares were never shown, so create new ones on the Key Custody page.\n")
except Exception as problem:     # never stop the app over this: the two-key file still opens everything
    print(f"\n[IoTShield] Could not finish an interrupted master-key rotation ({problem}). "
          "The server is using both keys, so nothing is lost.\n")
if vault.sealed:
    print("\n[IoTShield] The key vault is SEALED: devices cannot authenticate until it is unsealed."
          "\n  Log in and open Key Custody, then enter enough key shares.\n")

if EMAIL_OTP_ENABLED and not (ADMIN_EMAIL and SMTP_EMAIL and SMTP_PASSWORD):
    print("\n[IoTShield] Two-factor authentication is on, but Gmail is not configured"
          " (IOTSHIELD_ADMIN_EMAIL / IOTSHIELD_SMTP_EMAIL / IOTSHIELD_SMTP_PASSWORD).")
    print("  No emails will be sent - the login code will be shown directly on the login page"
          " instead, so the demo still works. See .env.example to set up real Gmail delivery.\n")

HEX64 = re.compile(r"[0-9a-f]{64}")
DEVICE_ID_PATTERN = re.compile(r"[A-Z0-9][A-Z0-9_-]{2,31}")
TEXT_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._/()-]{1,39}")
failed_logins = {}  # ip address -> {"count": n, "last": timestamp} (wrong password OR wrong 2FA code)
failed_custody = {}  # ip address -> {"count": n, "last": timestamp}  (wrong password / shares on key-custody actions)
failed_device_auth = {}  # device_id -> {"count": n, "last": timestamp}
pending_email_codes = {}  # pending_id -> {"code", "username", "expires", "attempts", "last_sent", "sent", "send_error"}


# ---------------------------------------------------------------------- helpers

def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = dbu.connect(DB_PATH)
    return g.db


@app.teardown_appcontext
def close_db(_error):
    connection = g.pop("db", None)
    if connection is not None:
        connection.close()


def json_error(message: str, status: int, **extra):
    return jsonify(success=False, error=message, **extra), status


def wants_json() -> bool:
    return request.path.startswith("/api/")


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not session.get("admin"):
            if wants_json():
                return json_error("Please log in to continue.", 401)
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapper


def csrf_token() -> str:
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def enforce_idle_timeout():
    """Sign the admin out after IDLE_TIMEOUT_SECONDS without real activity.

    Real activity = opening a page, a button/form action (POST/DELETE) or the
    "activity" ping the browser sends when the mouse or keyboard is used.
    The dashboard's automatic background refreshes (GET /api/...) do NOT count,
    otherwise an open dashboard would keep the session alive forever.
    """
    if not session.get("admin") or request.path.startswith("/static/"):
        return None
    now = time.time()
    if now - session.get("last_active", now) > IDLE_TIMEOUT_SECONDS:
        session.clear()
        if wants_json():
            return json_error("Session expired after 5 minutes of inactivity. Please log in again.", 401)
        return redirect(url_for("login", expired=1))
    background_refresh = request.method == "GET" and request.path.startswith("/api/")
    if not background_refresh:
        session["last_active"] = now
    return None


VAULT_PATHS = ("/api/device/challenge", "/api/device/verify", "/api/device/firmware/report", "/api/simulate/")


def uses_vault() -> bool:
    return request.path.startswith(VAULT_PATHS) or (request.method == "POST" and request.path == "/api/devices")


@app.before_request
def vault_gate_and_sealed_check():
    """Two jobs for every request that touches the master key.

    1. Take the vault gate for the whole request. Key rotation holds the same gate, so a login or
       a new device can never be half-done while the keys are being swapped (one runs, then the other).
    2. A sealed vault cannot decrypt device keys. Say so up front (before a challenge is consumed
       or a half-finished request is logged) instead of failing in the middle.
    """
    if uses_vault() or request.path.startswith("/api/custody/"):
        vault.gate.acquire()
        g.vault_gate_held = True
    if vault.sealed and uses_vault():
        raise custody.VaultSealed()


@app.teardown_request
def release_vault_gate(_error):
    if g.pop("vault_gate_held", False):
        vault.gate.release()


@app.errorhandler(custody.VaultSealed)
def handle_vault_sealed(_error):
    message = "The key vault is sealed. An administrator must unseal it on the Key Custody page."
    if wants_json():
        return json_error(message, 503, sealed=True)
    return render_error(message, 503)


@app.context_processor
def inject_vault_state():
    return {"vault_sealed": vault.sealed}


@app.before_request
def check_csrf_token():
    """Reject state-changing requests that do not carry our CSRF token.

    /api/device/* is the machine-to-machine protocol used by IoT devices. They
    have no browser session, and are protected by the HMAC itself.
    """
    if request.method in ("POST", "PUT", "PATCH", "DELETE") \
            and not request.path.startswith("/api/device/"):
        sent = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token", "")
        expected = session.get("csrf", "")
        if not expected or not secrets.compare_digest(sent.encode(), expected.encode()):
            if wants_json():
                return json_error("Security token invalid. Please refresh the page.", 400)
            return render_error("Security token invalid. Please go back and refresh the page.", 400)


@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Cache-Control"] = "no-store"
    return response


def render_error(message: str, status: int):
    return render_template("error.html", page="error", message=message, status=status), status


@app.errorhandler(404)
def handle_404(_error):
    if wants_json():
        return json_error("Not found.", 404)
    return render_error("The page you are looking for does not exist.", 404)


@app.errorhandler(405)
def handle_405(_error):
    if wants_json():
        return json_error("Method not allowed.", 405)
    return render_error("This action is not allowed.", 405)


@app.errorhandler(413)
def handle_413(_error):
    limit = f"{FIRMWARE_MAX_BYTES // (1024 * 1024)} MB"
    if wants_json():
        return json_error(f"File is too large. The limit is {limit}.", 413)
    return render_error(f"File is too large. The limit is {limit}.", 413)


@app.errorhandler(Exception)
def handle_unexpected_error(error):
    """Never show a Python stack trace to the user; log it on the server."""
    app.logger.exception("Unhandled error: %s", error)
    if wants_json():
        return json_error("Something went wrong on the server. Please try again.", 500)
    return render_error("Something went wrong on the server. Please try again.", 500)


def find_device(db, device_id: str):
    return db.execute("SELECT * FROM devices WHERE device_id = ?", (device_id,)).fetchone()


def display_status(device_row, pending_challenges: int) -> str:
    """Status shown in the UI: disabled / authenticating / online / offline."""
    if device_row["status"] == "disabled":
        return "disabled"
    if pending_challenges:
        return "authenticating"
    if device_row["last_authenticated"]:
        age = dbu.utcnow() - dbu.from_db_time(device_row["last_authenticated"])
        if age <= timedelta(minutes=ONLINE_WINDOW_MINUTES):
            return "online"
    return "offline"


def serialize_device(row) -> dict:
    """Device -> JSON. The secret key is deliberately NOT included."""
    return {
        "device_id": row["device_id"],
        "device_name": row["device_name"],
        "device_type": row["device_type"],
        "status": display_status(row, row["pending"]),
        "enabled": row["status"] == "active",
        "attempts": row["attempts"],
        "created_at": dbu.to_iso(row["created_at"]),
        "last_authenticated": dbu.to_iso(row["last_authenticated"]),
        "firmware_version": row["firmware_version"],
        "is_demo": bool(row["is_demo"]),
    }


DEVICE_QUERY = """
    SELECT d.*,
      (SELECT COUNT(*) FROM authentication_logs l WHERE l.device_id = d.device_id) AS attempts,
      (SELECT COUNT(*) FROM challenges c WHERE c.device_id = d.device_id
         AND c.used = 0 AND c.created_at >= :fresh) AS pending
    FROM devices d
"""


def fresh_cutoff() -> str:
    return dbu.to_db_time(dbu.utcnow() - timedelta(seconds=CHALLENGE_TTL_SECONDS))


def mask_email(address: str) -> str:
    """Obscure most of an email address for display, e.g. "gargi@gmail.com" -> "ga***@gmail.com"."""
    local, _, domain = address.partition("@")
    if not domain:
        return address
    visible = local[:2] if len(local) > 2 else local[:1]
    return f"{visible}{'*' * max(len(local) - len(visible), 1)}@{domain}"


def email_is_configured() -> bool:
    return bool(ADMIN_EMAIL and SMTP_EMAIL and SMTP_PASSWORD)


def send_login_code_email(code: str):
    """Email the one-time login code to ADMIN_EMAIL via Gmail SMTP. Returns (sent, error)."""
    if not email_is_configured():
        return False, "Email is not configured."
    message = EmailMessage()
    message["Subject"] = "Your IoTShield login code"
    message["From"] = SMTP_EMAIL
    message["To"] = ADMIN_EMAIL
    message.set_content(
        f"Your one-time IoTShield login code is: {code}\n\n"
        f"It expires in {EMAIL_OTP_LIFETIME_SECONDS // 60} minutes and can only be used once.\n"
        "If you did not try to log in to IoTShield, you can safely ignore this email."
    )
    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
            server.starttls()
            server.login(SMTP_EMAIL, SMTP_PASSWORD)
            server.send_message(message)
        return True, None
    except Exception as error:  # a mail problem must never break the login page
        app.logger.warning("Could not send login code email: %s", error)
        return False, str(error)


def purge_expired_email_codes() -> None:
    now = time.time()
    for pending_id in [pid for pid, entry in pending_email_codes.items() if entry["expires"] < now]:
        pending_email_codes.pop(pending_id, None)


def issue_email_code(pending_id: str, username: str) -> dict:
    """(Re)generate the one-time code for `pending_id`, store it server-side, and try to email
    it. The code itself never goes in the session cookie - only the opaque `pending_id` does."""
    purge_expired_email_codes()
    code = crypto.generate_otp_code()
    sent, error = send_login_code_email(code)
    entry = {"code": code, "username": username, "expires": time.time() + EMAIL_OTP_LIFETIME_SECONDS,
              "attempts": 0, "last_sent": time.time(), "sent": sent, "send_error": error}
    pending_email_codes[pending_id] = entry
    return entry


def write_log(db, device_id, challenge, received, expected, result, reason, commit=True):
    db.execute(
        "INSERT INTO authentication_logs (device_id, challenge, received_hmac,"
        " expected_hmac, result, reason, is_demo, timestamp) VALUES (?, ?, ?, ?, ?, ?, 0, ?)",
        (device_id, challenge, received, expected, result, reason,
         dbu.to_db_time(dbu.utcnow())),
    )
    if commit:
        db.commit()


# ------------------------------------------------------------- firmware helpers

FIRMWARE_ATTACKS = ("none", "tamper", "forged", "relabel", "downgrade")


def release_versions(db) -> list:
    """All published versions, newest first (compared numerically, so 1.10.0 > 1.9.0)."""
    versions = [row["version"] for row in db.execute("SELECT version FROM firmware_releases")]
    return sorted(versions, key=crypto.parse_version, reverse=True)


def find_release(db, version: str):
    return db.execute("SELECT * FROM firmware_releases WHERE version = ?", (version,)).fetchone()


def firmware_status(current, latest) -> str:
    """up_to_date / outdated / unknown, for the fleet view."""
    if not current or not crypto.parse_version(current):
        return "unknown"
    if latest and crypto.parse_version(current) < crypto.parse_version(latest):
        return "outdated"
    return "up_to_date"


def is_downgrade(current, offered) -> bool:
    """Anti-rollback rule: never go back to an older version (it may have a known hole)."""
    return bool(current and crypto.parse_version(current)
                and crypto.parse_version(offered) < crypto.parse_version(current))


def write_firmware_event(db, device_id, version, result, reason, commit=True):
    db.execute(
        "INSERT INTO firmware_events (device_id, version, result, reason, is_demo, timestamp)"
        " VALUES (?, ?, ?, ?, 0, ?)",
        (device_id, version, result, reason, dbu.to_db_time(dbu.utcnow())))
    if commit:
        db.commit()


def install_firmware(db, device_id, version, reason):
    db.execute("UPDATE devices SET firmware_version = ? WHERE device_id = ?", (version, device_id))
    write_firmware_event(db, device_id, version, "INSTALLED", reason)


def serialize_release(row, latest) -> dict:
    """Release -> JSON. The image itself is not included (devices download it separately)."""
    return {
        "version": row["version"],
        "filename": row["filename"],
        "size": row["size"],
        "sha256": row["sha256"],
        "signature": row["signature"],
        "notes": row["notes"] or "",
        "created_at": dbu.to_iso(row["created_at"]),
        "is_latest": row["version"] == latest,
        "is_demo": bool(row["is_demo"]),
    }


# ------------------------------------------------------------------------ pages

@app.get("/")
def splash():
    return render_template("splash.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Two-step login: username + password, then (if enabled) a 6-digit code emailed to
    IOTSHIELD_ADMIN_EMAIL.

    Both steps share ONE lockout counter, keyed by IP address: a wrong password and a wrong
    emailed code count the same way, so an attacker cannot try unlimited codes just because
    they got the password right. The code itself is also capped at MAX_CODE_ATTEMPTS wrong
    guesses of its own (defense in depth in case the IP-based counter is ever bypassed, e.g.
    a stolen session cookie used from elsewhere).
    """
    if session.get("admin"):
        return redirect(url_for("dashboard"))

    purge_expired_email_codes()

    def clear_pending():
        pending_email_codes.pop(session.get("pending_id"), None)
        session.pop("pending_admin", None)
        session.pop("pending_since", None)
        session.pop("pending_id", None)

    pending_admin = session.get("pending_admin")
    pending_id = session.get("pending_id")
    if pending_admin and time.time() - session.get("pending_since", 0) > PENDING_LOGIN_TIMEOUT_SECONDS:
        pending_admin = None
    if pending_admin and pending_id not in pending_email_codes:
        pending_admin = None       # code expired, was used up, or the server restarted
    if not pending_admin:
        clear_pending()
        pending_id = None

    def finish_login(username):
        failed_logins.pop(ip_address, None)
        pending_email_codes.pop(pending_id, None)
        session.clear()
        session["admin"] = username
        session.permanent = False          # cookie disappears when the browser closes
        session["last_active"] = time.time()

    def record_failure():
        record = failed_logins.setdefault(ip_address, {"count": 0, "last": 0})
        record["count"] += 1
        record["last"] = time.time()

    error = None
    notice = None
    if request.method == "POST":
        if request.form.get("cancel"):
            clear_pending()
            return redirect(url_for("login"))

        ip_address = request.remote_addr or "unknown"
        record = failed_logins.get(ip_address)
        if record and time.time() - record["last"] > LOGIN_LOCK_SECONDS:
            failed_logins.pop(ip_address)  # old failures are forgotten
            record = None
        locked = bool(record and record["count"] >= MAX_LOGIN_FAILURES)

        if locked:
            error = "Too many failed attempts. Please wait a minute and try again."
        elif pending_admin and request.form.get("resend"):
            entry = pending_email_codes.get(pending_id)
            if entry and time.time() - entry["last_sent"] < CODE_RESEND_COOLDOWN_SECONDS:
                flash("Please wait a few seconds before requesting another code.", "error")
            else:
                entry = issue_email_code(pending_id, pending_admin)
                if entry["sent"]:
                    flash("A new code was sent to your email.", "notice")
                elif EMAIL_OTP_SHOW_FALLBACK:
                    flash("Could not send the email - here is your new code below.", "notice")
                else:
                    flash("Could not send the login code by email. Please contact the administrator.", "error")
            # Post/Redirect/Get: reloading the resulting page must never re-send another email.
            return redirect(url_for("login"))
        elif pending_admin:
            code = request.form.get("code", "").strip()
            entry = pending_email_codes.get(pending_id)
            if not entry:
                clear_pending()
                pending_admin = None
                error = "That code is no longer valid. Please log in again."
            elif not code:
                error = "Please enter the 6-digit code we emailed you."
            elif crypto.verify_otp_code(entry["code"], code):
                finish_login(pending_admin)
                return redirect(url_for("dashboard"))
            else:
                record_failure()
                entry["attempts"] += 1
                if entry["attempts"] >= MAX_CODE_ATTEMPTS:
                    clear_pending()
                    pending_admin = None
                    error = "Too many incorrect attempts. Please log in again."
                else:
                    error = "Invalid code. Please try again."
        else:
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            if not username or not password:
                error = "Please enter all required fields."
            else:
                # compare_digest again: constant-time comparison of credentials
                user_ok = secrets.compare_digest(username.encode(), ADMIN_USER.encode())
                pass_ok = secrets.compare_digest(password.encode(), ADMIN_PASSWORD.encode())
                if user_ok and pass_ok:
                    if EMAIL_OTP_ENABLED:
                        failed_logins.pop(ip_address, None)
                        pending_id = secrets.token_hex(16)
                        entry = issue_email_code(pending_id, username)
                        session["pending_admin"] = username
                        session["pending_since"] = time.time()
                        session["pending_id"] = pending_id
                        if not entry["sent"] and not EMAIL_OTP_SHOW_FALLBACK:
                            flash("Could not send the login code by email. Please contact the administrator.", "error")
                        # Post/Redirect/Get: a page refresh here must re-show the pending code
                        # page, never resubmit the password and send a second email.
                        return redirect(url_for("login"))
                    else:
                        finish_login(username)
                        return redirect(url_for("dashboard"))
                else:
                    record_failure()
                    error = "Invalid username or password."

    for category, message in get_flashed_messages(with_categories=True):
        if category == "error" and error is None:
            error = message
        elif category == "notice" and notice is None:
            notice = message

    if notice is None and request.args.get("expired"):
        notice = "You were signed out after 5 minutes of inactivity. Please log in again."

    fallback_code = None
    if pending_admin:
        entry = pending_email_codes.get(session.get("pending_id"))
        if entry and not entry["sent"] and EMAIL_OTP_SHOW_FALLBACK:
            fallback_code = entry["code"]

    return render_template("login.html", error=error, notice=notice,
                          stage="code" if pending_admin else "credentials",
                          masked_email=mask_email(ADMIN_EMAIL) if ADMIN_EMAIL else None,
                          fallback_code=fallback_code)


@app.get("/logout")
def logout():
    session.clear()
    if request.args.get("reason") == "reload":      # the page was refreshed: start over from the opening screen
        return redirect(url_for("splash"))
    return redirect(url_for("login", expired=1 if request.args.get("reason") == "idle" else None))


@app.get("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", page="dashboard")


@app.get("/devices")
@login_required
def devices_page():
    return render_template("devices.html", page="devices")


@app.get("/devices/<device_id>")
@login_required
def device_details(device_id):
    device = find_device(get_db(), device_id.upper())
    if not device:
        return render_error("Device not found.", 404)
    return render_template("device_details.html", page="devices", device_id=device["device_id"])


@app.get("/authenticate")
@login_required
def authenticate_page():
    return render_template("authentication.html", page="authenticate")


@app.get("/logs")
@login_required
def logs_page():
    return render_template("logs.html", page="logs")


@app.get("/firmware")
@login_required
def firmware_page():
    return render_template("firmware.html", page="firmware")


@app.get("/custody")
@login_required
def custody_page():
    return render_template("custody.html", page="custody")


@app.get("/about")
@login_required
def about_page():
    return render_template("about.html", page="about")


# ------------------------------------------------- device protocol (no session)

@app.post("/api/device/challenge")
def api_issue_challenge():
    """Step 1-2: a device says who it is, the server answers with a challenge."""
    data = request.get_json(silent=True) or {}
    device_id = str(data.get("device_id", "")).strip().upper()[:40]
    if not device_id:
        return json_error("Please enter all required fields.", 400)

    db = get_db()
    device = find_device(db, device_id)
    if not device:
        return json_error("Device not found.", 404)
    if device["status"] == "disabled":
        return json_error("Device is disabled. Access denied.", 403)

    challenge = crypto.generate_challenge()
    db.execute("INSERT INTO challenges (device_id, challenge, created_at) VALUES (?, ?, ?)",
               (device_id, challenge, dbu.to_db_time(dbu.utcnow())))
    # housekeeping: forget challenges older than an hour
    db.execute("DELETE FROM challenges WHERE created_at < ?",
               (dbu.to_db_time(dbu.utcnow() - timedelta(hours=1)),))
    db.commit()
    return jsonify(success=True, device_id=device_id, challenge=challenge,
                   expires_in=CHALLENGE_TTL_SECONDS, algorithm="HMAC-SHA256")


@app.post("/api/device/verify")
def api_verify_response():
    """Step 4-6: check the HMAC sent by the device."""
    data = request.get_json(silent=True) or {}
    device_id = str(data.get("device_id", "")).strip().upper()[:40]
    challenge = str(data.get("challenge", "")).strip().lower()
    received = str(data.get("hmac", "")).strip().lower()
    if not (device_id and challenge and received):
        return json_error("Please enter all required fields.", 400)

    db = get_db()
    device = find_device(db, device_id)
    if not device:
        return json_error("Device not found.", 404)

    challenge_is_hex = bool(HEX64.fullmatch(challenge))
    hmac_is_hex = bool(HEX64.fullmatch(received))
    logged_challenge = challenge if challenge_is_hex else "(malformed)"
    logged_received = received if hmac_is_hex else "(malformed)"

    def deny(reason, message, challenge_state, hmac_state, expected=None, status=403, count_failure=True):
        if count_failure:
            record = failed_device_auth.setdefault(device_id, {"count": 0, "last": 0})
            record["count"] += 1
            record["last"] = time.time()
        write_log(db, device_id, logged_challenge, logged_received, expected, "FAILED", reason)
        return jsonify(success=False, device_id=device_id, message=message, reason=reason,
                       challenge=challenge_state, hmac=hmac_state, access="DENIED"), status

    # Rate limit: too many recent failures for this device -> refuse without even checking.
    # HMAC-SHA256 itself cannot realistically be brute-forced (see the README's security
    # analysis), but this still stops attack traffic, log spam and misbehaving clients.
    lock_record = failed_device_auth.get(device_id)
    if lock_record and time.time() - lock_record["last"] > DEVICE_AUTH_LOCK_SECONDS:
        failed_device_auth.pop(device_id, None)
        lock_record = None
    if lock_record and lock_record["count"] >= MAX_DEVICE_AUTH_FAILURES:
        return deny("Too many failed attempts - device temporarily locked",
                    f"Too many failed attempts for {device_id}. Please wait a minute and try again.",
                    "Rejected", "Not checked", status=429, count_failure=False)

    if device["status"] == "disabled":
        return deny("Device is disabled", "Device is disabled. Access denied.",
                    "Rejected", "Not checked")
    if not challenge_is_hex or not hmac_is_hex:
        return deny("Malformed challenge or HMAC", "Invalid authentication response.",
                    "Rejected", "Invalid")

    # The challenge must have been issued to THIS device and never used before.
    issued = db.execute("SELECT * FROM challenges WHERE device_id = ? AND challenge = ?",
                        (device_id, challenge)).fetchone()
    if not issued:
        return deny("Challenge was never issued to this device",
                    "Invalid authentication response.", "Rejected", "Not checked")

    # Mark it used immediately (atomic), whatever the outcome: one try per challenge.
    consumed = db.execute("UPDATE challenges SET used = 1 WHERE id = ? AND used = 0",
                          (issued["id"],))
    db.commit()
    if consumed.rowcount == 0:
        return deny("Challenge already used (replay attack blocked)",
                    "Challenge already used. Replay attempt blocked.",
                    "Rejected", "Not checked")
    if issued["created_at"] < fresh_cutoff():
        return deny("Challenge expired", "Challenge expired. Generate a new one.",
                    "Rejected", "Not checked")

    # --- the cryptographic check -------------------------------------------
    secret_key = vault.decrypt(device["secret_key"])
    expected = crypto.compute_hmac(secret_key, challenge)
    if not crypto.verify_hmac(expected, received):
        return deny("HMAC mismatch - device does not know the secret key",
                    "Authentication failed. Access denied.",
                    "Verified", "Invalid", expected=expected)

    failed_device_auth.pop(device_id, None)
    write_log(db, device_id, challenge, received, expected, "SUCCESS", "HMAC verified",
              commit=False)
    db.execute("UPDATE devices SET last_authenticated = ? WHERE device_id = ?",
               (dbu.to_db_time(dbu.utcnow()), device_id))
    # Session complete: any other challenge still open for this device is void.
    db.execute("UPDATE challenges SET used = 1 WHERE device_id = ? AND used = 0", (device_id,))
    db.commit()
    return jsonify(success=True, device_id=device_id, message="Authentication successful.",
                   challenge="Verified", hmac="Valid", access="GRANTED")


@app.get("/api/device/firmware/<version>")
def api_firmware_manifest(version):
    """Step 2: tell a device about a release ("latest" or an exact version).

    Firmware is not secret - anyone may download it. What protects devices is
    that only the server's private key can produce a signature they accept.
    """
    db = get_db()
    if version == "latest":
        versions = release_versions(db)
        version = versions[0] if versions else ""
    release = find_release(db, version)
    if not release:
        return json_error("No firmware release found.", 404)
    return jsonify(version=release["version"], size=release["size"], sha256=release["sha256"],
                   signature=release["signature"], algorithm=crypto.FIRMWARE_SIGNATURE_ALGORITHM,
                   image_url=url_for("api_firmware_image", version=release["version"]))


@app.get("/api/device/firmware/<version>/image")
def api_firmware_image(version):
    release = find_release(get_db(), version)
    if not release:
        return json_error("No firmware release found.", 404)
    return app.response_class(
        release["image"], mimetype="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{release["filename"]}"'})


@app.post("/api/device/firmware/report")
def api_firmware_report():
    """Step 4: a device reports what it did with an update.

    The report is authenticated like a login: the device takes a fresh
    challenge from /api/device/challenge and sends
    HMAC-SHA256(secret_key, "challenge|firmware|version|outcome"). Without it,
    anyone could claim a device is patched when it is not.
    """
    data = request.get_json(silent=True) or {}
    device_id = str(data.get("device_id", "")).strip().upper()[:40]
    version = str(data.get("version", "")).strip()
    outcome = str(data.get("outcome", "")).strip().lower()
    device_reason = " ".join(str(data.get("reason", "")).split())[:120]
    challenge = str(data.get("challenge", "")).strip().lower()
    received = str(data.get("hmac", "")).strip().lower()
    if not (device_id and version and outcome and challenge and received):
        return json_error("Please enter all required fields.", 400)
    if outcome not in ("installed", "rejected") or not crypto.parse_version(version):
        return json_error("Invalid firmware report.", 400)

    db = get_db()
    device = find_device(db, device_id)
    if not device:
        return json_error("Device not found.", 404)

    def refuse(reason, status=403):
        write_firmware_event(db, device_id, version, "REJECTED", reason)
        return jsonify(success=False, device_id=device_id, reason=reason), status

    if device["status"] == "disabled":
        return refuse("Report refused: device is disabled")
    if not HEX64.fullmatch(challenge) or not HEX64.fullmatch(received):
        return refuse("Report refused: malformed challenge or HMAC")
    issued = db.execute("SELECT * FROM challenges WHERE device_id = ? AND challenge = ?",
                        (device_id, challenge)).fetchone()
    if not issued:
        return refuse("Report refused: challenge was never issued to this device")
    consumed = db.execute("UPDATE challenges SET used = 1 WHERE id = ? AND used = 0", (issued["id"],))
    db.commit()
    if consumed.rowcount == 0:
        return refuse("Report refused: challenge already used (replay blocked)")
    if issued["created_at"] < fresh_cutoff():
        return refuse("Report refused: challenge expired")
    expected = crypto.compute_hmac(vault.decrypt(device["secret_key"]),
                                   crypto.firmware_report_message(challenge, version, outcome))
    if not crypto.verify_hmac(expected, received):
        return refuse("Report refused: HMAC mismatch (not sent by the real device)")

    # From here on the report provably comes from the device itself.
    if outcome == "rejected":
        write_firmware_event(db, device_id, version, "REJECTED",
                             f"Device refused update: {device_reason or 'no reason given'}")
        return jsonify(success=True, device_id=device_id, recorded="REJECTED")
    if not find_release(db, version):
        return refuse("Device reported a version that was never published", status=409)
    if is_downgrade(device["firmware_version"], version):
        return refuse(f"Rollback blocked: {version} is older than installed "
                      f"{device['firmware_version']}", status=409)
    install_firmware(db, device_id, version, "Signature verified on device, update installed")
    return jsonify(success=True, device_id=device_id, recorded="INSTALLED", version=version)


# ------------------------------------------------------------------- admin API

@app.post("/api/simulate/hmac")
@login_required
def api_simulate_device_hmac():
    """Plays the role of the IoT device's firmware for the classroom demo.

    A real device computes the HMAC itself, so its key never leaves it. Here
    the browser cannot know the key (we never send it), so the server does the
    device's part. It only answers for a live challenge, like a real device.
    """
    data = request.get_json(silent=True) or {}
    device_id = str(data.get("device_id", "")).strip().upper()
    challenge = str(data.get("challenge", "")).strip().lower()
    if not device_id or not challenge:
        return json_error("Please enter all required fields.", 400)

    db = get_db()
    device = find_device(db, device_id)
    if not device:
        return json_error("Device not found.", 404)
    live = HEX64.fullmatch(challenge) and db.execute(
        "SELECT 1 FROM challenges WHERE device_id = ? AND challenge = ? AND used = 0"
        " AND created_at >= ?", (device_id, challenge, fresh_cutoff())).fetchone()
    if not live:
        return json_error("Challenge is invalid or expired. Generate a new one.", 400)

    return jsonify(success=True,
                   hmac=crypto.compute_hmac(vault.decrypt(device["secret_key"]), challenge))


@app.post("/api/activity")
@login_required
def api_activity():
    """The browser calls this when the user moves the mouse or types (keeps the session alive)."""
    return jsonify(success=True, idle_timeout=IDLE_TIMEOUT_SECONDS)


@app.get("/api/devices")
@login_required
def api_list_devices():
    rows = get_db().execute(DEVICE_QUERY + " ORDER BY d.id", {"fresh": fresh_cutoff()}).fetchall()
    return jsonify(devices=[serialize_device(row) for row in rows])


@app.get("/api/devices/<device_id>")
@login_required
def api_device_detail(device_id):
    db = get_db()
    row = db.execute(DEVICE_QUERY + " WHERE d.device_id = :id",
                     {"fresh": fresh_cutoff(), "id": device_id.upper()}).fetchone()
    if not row:
        return json_error("Device not found.", 404)
    counts = db.execute(
        "SELECT SUM(result = 'SUCCESS') AS ok, SUM(result = 'FAILED') AS bad"
        " FROM authentication_logs WHERE device_id = ?", (row["device_id"],)).fetchone()
    recent = db.execute(
        "SELECT * FROM authentication_logs WHERE device_id = ?"
        " ORDER BY timestamp DESC, id DESC LIMIT 8", (row["device_id"],)).fetchall()
    return jsonify(device=serialize_device(row),
                   success=counts["ok"] or 0, failed=counts["bad"] or 0,
                   recent=[serialize_log(log) for log in recent])


@app.post("/api/devices")
@login_required
def api_add_device():
    data = request.get_json(silent=True) or {}
    device_id = str(data.get("device_id", "")).strip().upper()
    name = str(data.get("device_name", "")).strip()
    device_type = str(data.get("device_type", "")).strip()

    if not (device_id and name and device_type):
        return json_error("Please enter all required fields.", 400)
    if not DEVICE_ID_PATTERN.fullmatch(device_id):
        return json_error("Device ID must be 3-32 characters: letters, numbers, - or _.", 400)
    if not TEXT_PATTERN.fullmatch(name) or not TEXT_PATTERN.fullmatch(device_type):
        return json_error("Name and type must be 2-40 characters (letters, numbers, spaces).", 400)

    db = get_db()
    if find_device(db, device_id):
        return json_error("A device with this ID already exists.", 409)

    secret_key = crypto.generate_secret_key()  # 256-bit, from the OS secure RNG
    db.execute(
        "INSERT INTO devices (device_id, device_name, device_type, secret_key, status,"
        " is_demo, created_at) VALUES (?, ?, ?, ?, 'active', 0, ?)",
        (device_id, name, device_type, vault.encrypt(secret_key),
         dbu.to_db_time(dbu.utcnow())))
    db.commit()
    return jsonify(success=True, device_id=device_id,
                   message="Device registered successfully. Secret key generated securely."), 201


@app.post("/api/devices/<device_id>/toggle")
@login_required
def api_toggle_device(device_id):
    db = get_db()
    device = find_device(db, device_id.upper())
    if not device:
        return json_error("Device not found.", 404)
    new_status = "active" if device["status"] == "disabled" else "disabled"
    db.execute("UPDATE devices SET status = ? WHERE device_id = ?", (new_status, device["device_id"]))
    db.commit()
    verb = "enabled" if new_status == "active" else "disabled"
    return jsonify(success=True, message=f"{device['device_id']} {verb}.", enabled=new_status == "active")


def serialize_log(row) -> dict:
    """Log row -> JSON. HMAC values are not sent to the browser."""
    return {
        "id": row["id"],
        "timestamp": dbu.to_iso(row["timestamp"]),
        "device_id": row["device_id"],
        "challenge": row["challenge"],
        "result": row["result"],
        "method": "HMAC-SHA256",
        "reason": row["reason"],
        "is_demo": bool(row["is_demo"]),
    }


@app.get("/api/logs")
@login_required
def api_logs():
    result = request.args.get("result", "all").upper()
    device_id = request.args.get("device", "").strip().upper()
    query, params = "SELECT * FROM authentication_logs WHERE 1 = 1", []
    if result in ("SUCCESS", "FAILED"):
        query += " AND result = ?"
        params.append(result)
    if device_id:
        query += " AND device_id = ?"
        params.append(device_id)
    query += " ORDER BY timestamp DESC, id DESC LIMIT 300"
    rows = get_db().execute(query, params).fetchall()
    return jsonify(logs=[serialize_log(row) for row in rows])


@app.delete("/api/logs")
@login_required
def api_clear_logs():
    db = get_db()
    db.execute("DELETE FROM authentication_logs")
    db.commit()
    return jsonify(success=True, message="All security logs were cleared.")


@app.get("/api/stats")
@login_required
def api_stats():
    db = get_db()
    device_rows = db.execute(DEVICE_QUERY, {"fresh": fresh_cutoff()}).fetchall()
    devices = [serialize_device(row) for row in device_rows]

    totals = db.execute("SELECT COALESCE(SUM(result = 'SUCCESS'), 0) AS ok,"
                        " COALESCE(SUM(result = 'FAILED'), 0) AS bad"
                        " FROM authentication_logs").fetchone()
    success, failed = totals["ok"], totals["bad"]
    total_attempts = success + failed

    return jsonify(
        total_devices=len(devices),
        online_devices=sum(1 for device in devices if device["status"] == "online"),
        failed_attempts=failed,
        success_attempts=success,
        success_rate=round(success * 100 / total_attempts, 1) if total_attempts else 0,
        has_demo_data=any(device["is_demo"] for device in devices),
    )


@app.get("/api/firmware")
@login_required
def api_firmware_overview():
    db = get_db()
    versions = release_versions(db)
    latest = versions[0] if versions else None
    releases = sorted(db.execute("SELECT * FROM firmware_releases").fetchall(),
                      key=lambda row: crypto.parse_version(row["version"]), reverse=True)
    devices = db.execute("SELECT device_id, device_name, status, firmware_version, is_demo"
                         " FROM devices ORDER BY id").fetchall()
    events = db.execute("SELECT * FROM firmware_events ORDER BY timestamp DESC, id DESC LIMIT 50").fetchall()
    return jsonify(
        latest=latest,
        algorithm=crypto.FIRMWARE_SIGNATURE_ALGORITHM,
        public_key=signer.public_key_hex,
        fingerprint=crypto.public_key_fingerprint(signer.public_key_hex),
        max_bytes=FIRMWARE_MAX_BYTES,
        releases=[serialize_release(row, latest) for row in releases],
        devices=[{"device_id": row["device_id"], "device_name": row["device_name"],
                  "enabled": row["status"] == "active", "firmware_version": row["firmware_version"],
                  "firmware_status": firmware_status(row["firmware_version"], latest),
                  "is_demo": bool(row["is_demo"])} for row in devices],
        events=[{"timestamp": dbu.to_iso(row["timestamp"]), "device_id": row["device_id"],
                 "version": row["version"], "result": row["result"], "reason": row["reason"],
                 "is_demo": bool(row["is_demo"])} for row in events],
    )


@app.post("/api/firmware")
@login_required
def api_publish_firmware():
    """Step 1: the admin uploads an image; the server signs it with its private key."""
    upload = request.files.get("file")
    version = request.form.get("version", "").strip()
    notes = " ".join(request.form.get("notes", "").split())[:120]
    if not upload or not upload.filename or not version:
        return json_error("Please choose a firmware file and enter a version.", 400)
    if not crypto.parse_version(version):
        return json_error("Version must look like 1.3.0 (three numbers separated by dots).", 400)

    db = get_db()
    versions = release_versions(db)
    if version in versions:
        return json_error(f"Version {version} has already been published.", 409)
    if versions and crypto.parse_version(version) < crypto.parse_version(versions[0]):
        return json_error(f"New releases must be newer than the latest ({versions[0]}).", 409)

    image = upload.read(FIRMWARE_MAX_BYTES + 1)
    if not image:
        return json_error("The firmware file is empty.", 400)
    if len(image) > FIRMWARE_MAX_BYTES:
        return json_error(f"File is too large. The limit is {FIRMWARE_MAX_BYTES // (1024 * 1024)} MB.", 413)

    signed = signer.sign_release(version, image)
    filename = (secure_filename(upload.filename) or f"firmware-{version}.bin")[:80]
    db.execute(
        "INSERT INTO firmware_releases (version, filename, size, sha256, signature, notes, image,"
        " is_demo, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)",
        (version, filename, len(image), signed["sha256"], signed["signature"], notes, image,
         dbu.to_db_time(dbu.utcnow())))
    db.commit()
    return jsonify(success=True, version=version, sha256=signed["sha256"], signature=signed["signature"],
                   message=f"Firmware {version} signed and published."), 201


@app.post("/api/simulate/firmware-install")
@login_required
def api_simulate_firmware_install():
    """Plays the device's update routine for the classroom demo (like /api/simulate/hmac).

    The verification below is the very same crypto.verify_firmware() a real
    device - and device_simulator.py --update - runs. `attack` lets the admin
    see each kind of malicious update being refused.
    """
    data = request.get_json(silent=True) or {}
    device_id = str(data.get("device_id", "")).strip().upper()
    version = str(data.get("version", "")).strip()
    attack = str(data.get("attack", "none")).strip().lower()
    if not device_id or attack not in FIRMWARE_ATTACKS:
        return json_error("Please enter all required fields.", 400)

    db = get_db()
    device = find_device(db, device_id)
    if not device:
        return json_error("Device not found.", 404)
    if device["status"] == "disabled":
        return json_error("Device is disabled. Enable it before updating.", 403)
    versions = release_versions(db)
    if not versions:
        return json_error("No firmware has been published yet.", 400)
    current = device["firmware_version"]

    # Choose what the "server" (or the attacker) offers.
    if attack == "downgrade":
        older = [v for v in versions if current and crypto.parse_version(v) < crypto.parse_version(current)]
        if not older:
            return json_error(f"{device_id} is on the oldest version - there is nothing older to downgrade to.", 400)
        version = older[0]
    elif attack == "relabel":
        if len(versions) < 2:
            return json_error("Relabelling needs at least two published releases.", 400)
        version = versions[0]
    elif version not in versions:
        return json_error("Please choose a published firmware version.", 400)

    release = find_release(db, version)
    image, signature = release["image"], release["signature"]
    steps = []

    def step(kind, who, text):
        steps.append({"kind": kind, "who": who, "text": text})

    step("srv", "server →", f"offers firmware {version} ({release['size']:,} bytes), "
                            f"SHA-256 {release['sha256'][:16]}…, Ed25519 signature {signature[:16]}…")
    if attack == "tamper":
        position = len(image) // 2
        image = image[:position] + bytes([image[position] ^ 0x01]) + image[position + 1:]
        step("evil", "attacker", f"flips ONE bit at byte {position:,} in transit (man-in-the-middle)")
    elif attack == "forged":
        signature = crypto.FirmwareSigner.generate().sign_release(version, image)["signature"]
        step("evil", "attacker", "replaces the signature with one made by the attacker's own private key")
    elif attack == "relabel":
        oldest = find_release(db, versions[-1])
        image, signature = oldest["image"], oldest["signature"]
        step("evil", "attacker", f"sends old firmware {oldest['version']} (genuinely signed, but with known bugs) "
                                 f"relabelled as {version}")
    elif attack == "downgrade":
        step("evil", "attacker", f"offers genuine but OLDER firmware {version} (device runs {current})")

    step("dev", "device", f"SHA-256 of downloaded image = {crypto.sha256_hex(image)[:16]}…")
    step("dev", "device", f"checks the signature with its built-in public key "
                          f"({crypto.public_key_fingerprint(signer.public_key_hex)})")
    ok, reason = crypto.verify_firmware(signer.public_key_hex, version, image, signature)
    if not ok:
        step("evil", "device", f"{reason} → UPDATE REFUSED")
        write_firmware_event(db, device_id, version, "REJECTED", reason)
        return jsonify(success=False, device_id=device_id, version=version, reason=reason, steps=steps)
    step("good", "device", "signature valid - image is exactly what IoTShield signed")

    if is_downgrade(current, version):
        reason = f"Rollback blocked: {version} is older than installed {current}"
        step("evil", "device", f"{reason} → UPDATE REFUSED")
        write_firmware_event(db, device_id, version, "REJECTED", reason)
        return jsonify(success=False, device_id=device_id, version=version, reason=reason, steps=steps)

    install_firmware(db, device_id, version, "Signature verified on device, update installed")
    step("good", "device", f"installs {version} and reboots → now running {version}")
    return jsonify(success=True, device_id=device_id, version=version, previous=current,
                   reason="Signature verified, update installed", steps=steps)


# ----------------------------------------------------------- key custody (Shamir)

def custody_locked() -> bool:
    """Too many wrong passwords / wrong shares from this address in the last minute?"""
    key = request.remote_addr or "unknown"
    record = failed_custody.get(key)
    if record and time.time() - record["last"] > LOGIN_LOCK_SECONDS:
        failed_custody.pop(key, None)
        record = None
    return bool(record and record["count"] >= MAX_LOGIN_FAILURES)


def custody_failed() -> None:
    record = failed_custody.setdefault(request.remote_addr or "unknown", {"count": 0, "last": 0})
    record["count"] += 1
    record["last"] = time.time()


def custody_guard(data, need_password=True):
    """Common checks for the actions that release or remove key material.
    Returns an error response, or None when it is fine to go on."""
    if custody_locked():
        return json_error("Too many wrong attempts. Please wait a minute and try again.", 429)
    if need_password:
        password = str(data.get("password", ""))
        if not password or not secrets.compare_digest(password.encode(), ADMIN_PASSWORD.encode()):
            custody_failed()
            return json_error("The administrator password is wrong.", 403)
    return None


def custody_shares(data):
    """Shares pasted into a form -> (list of Share, None) or (None, error response)."""
    try:
        return shamir.parse_shares(str(data.get("shares", ""))), None
    except shamir.ShamirError as error:
        return None, json_error(str(error), 400)


@app.get("/api/custody")
@login_required
def api_custody_status():
    return jsonify({**vault.status(), "min_threshold": shamir.MIN_THRESHOLD, "max_shares": shamir.MAX_SHARES})


@app.post("/api/custody/split")
@login_required
def api_custody_split():
    """Create shares of the master key. They are shown ONCE and never stored."""
    data = request.get_json(silent=True) or {}
    refusal = custody_guard(data)
    if refusal:
        return refusal
    try:
        threshold, total = int(data.get("threshold", 0)), int(data.get("total", 0))
    except (TypeError, ValueError):
        return json_error("Threshold and number of shares must be whole numbers.", 400)
    try:
        parts = shamir.split_secret(vault.raw_key(), threshold, total)
    except shamir.ShamirError as error:
        return json_error(str(error), 400)
    vault.record_split(parts[0].split_id, threshold, total)
    app.logger.warning("Key custody: master key split into %s shares (threshold %s)", total, threshold)
    return jsonify(success=True, threshold=threshold, total=total,
                   fingerprint=vault.status()["fingerprint"],
                   shares=[shamir.format_share(part) for part in parts])


@app.post("/api/custody/verify")
@login_required
def api_custody_verify():
    """Do these shares rebuild this server's key? Never returns the key itself."""
    data = request.get_json(silent=True) or {}
    shares, error = custody_shares(data)
    if error:
        return error
    try:
        value = shamir.interpolate(shares)
        one_set = len({(s.split_id, s.threshold, s.total) for s in shares}) == 1
    except shamir.ShamirError as problem:
        return json_error(str(problem), 400)
    if not one_set:
        return jsonify(success=True, match=False, supplied=len(shares), needed=None,
                       message="These shares come from different splits, so they cannot be combined.")
    needed = shares[0].threshold
    match = value < 2 ** (8 * shamir.SECRET_BYTES) and \
        crypto.master_key_fingerprint(value.to_bytes(shamir.SECRET_BYTES, "big")) == vault.fingerprint_hex()
    if match:
        message = f"Yes. These {len(shares)} shares rebuild this server's real master key."
    elif len(shares) < needed:
        message = (f"Not enough: this set needs {needed} shares and {len(shares)} "
                   f"{'was' if len(shares) == 1 else 'were'} given. With too few shares the result is just "
                   f"random data, so {len(shares)} share{'' if len(shares) == 1 else 's'} reveal nothing about the key.")
    else:
        message = "No. These shares do not rebuild this server's key (they belong to a different key)."
    return jsonify(success=True, match=match, supplied=len(shares), needed=needed, message=message)


@app.post("/api/custody/seal")
@login_required
def api_custody_seal():
    """Delete the key file and lock the vault. Needs the password AND enough valid shares."""
    data = request.get_json(silent=True) or {}
    refusal = custody_guard(data)
    if refusal:
        return refusal
    if str(data.get("confirm", "")).strip() != "SEAL":
        return json_error('Type SEAL (in capitals) to confirm.', 400)
    shares, error = custody_shares(data)
    if error:
        return error
    try:
        rebuilt = shamir.combine(shares)
    except shamir.ShamirError as problem:
        return json_error(f"{problem} Sealing needs enough shares to prove you can get the key back.", 400)
    if crypto.master_key_fingerprint(rebuilt) != vault.fingerprint_hex():
        custody_failed()
        return json_error("These shares do not rebuild this server's key, so the vault was NOT sealed.", 400)
    try:
        vault.seal(shares[0].threshold, shares[0].total)
    except custody.CustodyError as problem:
        return json_error(str(problem), 400)
    app.logger.warning("Key custody: vault SEALED, key file removed")
    return jsonify(success=True, message="The vault is sealed and the key file was deleted.")


@app.post("/api/custody/unseal")
@login_required
def api_custody_unseal():
    data = request.get_json(silent=True) or {}
    refusal = custody_guard(data, need_password=False)
    if refusal:
        return refusal
    shares, error = custody_shares(data)
    if error:
        return error
    try:
        vault.unseal(shamir.combine(shares))
    except (shamir.ShamirError, custody.CustodyError) as problem:
        if not isinstance(problem, shamir.NotEnoughShares):
            custody_failed()
        return json_error(str(problem), 400)
    app.logger.warning("Key custody: vault UNSEALED (key held in memory only)")
    return jsonify(success=True, message="The vault is unsealed. Devices can authenticate again.")


@app.post("/api/custody/rotate")
@login_required
def api_custody_rotate():
    """Replace the master key: new key, every device key re-encrypted, new shares. All or nothing."""
    data = request.get_json(silent=True) or {}
    refusal = custody_guard(data)
    if refusal:
        return refusal
    try:
        threshold, total = int(data.get("threshold", 0)), int(data.get("total", 0))
    except (TypeError, ValueError):
        return json_error("Threshold and number of shares must be whole numbers.", 400)
    new_key = os.urandom(shamir.SECRET_BYTES)
    try:
        parts = shamir.split_secret(new_key, threshold, total)     # checked BEFORE anything is changed
    except shamir.ShamirError as error:
        return json_error(str(error), 400)
    state = vault.status()
    if not state["can_rotate"]:
        reason = {"sealed": "The vault is sealed. Unseal it first.",
                  "unsealed": 'The key is only in memory. Use "Write key back to file" first, then rotate.',
                  "environment": "The key comes from an environment variable, so it cannot be rotated here."
                  }.get(state["state"], "An earlier rotation did not finish. Restart the server to finish it.")
        return json_error(reason, 400)

    backup = None
    try:
        if data.get("backup", True):
            backup = dbu.backup_database(DB_PATH, os.path.join(INSTANCE_DIR, "backups"))
        old_fingerprint = state["fingerprint"]
        transition, count = vault.rotate(
            new_key,
            lambda source, target: dbu.reencrypt_device_keys(DB_PATH, source, target),
            lambda: dbu.snapshot_device_keys(DB_PATH))
    except (dbu.RotationError, custody.CustodyError) as problem:
        return json_error(f"{problem} Nothing was changed.", 400)
    except sqlite3.OperationalError:
        return json_error("The database is busy right now. Nothing was changed; please try again.", 503)
    vault.finish_rotation(transition, parts[0].split_id, threshold, total)
    new_state = vault.status()
    app.logger.warning("Key custody: master key ROTATED (%s device keys re-encrypted, %s -> %s)",
                       count, old_fingerprint, new_state["fingerprint"])
    return jsonify(success=True, devices=count, threshold=threshold, total=total,
                   old_fingerprint=old_fingerprint, fingerprint=new_state["fingerprint"],
                   backup=os.path.basename(backup) if backup else None,
                   shares=[shamir.format_share(part) for part in parts])


@app.post("/api/custody/restore-file")
@login_required
def api_custody_restore_file():
    """Stop using sealed mode: write the key back to master.key."""
    data = request.get_json(silent=True) or {}
    refusal = custody_guard(data)
    if refusal:
        return refusal
    try:
        vault.restore_key_file()
    except custody.CustodyError as problem:
        return json_error(str(problem), 400)
    app.logger.warning("Key custody: key file restored, sealed mode off")
    return jsonify(success=True, message="The key was written back to its file. Sealed mode is off.")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5001"))
    print(f"\n  IoTShield is running -> open http://127.0.0.1:{port}\n")
    app.run(host="127.0.0.1", port=port, debug=False)
