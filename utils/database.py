"""SQLite helpers: schema creation, time helpers and first-launch demo data."""

import os
import random
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone

from utils import crypto

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id          TEXT NOT NULL UNIQUE,
    device_name        TEXT NOT NULL,
    device_type        TEXT NOT NULL,
    secret_key         TEXT NOT NULL,          -- encrypted, never plain text
    status             TEXT NOT NULL DEFAULT 'active'
                       CHECK (status IN ('active', 'disabled')),
    is_demo            INTEGER NOT NULL DEFAULT 0,
    created_at         TEXT NOT NULL,
    last_authenticated TEXT,
    firmware_version   TEXT                    -- last version the device reported installing
);

CREATE TABLE IF NOT EXISTS authentication_logs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id     TEXT NOT NULL,
    challenge     TEXT NOT NULL,
    received_hmac TEXT,
    expected_hmac TEXT,
    result        TEXT NOT NULL CHECK (result IN ('SUCCESS', 'FAILED')),
    reason        TEXT,
    is_demo       INTEGER NOT NULL DEFAULT 0,
    timestamp     TEXT NOT NULL
);

-- Challenges the server has issued. A challenge can be used only once and
-- only for a short time, which is what stops replay attacks.
CREATE TABLE IF NOT EXISTS challenges (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id  TEXT NOT NULL,
    challenge  TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    used       INTEGER NOT NULL DEFAULT 0
);

-- Firmware images published by the admin. `signature` is Ed25519 over
-- (version, sha256) - see utils/crypto.py, section 4.
CREATE TABLE IF NOT EXISTS firmware_releases (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    version    TEXT NOT NULL UNIQUE,
    filename   TEXT NOT NULL,
    size       INTEGER NOT NULL,
    sha256     TEXT NOT NULL,
    signature  TEXT NOT NULL,
    notes      TEXT,
    image      BLOB NOT NULL,
    is_demo    INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

-- Every update attempt a device reports, accepted or rejected.
CREATE TABLE IF NOT EXISTS firmware_events (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT NOT NULL,
    version   TEXT NOT NULL,
    result    TEXT NOT NULL CHECK (result IN ('INSTALLED', 'REJECTED')),
    reason    TEXT,
    is_demo   INTEGER NOT NULL DEFAULT 0,
    timestamp TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);

CREATE INDEX IF NOT EXISTS idx_logs_time   ON authentication_logs (timestamp);
CREATE INDEX IF NOT EXISTS idx_logs_device ON authentication_logs (device_id);
"""

TIME_FORMAT = "%Y-%m-%dT%H:%M:%S"


# ---------------------------------------------------------------- time helpers

def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0, tzinfo=None)


def to_db_time(moment: datetime) -> str:
    return moment.strftime(TIME_FORMAT)


def from_db_time(text: str) -> datetime:
    return datetime.strptime(text, TIME_FORMAT)


def to_iso(text):
    """DB time (UTC) -> ISO string with 'Z', so the browser shows local time."""
    return f"{text}Z" if text else None


# ------------------------------------------------------------------ connection

def connect(db_path: str) -> sqlite3.Connection:
    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


# ------------------------------------------------------- master-key rotation helpers

class RotationError(Exception):
    """A master-key rotation could not be done; the message says why and nothing was changed."""


def reencrypt_device_keys(db_path: str, source, target) -> int:
    """Re-encrypt every device secret key from `source` to `target`, in ONE transaction.

    All-or-nothing: either every device key is now encrypted with the new key, or (on any
    error at all) the database is exactly as it was. Safe to run again, since keys that are
    already on the new key are simply re-encrypted with it. Returns how many were done.
    """
    connection = connect(db_path)
    connection.isolation_level = None            # we control the transaction ourselves
    try:
        connection.execute("BEGIN IMMEDIATE")    # take the write lock now: nobody else changes devices meanwhile
        updates = []
        for row in connection.execute("SELECT id, device_id, secret_key FROM devices").fetchall():
            try:
                plain = source.decrypt(row["secret_key"])
            except crypto.SecretVaultError:
                raise RotationError(f"The key of device {row['device_id']} cannot be decrypted with the "
                                    "current master key.") from None
            token = target.encrypt(plain)
            if target.decrypt(token) != plain:   # trust nothing: prove the new ciphertext reads back identically
                raise RotationError(f"Self-check failed for device {row['device_id']}.")
            updates.append((token, row["id"]))
        connection.executemany("UPDATE devices SET secret_key = ? WHERE id = ?", updates)
        for (secret_key,) in connection.execute("SELECT secret_key FROM devices").fetchall():
            target.decrypt(secret_key)           # every stored key must now open with the NEW key alone
        connection.execute("COMMIT")
        return len(updates)
    except BaseException:
        try:
            connection.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        raise
    finally:
        connection.close()


def snapshot_device_keys(db_path: str) -> list:
    """Every stored (id, encrypted key) pair, to compare before and after: did anything change?"""
    connection = connect(db_path)
    try:
        return [tuple(row) for row in connection.execute("SELECT id, secret_key FROM devices ORDER BY id")]
    finally:
        connection.close()


def backup_database(db_path: str, directory: str) -> str:
    """A consistent copy of the database (SQLite's online backup), saved owner-only. Returns its path.

    The copy holds device keys encrypted with whatever master key is current NOW, so keep it
    as carefully as the key itself, and delete it once it is no longer needed."""
    os.makedirs(directory, mode=0o700, exist_ok=True)
    stamp = utcnow().strftime("%Y%m%dT%H%M%SZ")
    target = os.path.join(directory, f"database-before-rotation-{stamp}-{secrets.token_hex(2)}.db")
    source, copy = connect(db_path), sqlite3.connect(target)
    try:
        source.backup(copy)
    finally:
        copy.close()
        source.close()
    os.chmod(target, 0o600)
    return target


def init_db(db_path: str, vault: crypto.SecretVault, signer: crypto.FirmwareSigner = None) -> None:
    """Create tables and, on the very first launch, the demo data."""
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    connection = connect(db_path)
    try:
        connection.executescript(SCHEMA)
        migrate(connection)
        already_seeded = connection.execute(
            "SELECT value FROM meta WHERE key = 'demo_seeded'"
        ).fetchone()
        if not already_seeded:
            seed_demo_data(connection, vault)
            connection.execute(
                "INSERT INTO meta (key, value) VALUES ('demo_seeded', '1')"
            )
        firmware_seeded = connection.execute(
            "SELECT value FROM meta WHERE key = 'firmware_seeded'"
        ).fetchone()
        if signer and not firmware_seeded:
            seed_demo_firmware(connection, signer)
            connection.execute(
                "INSERT INTO meta (key, value) VALUES ('firmware_seeded', '1')"
            )
        connection.commit()
    finally:
        connection.close()


def migrate(connection: sqlite3.Connection) -> None:
    """Upgrade databases created by older versions of IoTShield in place."""
    columns = {row["name"] for row in connection.execute("PRAGMA table_info(devices)")}
    if "firmware_version" not in columns:
        connection.execute("ALTER TABLE devices ADD COLUMN firmware_version TEXT")


# ------------------------------------------------------------------- demo data

DEMO_DEVICES = [
    ("TEMP-001", "Lab Temperature Node", "Temperature Sensor"),
    ("CAM-002", "Entrance Camera", "Security Camera"),
    ("MOT-003", "Corridor Motion Detector", "Motion Sensor"),
    ("GPS-004", "Fleet GPS Tracker", "GPS Tracker"),
]


def seed_demo_data(connection: sqlite3.Connection, vault: crypto.SecretVault) -> None:
    """Insert 4 demo devices and about a day of sample authentication history.

    Everything inserted here is flagged is_demo = 1, and the UI shows a DEMO
    badge on it. The HMAC values are computed with the real functions, so the
    sample history is cryptographically genuine, only the events are invented.
    """
    now = utcnow()
    demo_random = random.Random()  # fine here: demo timestamps are not secret
    secrets_by_device = {}

    for device_id, name, device_type in DEMO_DEVICES:
        secret_key = crypto.generate_secret_key()
        secrets_by_device[device_id] = secret_key
        connection.execute(
            "INSERT INTO devices (device_id, device_name, device_type, secret_key,"
            " status, is_demo, created_at) VALUES (?, ?, ?, ?, 'active', 1, ?)",
            (device_id, name, device_type, vault.encrypt(secret_key),
             to_db_time(now - timedelta(days=3))),
        )

    device_ids = [device[0] for device in DEMO_DEVICES]

    # (device, minutes ago, success?)
    history = [
        ("TEMP-001", 2, True), ("CAM-002", 5, True),
        ("GPS-004", 8, True), ("MOT-003", 20, True),        # latest per device
        ("CAM-002", 47, False), ("MOT-003", 190, False),    # a few failures
        ("GPS-004", 540, False),
    ]
    for _ in range(36):
        history.append((
            demo_random.choice(device_ids),
            demo_random.uniform(25, 24 * 60 - 10),
            demo_random.random() < 0.96,
        ))

    last_success = {}
    for device_id, minutes_ago, success in history:
        moment = now - timedelta(minutes=minutes_ago)
        challenge = crypto.generate_challenge()
        expected = crypto.compute_hmac(secrets_by_device[device_id], challenge)
        if success:
            received, reason = expected, "HMAC verified"
            last_success[device_id] = max(moment, last_success.get(device_id, moment))
        else:
            received, reason = secrets.token_hex(32), "HMAC mismatch"
        connection.execute(
            "INSERT INTO authentication_logs (device_id, challenge, received_hmac,"
            " expected_hmac, result, reason, is_demo, timestamp)"
            " VALUES (?, ?, ?, ?, ?, ?, 1, ?)",
            (device_id, challenge, received, expected,
             "SUCCESS" if success else "FAILED", reason, to_db_time(moment)),
        )

    for device_id, moment in last_success.items():
        connection.execute(
            "UPDATE devices SET last_authenticated = ? WHERE device_id = ?",
            (to_db_time(moment), device_id),
        )


DEMO_FIRMWARE = [
    ("1.0.0", 3, "Initial release"),
    ("1.1.0", 2, "Faster sensor sampling, bug fixes"),
    ("1.2.0", 1, "Security patch: hardened network stack"),
]
# Which demo device runs which version, so the fleet view has something to update.
DEMO_DEVICE_FIRMWARE = {"TEMP-001": "1.2.0", "CAM-002": "1.1.0", "MOT-003": "1.0.0", "GPS-004": "1.2.0"}


def demo_firmware_image(version: str) -> bytes:
    """A small fake firmware binary. Deterministic, so the same version always has the same hash."""
    header = f"IOTSHIELD-FW {version}\n".encode()
    return header + random.Random(f"firmware-{version}").randbytes(8192 - len(header))


def seed_demo_firmware(connection: sqlite3.Connection, signer: crypto.FirmwareSigner) -> None:
    """Publish three genuinely signed demo releases (flagged is_demo = 1)."""
    now = utcnow()
    for version, days_ago, notes in DEMO_FIRMWARE:
        image = demo_firmware_image(version)
        signed = signer.sign_release(version, image)
        connection.execute(
            "INSERT OR IGNORE INTO firmware_releases (version, filename, size, sha256, signature,"
            " notes, image, is_demo, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)",
            (version, f"iotshield-fw-{version}.bin", len(image), signed["sha256"],
             signed["signature"], notes, image, to_db_time(now - timedelta(days=days_ago))),
        )
    for device_id, version in DEMO_DEVICE_FIRMWARE.items():
        connection.execute(
            "UPDATE devices SET firmware_version = ? WHERE device_id = ? AND firmware_version IS NULL",
            (version, device_id),
        )
