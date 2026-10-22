"""
IoTShield cryptography helpers.

This file contains ALL the cryptography used by the project, so it is the
place to look when you are explaining the project in your viva.

Three separate ideas are used here:

1. Challenge-Response authentication with HMAC-SHA256
   (generate_challenge, compute_hmac, verify_hmac)

2. Protecting the device secret keys while they sit in the database
   (SecretVault, which uses Fernet = AES-128-CBC + HMAC-SHA256 authentication)

3. A one-time code for the admin's second login factor, emailed to them
   (generate_otp_code) - a random code from the OS's secure RNG, the same
   `secrets` module used for challenges and device keys above. Unlike the
   HMAC constructions, there is no "secret key" to derive this from: the
   server just remembers the code it generated until it is used or expires.

4. Signed firmware updates with Ed25519 digital signatures
   (FirmwareSigner, verify_firmware) - public-key cryptography, so devices
   can CHECK a firmware image without holding anything that could SIGN one.
"""

import base64
import hashlib
import hmac
import os
import secrets

import re

from cryptography.exceptions import InvalidSignature
from cryptography.fernet import Fernet, InvalidToken, MultiFernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

CHALLENGE_BYTES = 32   # 32 random bytes  -> 64 hex characters (256 bits)
SECRET_KEY_BYTES = 32  # 32 random bytes  -> 256-bit device secret key


# --------------------------------------------------------------------------
# 1. Challenge-Response + HMAC
# --------------------------------------------------------------------------

def generate_challenge() -> str:
    """Return a fresh, unpredictable challenge (hex string).

    `secrets` uses the operating system's cryptographically secure random
    number generator. The normal `random` module must NEVER be used for this,
    because its output can be predicted.
    """
    return secrets.token_hex(CHALLENGE_BYTES)


def generate_secret_key() -> str:
    """Return a new random 256-bit device secret key (hex string)."""
    return secrets.token_hex(SECRET_KEY_BYTES)


def compute_hmac(secret_key_hex: str, challenge_hex: str) -> str:
    """Compute HMAC-SHA256(secret_key, challenge) and return it as hex.

    This is what the IoT device does with its secret key, and it is exactly
    what the server does again to obtain the *expected* value.
    The secret key itself is never transmitted - only the HMAC is.
    """
    key_bytes = bytes.fromhex(secret_key_hex)
    message = challenge_hex.encode("ascii")
    return hmac.new(key_bytes, message, hashlib.sha256).hexdigest()


def verify_hmac(expected_hmac: str, received_hmac: str) -> bool:
    """Compare two HMACs in constant time.

    A normal `==` stops at the first different character, so the time it
    takes leaks how many leading characters were correct (a timing attack).
    `hmac.compare_digest` always takes the same time.
    """
    return hmac.compare_digest(
        expected_hmac.encode("ascii"), received_hmac.lower().encode("ascii")
    )


# --------------------------------------------------------------------------
# 2. Encrypting the secret keys at rest
# --------------------------------------------------------------------------

class SecretVaultError(Exception):
    """Raised when a stored secret cannot be decrypted."""


class SecretVault:
    """Encrypts / decrypts device secret keys before they touch the database.

    HMAC needs the original secret key on the server, so we cannot store a
    one-way hash of it (like a password). Instead the key is ENCRYPTED with a
    master key. The master key lives in a file outside the database, so a
    stolen database.db alone does not reveal any device key.
    """

    def __init__(self, master_key: bytes, older_keys=()):
        """`master_key` encrypts everything new. `older_keys` can still DECRYPT, and exist only
        while a master-key rotation is in progress (Fernet's MultiFernet tries each key in turn)."""
        self._master_key = master_key
        self._keys = [master_key, *older_keys]
        fernets = [Fernet(key) for key in self._keys]
        self._fernet = fernets[0] if len(fernets) == 1 else MultiFernet(fernets)

    @classmethod
    def rotating(cls, new_raw_key: bytes, previous: "SecretVault") -> "SecretVault":
        """A vault that encrypts with a NEW key but still opens everything the previous key made.
        This is what makes rotation safe: at every moment, every device key can be decrypted."""
        return cls(base64.urlsafe_b64encode(new_raw_key), older_keys=previous._keys)

    @property
    def key_count(self) -> int:
        return len(self._keys)

    def primary_only(self) -> "SecretVault":
        """The same vault with the older keys dropped (the last step of a rotation)."""
        return SecretVault(self._master_key)

    @classmethod
    def from_key_bytes(cls, raw_key: bytes) -> "SecretVault":
        """Rebuild a vault from the 32 raw key bytes (what key_bytes() gives, or Shamir shares rebuild)."""
        return cls(base64.urlsafe_b64encode(raw_key))

    def key_bytes(self) -> bytes:
        """The master key as 32 raw bytes. Only the key-custody code (splitting into shares,
        sealing) should ever call this: it is the one thing that protects every device key."""
        return base64.urlsafe_b64decode(self._master_key)

    def write_key_file(self, path: str) -> None:
        """Save the key(s) to `path` (owner-only, one per line, newest first), replacing any file there."""
        os.makedirs(os.path.dirname(path), exist_ok=True)
        temporary = path + ".tmp"
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as key_file:
            key_file.write(b"\n".join(self._keys) + b"\n")
            key_file.flush()
            os.fsync(key_file.fileno())
        os.replace(temporary, path)

    @classmethod
    def from_key_file(cls, path: str, create: bool = True) -> "SecretVault":
        """Load the master key from `path`, creating it on first run.

        Pass create=False when a missing file must be an ERROR rather than a reason to invent
        a brand-new key (a new key could not decrypt any existing device key).
        """
        env_key = os.environ.get("IOTSHIELD_MASTER_KEY")
        if env_key:
            return cls(env_key.encode())

        if not os.path.exists(path) and not create:
            raise SecretVaultError(f"The master key file {path} does not exist.")
        if not os.path.exists(path):
            os.makedirs(os.path.dirname(path), exist_ok=True)
            # 0o600 = only the owner may read/write the file
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as key_file:
                key_file.write(Fernet.generate_key())

        with open(path, "rb") as key_file:
            keys = key_file.read().split()          # normally one key; two while a rotation is in progress
        if not keys:
            raise SecretVaultError(f"The master key file {path} is empty.")
        return cls(keys[0], older_keys=keys[1:])

    def encrypt(self, plain_secret: str) -> str:
        return self._fernet.encrypt(plain_secret.encode()).decode()

    def decrypt(self, encrypted_secret: str) -> str:
        try:
            return self._fernet.decrypt(encrypted_secret.encode()).decode()
        except InvalidToken as error:
            raise SecretVaultError(
                "Stored device key cannot be decrypted (wrong master key)."
            ) from error


def master_key_fingerprint(raw_key: bytes) -> str:
    """A short public check value for a master key, e.g. "3f9a1c07b24de810".

    It lets people compare keys ("do the shares rebuild the key this server uses?") without
    ever showing the key. It is a one-way hash of a random 256-bit key, so it gives nothing
    away. The label in front keeps it different from every other hash in the project.
    """
    return hashlib.sha256(b"IoTShield-master-key-fingerprint|" + raw_key).hexdigest()[:16]


def format_fingerprint(fingerprint_hex: str) -> str:
    """"3f9a1c07b24de810" -> "3f9a:1c07:b24d:e810" (same style as the firmware key fingerprint)."""
    return ":".join(fingerprint_hex[i:i + 4] for i in range(0, len(fingerprint_hex), 4))


# --------------------------------------------------------------------------
# 3. One-time email codes for the admin login
# --------------------------------------------------------------------------
#
# This is a different idea from HOTP/TOTP: there is no shared secret the
# server and the admin both hold. Instead the server picks a fresh random
# code with the OS's secure RNG (`secrets`, never the ordinary `random`
# module - see generate_challenge above), remembers it server-side, and
# hands it to the admin over a channel an attacker who only has the
# password should not also control: their email inbox. Whoever can
# produce the code proves they can read that inbox right now.
#
# Because the code is random rather than derived from anything, it cannot
# be recomputed or predicted - it has to be looked up - so the server must
# hold onto it (with an expiry and a use-once flag) until it is checked.

EMAIL_OTP_DIGITS = 6


def generate_otp_code() -> str:
    """A fresh, unpredictable 6-digit code (as a zero-padded string) to email to the admin."""
    return str(secrets.randbelow(10 ** EMAIL_OTP_DIGITS)).zfill(EMAIL_OTP_DIGITS)


def verify_otp_code(expected_code: str, submitted_code: str) -> bool:
    """Compare two codes in constant time (same reasoning as verify_hmac above)."""
    submitted_code = (submitted_code or "").strip()
    if not (submitted_code.isdigit() and len(submitted_code) == EMAIL_OTP_DIGITS):
        return False
    return hmac.compare_digest(expected_code.encode("ascii"), submitted_code.encode("ascii"))


# --------------------------------------------------------------------------
# 4. Signed firmware updates (Ed25519 digital signatures)
# --------------------------------------------------------------------------
#
# Why not HMAC here too? HMAC needs the SAME secret on both sides. Every
# device would then hold a key that can also *create* valid firmware - steal
# it from one cheap sensor and you can push malware to the whole fleet.
#
# A digital signature splits the key in two:
#   * the PRIVATE key stays on the server and is the only thing that can sign;
#   * the PUBLIC key is built into every device and can only verify.
# Extracting the public key from a device gives an attacker nothing.
#
# What is signed is a small "manifest" binding the version number to the
# SHA-256 hash of the image. Signing the hash (not the image directly) is
# standard practice; including the version stops an attacker from taking an
# old, genuinely-signed image with a known bug and relabelling it as new.

FIRMWARE_SIGNATURE_ALGORITHM = "Ed25519"
VERSION_PATTERN = re.compile(r"(0|[1-9]\d{0,3})\.(0|[1-9]\d{0,3})\.(0|[1-9]\d{0,3})")


def parse_version(text: str):
    """"1.10.2" -> (1, 10, 2), so versions compare numerically (1.10 > 1.9). None if invalid."""
    match = VERSION_PATTERN.fullmatch(str(text or "").strip())
    return tuple(int(part) for part in match.groups()) if match else None


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def firmware_manifest(version: str, image_sha256: str) -> bytes:
    """The exact bytes that get signed for a firmware release."""
    return f"IoTShield-firmware|v1|{version}|{image_sha256}".encode("ascii")


class FirmwareSigner:
    """Holds the server's Ed25519 private key and signs firmware releases."""

    def __init__(self, private_key: Ed25519PrivateKey):
        self._private_key = private_key

    @classmethod
    def generate(cls) -> "FirmwareSigner":
        """A brand-new key pair (used to play the attacker, who has their own key)."""
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_key_file(cls, path: str) -> "FirmwareSigner":
        """Load the signing key from `path` (PEM), creating it on first run.

        The matching public key is also written next to it as `<name>.pub`
        (hex), which is what a device manufacturer would burn into firmware.
        """
        if not os.path.exists(path):
            os.makedirs(os.path.dirname(path), exist_ok=True)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as key_file:
                key_file.write(Ed25519PrivateKey.generate().private_bytes(
                    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption()))
        with open(path, "rb") as key_file:
            signer = cls(serialization.load_pem_private_key(key_file.read(), password=None))
        public_path = os.path.splitext(path)[0] + ".pub"
        with open(public_path, "w", encoding="ascii") as public_file:
            public_file.write(signer.public_key_hex + "\n")
        return signer

    @property
    def public_key_hex(self) -> str:
        """The 32-byte public key as hex - safe to publish, can only verify."""
        return self._private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()

    def sign_release(self, version: str, image: bytes) -> dict:
        digest = sha256_hex(image)
        signature = self._private_key.sign(firmware_manifest(version, digest))
        return {"version": version, "sha256": digest, "signature": signature.hex()}


def public_key_fingerprint(public_key_hex: str) -> str:
    """Short, human-comparable ID of a public key, e.g. "3f9a:1c07:..."."""
    digest = sha256_hex(bytes.fromhex(public_key_hex))[:16]
    return ":".join(digest[i:i + 4] for i in range(0, 16, 4))


def verify_firmware(public_key_hex: str, version: str, image: bytes, signature_hex: str):
    """What a DEVICE runs before installing an update. Returns (ok, reason).

    1. hash the image it actually downloaded,
    2. rebuild the manifest for the version it was told it is getting,
    3. check the server's signature over that manifest with the built-in public key.
    Any change to the image, the version, or the signature makes step 3 fail.
    """
    try:
        public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
        signature = bytes.fromhex(signature_hex)
    except ValueError:
        return False, "Malformed public key or signature"
    if parse_version(version) is None:
        return False, "Invalid version number"
    try:
        public_key.verify(signature, firmware_manifest(version, sha256_hex(image)))
    except InvalidSignature:
        return False, "Signature check failed - image or version was modified, or not signed by IoTShield"
    return True, "Signature valid"


def firmware_report_message(challenge_hex: str, version: str, outcome: str) -> str:
    """What a device HMACs to prove it really sent an update report (see compute_hmac)."""
    return f"{challenge_hex}|firmware|{version}|{outcome}"
