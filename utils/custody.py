"""Key custody: who holds the master key, and is the vault open or sealed?

The master key encrypts every device secret key in the database. Normally it sits in
`instance/master.key`, so whoever steals that file (plus the database) can read every
device key. Key custody lets the administrator do better in three steps:

  1. SPLIT the key into shares (Shamir, see shamir.py) and give them to different people.
  2. SEAL the vault: the key file is deleted from the disk. Until someone unseals it, the
     server cannot decrypt a single device key, so a stolen disk or backup is useless.
  3. UNSEAL after a restart by entering enough shares. The rebuilt key lives only in the
     server's memory and is never written back to disk.

And if a share ever leaks, ROTATE the key: make a brand-new master key, re-encrypt every
device key with it, and issue new shares. The old shares then rebuild a key that opens
nothing. Rotation is done so that a crash or error at ANY moment loses nothing: for a short
while the key file holds both keys (new first), so every device key can always be opened.

What is kept on disk is only a small non-secret note, `instance/vault.json`: the key's
fingerprint (to recognise the right key), the split settings (e.g. 3 of 5) and whether
the vault is sealed. Without that note, a missing key file looks the same as a first run,
and the old code would quietly invent a NEW key that cannot decrypt anything.

`app.py` uses a VaultGuard exactly like a SecretVault (encrypt / decrypt). When sealed,
both raise VaultSealed instead.
"""

import json
import os
import threading
from datetime import datetime, timezone

from utils import crypto


class VaultSealed(Exception):
    """The vault is sealed: the master key is not available until enough shares are entered."""


class CustodyError(Exception):
    """A key-custody request that cannot be done right now; the message is safe to show."""


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class VaultGuard:
    def __init__(self, instance_dir: str):
        self.key_path = os.path.join(instance_dir, "master.key")
        self.meta_path = os.path.join(instance_dir, "vault.json")
        self._env = bool(os.environ.get("IOTSHIELD_MASTER_KEY"))
        self._lock = threading.RLock()
        self.gate = threading.RLock() # held by every request that uses the vault, and by key rotation:
                                      # no login or new device can be half-done while keys are swapped
        self._vault = None            # a crypto.SecretVault while open, None while sealed
        self._load()

    @classmethod
    def open(cls, instance_dir: str) -> "VaultGuard":
        return cls(instance_dir)

    # ------------------------------------------------------------- the note on disk

    def _read_meta(self) -> dict:
        try:
            with open(self.meta_path, encoding="utf-8") as meta_file:
                data = json.load(meta_file)
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def _write_meta(self, meta: dict) -> None:
        os.makedirs(os.path.dirname(self.meta_path), exist_ok=True)
        temporary = self.meta_path + ".tmp"
        with open(temporary, "w", encoding="utf-8") as meta_file:
            json.dump(meta, meta_file, indent=2)
        os.replace(temporary, self.meta_path)

    def _load(self) -> None:
        if self._env:                                    # key supplied by the environment: nothing to seal
            self._vault = crypto.SecretVault.from_key_file(self.key_path)
            return
        meta = self._read_meta()
        if meta.get("sealed"):
            if os.path.exists(self.key_path):
                # The key file was put back by hand. Accept it only if it is the RIGHT key.
                vault = crypto.SecretVault.from_key_file(self.key_path, create=False)
                if crypto.master_key_fingerprint(vault.key_bytes()) == meta.get("fingerprint"):
                    self._vault = vault
                    meta["sealed"] = False
                    self._write_meta(meta)
                    return
            self._vault = None                           # sealed: never create a new key
            return
        self._vault = crypto.SecretVault.from_key_file(self.key_path)   # normal (creates the key on first run)

    # ------------------------------------------------------------ same shape as SecretVault

    @property
    def sealed(self) -> bool:
        return self._vault is None

    def encrypt(self, plain_secret: str) -> str:
        if self._vault is None:
            raise VaultSealed()
        return self._vault.encrypt(plain_secret)

    def decrypt(self, encrypted_secret: str) -> str:
        if self._vault is None:
            raise VaultSealed()
        return self._vault.decrypt(encrypted_secret)

    # -------------------------------------------------------------------- key custody

    def raw_key(self) -> bytes:
        if self._vault is None:
            raise VaultSealed()
        return self._vault.key_bytes()

    def fingerprint_hex(self):
        """16 hex characters identifying the master key (safe to show), or None if unknown."""
        if self._vault is not None:
            return crypto.master_key_fingerprint(self._vault.key_bytes())
        return self._read_meta().get("fingerprint")

    def status(self) -> dict:
        meta = self._read_meta()
        if self._env:
            state = "environment"
        elif self._vault is None:
            state = "sealed"
        elif meta.get("sealed"):
            state = "unsealed"        # sealed mode, but unlocked: the key exists only in memory
        else:
            state = "normal"          # the key sits in master.key
        fingerprint = self.fingerprint_hex()
        issued = None
        if meta.get("split_id"):
            issued = {"threshold": meta.get("threshold"), "total": meta.get("shares"),
                      "issued_at": meta.get("split_at"), "split_id": meta.get("split_id")}
        unfinished = self._vault is not None and self._vault.key_count > 1
        return {"state": state, "sealed": state == "sealed",
                "fingerprint": crypto.format_fingerprint(fingerprint) if fingerprint else None,
                "shares": issued,
                "can_split": state != "sealed", "can_seal": state in ("normal", "unsealed"),
                "can_restore_file": state == "unsealed",
                "can_rotate": state == "normal" and not unfinished,
                "rotation_unfinished": unfinished,
                "rotations": int(meta.get("rotations", 0)), "rotated_at": meta.get("rotated_at"),
                "sealed_at": meta.get("sealed_at")}

    def record_split(self, split_id: str, threshold: int, total: int) -> None:
        """Remember (not the shares!) that a split happened and how it was set up."""
        with self._lock:
            meta = self._read_meta()
            meta.update(fingerprint=self.fingerprint_hex(), split_id=split_id, threshold=threshold,
                        shares=total, split_at=_now())
            meta.setdefault("sealed", False)
            self._write_meta(meta)

    def seal(self, threshold=None, total=None) -> None:
        """Forget the key now, and delete its file so a restart also starts sealed."""
        with self._lock:
            if self._env:
                raise CustodyError("The master key comes from the IOTSHIELD_MASTER_KEY environment variable, "
                                   "so there is no key file to remove.")
            if self._vault is None:
                raise CustodyError("The vault is already sealed.")
            meta = self._read_meta()
            meta.update(fingerprint=self.fingerprint_hex(), sealed=True, sealed_at=_now())
            if threshold and not meta.get("threshold"):
                meta.update(threshold=threshold, shares=total)
            self._write_meta(meta)               # note first: if we crash after this, a restart is still safe
            if os.path.exists(self.key_path):
                os.remove(self.key_path)
            self._vault = None

    def unseal(self, raw_key: bytes) -> None:
        """Open a sealed vault with a rebuilt key. The key is held in memory only."""
        with self._lock:
            if self._vault is not None:
                raise CustodyError("The vault is not sealed.")
            if crypto.master_key_fingerprint(raw_key) != self._read_meta().get("fingerprint"):
                raise CustodyError("These shares rebuild a key that does not belong to this server.")
            self._vault = crypto.SecretVault.from_key_bytes(raw_key)

    def restore_key_file(self) -> None:
        """Leave sealed mode: write the (in-memory) key back to master.key."""
        with self._lock:
            if self._vault is None:
                raise CustodyError("Unseal the vault first: the key is not available.")
            meta = self._read_meta()
            if not meta.get("sealed"):
                raise CustodyError("The key is already stored in its file.")
            self._vault.write_key_file(self.key_path)
            meta["sealed"] = False
            self._write_meta(meta)

    # --------------------------------------------------------------- key rotation

    def rotate(self, new_raw_key: bytes, reencrypt, snapshot):
        """Replace the master key with `new_raw_key`. Returns (new_vault, devices_done).

        `reencrypt(source_vault, target_vault)` must re-encrypt the whole database in ONE
        transaction (see database.reencrypt_device_keys); `snapshot()` returns the stored
        encrypted keys, so after a failure we can tell whether the database changed.
        Order of events, and why it is safe:

          1. Write a key file with BOTH keys (new first). From now on every secret can be
             opened with either, and anything new is encrypted with the new key.
          2. Re-encrypt the database in one transaction. If it fails, nothing changed.
          3. (the caller then records the new shares and calls finish_rotation, which
             removes the old key from the file.)

        A crash after step 1 leaves a perfectly working two-key file; recover_rotation()
        finishes the job on the next start.
        """
        with self._lock:
            if self._env:
                raise CustodyError("The master key comes from the IOTSHIELD_MASTER_KEY environment "
                                   "variable, so it cannot be rotated from here.")
            if self._vault is None:
                raise VaultSealed()
            if self.status()["state"] != "normal":
                raise CustodyError("The key must be stored in its file to rotate it. "
                                   'Use "Write key back to file" first.')
            if self._vault.key_count > 1:
                raise CustodyError("An earlier rotation did not finish. Restart the server and it will finish it.")
            old = self._vault
            before = snapshot()
            transition = crypto.SecretVault.rotating(new_raw_key, old)
            transition.write_key_file(self.key_path)
            self._vault = transition
            try:
                count = reencrypt(transition, crypto.SecretVault.from_key_bytes(new_raw_key))
            except BaseException:
                try:
                    unchanged = snapshot() == before
                except Exception:
                    unchanged = False                    # cannot tell: the safe choice is to keep both keys
                if unchanged:                            # the database was NOT touched: back to the old key alone
                    old.write_key_file(self.key_path)
                    self._vault = old
                raise                                    # (otherwise keep both keys: everything still opens)
            return transition, count

    def finish_rotation(self, transition, split_id: str, threshold: int, total: int) -> None:
        """Last step: remember the new shares' settings, then drop the old key from the file."""
        with self._lock:
            only_new = transition.primary_only()
            meta = self._read_meta()
            meta.update(fingerprint=crypto.master_key_fingerprint(only_new.key_bytes()), split_id=split_id,
                        threshold=threshold, shares=total, split_at=_now(), rotated_at=_now(),
                        rotations=int(meta.get("rotations", 0)) + 1, sealed=False)
            self._write_meta(meta)                       # note first, then trim: a crash in between is harmless
            only_new.write_key_file(self.key_path)
            self._vault = only_new

    def recover_rotation(self, reencrypt) -> bool:
        """If the key file holds two keys, an earlier rotation was cut short: finish it.
        Re-encrypting is repeatable, so this is safe whatever state the database is in.
        The shares of the new key were never shown (or are for the old key), so they are forgotten:
        the administrator makes new ones."""
        with self._lock:
            if self._env or self._vault is None or self._vault.key_count < 2:
                return False
            only_new = self._vault.primary_only()
            reencrypt(self._vault, only_new)
            meta = self._read_meta()
            for field in ("split_id", "threshold", "shares", "split_at"):
                meta.pop(field, None)
            meta.update(fingerprint=crypto.master_key_fingerprint(only_new.key_bytes()), rotated_at=_now(),
                        rotations=int(meta.get("rotations", 0)) + 1)
            self._write_meta(meta)
            only_new.write_key_file(self.key_path)
            self._vault = only_new
            return True
