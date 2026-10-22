"""
IoTShield device simulator - acts like the firmware of a real IoT device.

It talks to the running server over plain HTTP, exactly like a real device
would. The only "cheat" is that the device's secret key is read from the local
database (a real device would have it stored in its own flash memory).

Usage (start `python app.py` in another terminal first):

    python device_simulator.py TEMP-001              # genuine device  -> SUCCESS
    python device_simulator.py TEMP-001 --attacker   # wrong key       -> FAILED
    python device_simulator.py TEMP-001 --replay     # re-send response-> FAILED

Signed firmware updates:

    python device_simulator.py MOT-003 --update             # verify + install latest
    python device_simulator.py MOT-003 --update --tamper    # image altered in transit -> refused
"""

import argparse
import json
import os
import sqlite3
import sys
import urllib.error
import urllib.request

from utils import crypto

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "database", "database.db")
MASTER_KEY_PATH = os.path.join(BASE_DIR, "instance", "master.key")
# The firmware-signing PUBLIC key. A real manufacturer burns this into the device at the factory.
FIRMWARE_PUBLIC_KEY_PATH = os.path.join(BASE_DIR, "instance", "firmware_signing.pub")


def post_json(server: str, path: str, payload: dict):
    """POST JSON and return (http_status, parsed_json). Never raises on 4xx."""
    request = urllib.request.Request(
        server + path, data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as error:
        return error.code, json.load(error)
    except urllib.error.URLError:
        sys.exit("Cannot reach the server. Start it first with:  python app.py")


def get_url(server: str, path: str):
    """GET and return (http_status, body bytes). Never raises on 4xx."""
    try:
        with urllib.request.urlopen(server + path, timeout=10) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()
    except urllib.error.URLError:
        sys.exit("Cannot reach the server. Start it first with:  python app.py")


def load_installed_version(device_id: str):
    """Firmware version currently in the device's flash (read from the database for the demo)."""
    connection = sqlite3.connect(DB_PATH)
    row = connection.execute("SELECT firmware_version FROM devices WHERE device_id = ?",
                             (device_id,)).fetchone()
    connection.close()
    return row[0] if row else None


def load_device_key(device_id: str) -> str:
    """Read this device's secret key (simulates the key stored inside the device)."""
    try:
        vault = crypto.SecretVault.from_key_file(MASTER_KEY_PATH, create=False)   # never invent a key
    except crypto.SecretVaultError:
        sys.exit("The master key file is missing. If the vault is sealed, unseal it first "
                 "(Key Custody page) or restore the key file; this simulator reads the device key from it.")
    connection = sqlite3.connect(DB_PATH)
    row = connection.execute("SELECT secret_key FROM devices WHERE device_id = ?",
                             (device_id,)).fetchone()
    connection.close()
    if not row:
        sys.exit(f"Device {device_id} is not registered.")
    return vault.decrypt(row[0])


def main():
    parser = argparse.ArgumentParser(description="IoTShield device simulator")
    parser.add_argument("device_id", help="e.g. TEMP-001")
    parser.add_argument("--server", default=os.environ.get("IOTSHIELD_SERVER", "http://127.0.0.1:5001"),
                        help="server address (default: http://127.0.0.1:5001, or $IOTSHIELD_SERVER)")
    parser.add_argument("--attacker", action="store_true", help="use a wrong (random) key")
    parser.add_argument("--replay", action="store_true", help="re-send the response afterwards")
    parser.add_argument("--update", action="store_true", help="check for, verify and install signed firmware")
    parser.add_argument("--tamper", action="store_true", help="with --update: alter one bit of the download")
    args = parser.parse_args()
    device_id = args.device_id.upper()
    if args.update:
        firmware_update(args, device_id)
        return

    secret_key = crypto.generate_secret_key() if args.attacker else load_device_key(device_id)
    if args.attacker:
        print("[attacker] using a random key - does not know the real secret")

    print(f"[device]  -> server : authentication request for {device_id}")
    status, reply = post_json(args.server, "/api/device/challenge", {"device_id": device_id})
    if status != 200:
        sys.exit(f"[server]  refused: {reply.get('error')}")
    challenge = reply["challenge"]
    print(f"[server]  -> device : challenge = {challenge}")

    response_hmac = crypto.compute_hmac(secret_key, challenge)
    print(f"[device]  computed  : HMAC-SHA256(key, challenge) = {response_hmac}")

    payload = {"device_id": device_id, "challenge": challenge, "hmac": response_hmac}
    status, reply = post_json(args.server, "/api/device/verify", payload)
    print(f"[server]  -> device : {'ACCESS GRANTED' if reply.get('success') else 'ACCESS DENIED'}"
          f"  ({reply.get('message') or reply.get('error')})")

    if args.replay:
        print("[attacker] replaying the very same response...")
        status, reply = post_json(args.server, "/api/device/verify", payload)
        print(f"[server]  -> attacker: {'ACCESS GRANTED' if reply.get('success') else 'ACCESS DENIED'}"
              f"  ({reply.get('reason') or reply.get('message')})")


def send_firmware_report(args, device_id, secret_key, version, outcome, reason=""):
    """Tell the server what happened, proving it is really us with a fresh challenge + HMAC."""
    status, reply = post_json(args.server, "/api/device/challenge", {"device_id": device_id})
    if status != 200:
        sys.exit(f"[server]  refused: {reply.get('error')}")
    challenge = reply["challenge"]
    proof = crypto.compute_hmac(secret_key, crypto.firmware_report_message(challenge, version, outcome))
    status, reply = post_json(args.server, "/api/device/firmware/report", {
        "device_id": device_id, "version": version, "outcome": outcome, "reason": reason,
        "challenge": challenge, "hmac": proof})
    print(f"[server]  -> device : report {'accepted' if reply.get('success') else 'refused'}"
          f"  ({reply.get('recorded') or reply.get('reason') or reply.get('error')})")


def firmware_update(args, device_id):
    """The device's update routine: never install anything the signature does not vouch for."""
    secret_key = load_device_key(device_id)
    if not os.path.exists(FIRMWARE_PUBLIC_KEY_PATH):
        sys.exit("No firmware public key found - start the server once first.")
    with open(FIRMWARE_PUBLIC_KEY_PATH, encoding="ascii") as key_file:
        public_key = key_file.read().strip()
    installed = load_installed_version(device_id)
    print(f"[device]  running firmware {installed or '(unknown)'}; "
          f"built-in public key {crypto.public_key_fingerprint(public_key)}")

    status, body = get_url(args.server, "/api/device/firmware/latest")
    if status != 200:
        sys.exit("[server]  no firmware published yet")
    manifest = json.loads(body)
    version, signature = manifest["version"], manifest["signature"]
    print(f"[server]  -> device : latest is {version}, signature {signature[:24]}...")

    if installed and crypto.parse_version(installed) and \
            crypto.parse_version(version) <= crypto.parse_version(installed):
        print("[device]  already up to date - nothing to do")
        return

    status, image = get_url(args.server, manifest["image_url"])
    if status != 200:
        sys.exit("[server]  could not download the image")
    print(f"[device]  downloaded {len(image):,} bytes, SHA-256 {crypto.sha256_hex(image)[:24]}...")
    if args.tamper:
        middle = len(image) // 2
        image = image[:middle] + bytes([image[middle] ^ 0x01]) + image[middle + 1:]
        print(f"[attacker] flipped one bit at byte {middle:,} in transit")

    ok, reason = crypto.verify_firmware(public_key, version, image, signature)
    if not ok:
        print(f"[device]  {reason} -> UPDATE REFUSED, keeping {installed}")
        send_firmware_report(args, device_id, secret_key, version, "rejected", reason)
        return
    print(f"[device]  Ed25519 signature valid -> installing {version} and rebooting")
    send_firmware_report(args, device_id, secret_key, version, "installed")


if __name__ == "__main__":
    main()
