"""IoTShield key custody: rebuild the master key file from Shamir shares, without the web app.

The web app's Key Custody page can split the master key into shares and seal the vault.
This small tool covers the situation where the app is not available, for example the key
file was lost or you are setting up IoTShield on a new machine from a copy of the database:

    python key_custody.py recover                       # type or paste shares, one per line
    python key_custody.py recover --out instance/master.key
    python key_custody.py recover --fingerprint 3f9a:1c07:b24d:e810   # also check it is the RIGHT key

Shares are secrets, so they are read from the keyboard (not from command-line arguments,
which would end up in your shell history). Finish with an empty line.
"""

import argparse
import os
import sys

from utils import crypto, shamir

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_OUT = os.path.join(BASE_DIR, "instance", "master.key")


def read_shares() -> str:
    print("Paste the shares, one per line. Finish with an empty line.")
    lines = []
    while True:
        try:
            line = input("> ")
        except EOFError:
            break
        if not line.strip():
            break
        lines.append(line)
    return "\n".join(lines)


def recover(args) -> int:
    try:
        raw = shamir.combine(shamir.parse_shares(read_shares()))
    except shamir.ShamirError as error:
        print(f"Could not rebuild the key: {error}", file=sys.stderr)
        return 1
    fingerprint = crypto.format_fingerprint(crypto.master_key_fingerprint(raw))
    print(f"Rebuilt a key with fingerprint {fingerprint}")
    if args.fingerprint and args.fingerprint.replace(":", "").lower() != fingerprint.replace(":", ""):
        print(f"That is NOT the expected key ({args.fingerprint}). Nothing was written.", file=sys.stderr)
        return 1
    if os.path.exists(args.out) and not args.force:
        print(f"{args.out} already exists. Use --force to replace it. Nothing was written.", file=sys.stderr)
        return 1
    crypto.SecretVault.from_key_bytes(raw).write_key_file(args.out)
    print(f"Wrote the master key to {args.out} (owner-only). Start IoTShield and it will use it.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="IoTShield key custody tool")
    commands = parser.add_subparsers(dest="command", required=True)
    rebuild = commands.add_parser("recover", help="rebuild the master key file from shares")
    rebuild.add_argument("--out", default=DEFAULT_OUT, help="where to write the key (default: instance/master.key)")
    rebuild.add_argument("--fingerprint", help="the key's fingerprint, to be sure the shares are for the right key")
    rebuild.add_argument("--force", action="store_true", help="replace an existing key file")
    args = parser.parse_args()
    return recover(args)


if __name__ == "__main__":
    sys.exit(main())
