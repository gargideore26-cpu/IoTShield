"""Shamir's Secret Sharing: split a secret into pieces, rebuild it from enough of them.

The idea (for your viva): two points make exactly one straight line, three points make
exactly one parabola, and in general k points make exactly one curve of "degree k-1".

  * To SPLIT a secret into n shares with a "threshold" of k:
      1. build a random curve of degree k-1 whose height at x = 0 is the SECRET,
      2. hand out the heights at x = 1, 2, ... n. Each (x, height) pair is one share.
  * To REBUILD: any k shares pin down the curve, so read off its height at x = 0.
  * With only k-1 shares, infinitely many curves fit, and every possible secret is
    equally likely. They reveal nothing, however much computing power you have.

Example with k = 2 (a straight line): the secret is where the line crosses the
vertical axis. One point on the line tells you nothing about that crossing; two points
tell you exactly where it is.

All the arithmetic is done "modulo a prime" so the numbers stay a fixed size and the
"nothing leaks" guarantee holds exactly. The prime is 2**521 - 1 (a Mersenne prime).

This file is pure maths with no database and no Flask, so it is easy to test. The random
numbers come from `secrets` (the operating system's secure generator), never `random`.
"""

import hashlib
import re
import secrets
from dataclasses import dataclass

PRIME = 2 ** 521 - 1       # every share value is a number below this prime
SECRET_BYTES = 32          # we split 256-bit keys
SHARE_HEX = 132            # a 521-bit value written in hex (66 bytes)
MIN_THRESHOLD = 2          # with a threshold of 1, every share would simply BE the key
MAX_SHARES = 10
PREFIX = "IOTS1"           # share format version 1


class ShamirError(ValueError):
    """A share is malformed, mixed up with another set, or the shares cannot rebuild a key."""


class NotEnoughShares(ShamirError):
    def __init__(self, needed: int, have: int):
        super().__init__(f"This set needs {needed} shares, but only {have} "
                         f"{'was' if have == 1 else 'were'} given.")
        self.needed, self.have = needed, have


@dataclass(frozen=True)
class Share:
    threshold: int    # k: how many shares are needed to rebuild
    total: int        # n: how many shares were made
    split_id: str     # random label, so shares from different splits are never mixed up
    index: int        # x: which point on the curve (1..n)
    value: int        # y: the height of the curve at x


# ------------------------------------------------------------------ the maths

def _evaluate(coefficients: list, x: int) -> int:
    """Height of the curve at x (Horner's method), modulo the prime."""
    result = 0
    for coefficient in reversed(coefficients):
        result = (result * x + coefficient) % PRIME
    return result


def split_secret(secret: bytes, threshold: int, total: int) -> list:
    """Split a 32-byte secret into `total` shares, any `threshold` of which rebuild it."""
    if len(secret) != SECRET_BYTES:
        raise ShamirError(f"The secret must be exactly {SECRET_BYTES} bytes.")
    if not (MIN_THRESHOLD <= threshold <= total <= MAX_SHARES):
        raise ShamirError(f"Choose a threshold of at least {MIN_THRESHOLD}, "
                          f"no more than the number of shares, and at most {MAX_SHARES} shares.")
    # The curve: secret + a1*x + a2*x^2 + ... with RANDOM a1..a(k-1). The last one must not be
    # zero, otherwise the curve would be one degree lower and k-1 shares would be enough.
    coefficients = [int.from_bytes(secret, "big")]
    coefficients += [secrets.randbelow(PRIME) for _ in range(threshold - 1)]
    while coefficients[-1] == 0:
        coefficients[-1] = secrets.randbelow(PRIME)
    split_id = secrets.token_hex(4)
    return [Share(threshold, total, split_id, x, _evaluate(coefficients, x)) for x in range(1, total + 1)]


def interpolate(shares: list) -> int:
    """The curve's height at x = 0 (Lagrange interpolation), from whatever shares are given.

    With at least `threshold` shares of one set this is the secret. With fewer it is a
    meaningless random number, which is the whole point: it is exposed so the key-custody
    page can SHOW that too few shares reveal nothing.
    """
    indexes = [share.index for share in shares]
    if len(set(indexes)) != len(indexes):
        raise ShamirError("The same share was entered more than once.")
    secret = 0
    for share in shares:
        numerator, denominator = 1, 1
        for other in shares:
            if other.index != share.index:
                numerator = numerator * (-other.index) % PRIME
                denominator = denominator * (share.index - other.index) % PRIME
        secret = (secret + share.value * numerator * pow(denominator, -1, PRIME)) % PRIME
    return secret


def _same_set(shares: list) -> None:
    if not shares:
        raise ShamirError("No shares were given.")
    if len({(s.split_id, s.threshold, s.total) for s in shares}) != 1:
        raise ShamirError("These shares come from different splits and cannot be combined.")


def combine(shares: list) -> bytes:
    """Rebuild the 32-byte secret, or raise a clear error."""
    _same_set(shares)
    threshold = shares[0].threshold
    if len(shares) < threshold:
        raise NotEnoughShares(threshold, len(shares))
    value = interpolate(shares[:threshold])
    # Extra shares must agree, otherwise one of them is wrong.
    if len(shares) > threshold and interpolate(shares[-threshold:]) != value:
        raise ShamirError("These shares are inconsistent: at least one of them is wrong.")
    if value >= 2 ** (8 * SECRET_BYTES):
        raise ShamirError("These shares do not rebuild a valid key.")
    return value.to_bytes(SECRET_BYTES, "big")


# ------------------------------------------------------- writing shares as text

def _check(threshold, total, split_id, index, value_hex) -> str:
    return hashlib.sha256(f"{PREFIX}-{threshold}-{total}-{split_id}-{index}-{value_hex}".encode()).hexdigest()[:8]


def format_share(share: Share) -> str:
    """e.g. IOTS1-3-5-9f3a1c02-2-<132 hex digits>-<8 hex check digits>

    The last part is a checksum over the rest, so a typo is caught at once instead of
    quietly producing a wrong key later. It is computed FROM the share, so it adds no secret.
    """
    value_hex = f"{share.value:0{SHARE_HEX}x}"
    return "-".join([PREFIX, str(share.threshold), str(share.total), share.split_id, str(share.index),
                     value_hex, _check(share.threshold, share.total, share.split_id, share.index, value_hex)])


_SHARE = re.compile(rf"{PREFIX}-(\d{{1,2}})-(\d{{1,2}})-([0-9a-f]{{8}})-(\d{{1,2}})-([0-9a-f]{{{SHARE_HEX}}})-([0-9a-f]{{8}})", re.IGNORECASE)
_CANDIDATE = re.compile(rf"{PREFIX}-[0-9A-Za-z-]+", re.IGNORECASE)


def parse_share(text: str) -> Share:
    match = _SHARE.fullmatch(text.strip())
    if not match:
        raise ShamirError("That does not look like a share (it should start with IOTS1- and has no spaces).")
    threshold, total, split_id, index, value_hex, check = match.groups()
    threshold, total, index = int(threshold), int(total), int(index)
    split_id, value_hex, check = split_id.lower(), value_hex.lower(), check.lower()
    if not (MIN_THRESHOLD <= threshold <= total <= MAX_SHARES and 1 <= index <= total):
        raise ShamirError("This share has impossible numbers in it, so it was probably mistyped.")
    if check != _check(threshold, total, split_id, index, value_hex):
        raise ShamirError("The checksum of a share does not match: it was mistyped or damaged.")
    value = int(value_hex, 16)
    if value >= PRIME:
        raise ShamirError("This share is not valid.")
    return Share(threshold, total, split_id, index, value)


def parse_shares(text: str) -> list:
    """Find every share in pasted text (any mix of lines, spaces, commas, labels)."""
    tokens = _CANDIDATE.findall(text or "")
    if not tokens:
        raise ShamirError("No shares were found. Paste them one per line.")
    shares = []
    for position, token in enumerate(tokens, start=1):
        try:
            shares.append(parse_share(token))
        except ShamirError as error:
            raise ShamirError(f"Share {position}: {error}") from None
    return shares
