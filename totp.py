#!/usr/bin/env python3
"""
TOTP 2FA Library
=================

A from-scratch, pure standard-library implementation of:

  * HOTP  - HMAC-Based One-Time Password Algorithm  (RFC 4226)
  * TOTP  - Time-Based One-Time Password Algorithm   (RFC 6238)

No third-party dependencies (no `pyotp`). Only `hmac`, `hashlib`,
`base64`, `struct`, `secrets`, and other pieces of the standard library
are used.

See README.md for a full explanation of the algorithm and usage examples.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import sys
import time
from urllib.parse import quote

# ---------------------------------------------------------------------------
# HOTP - RFC 4226
# ---------------------------------------------------------------------------

_DIGEST_MAP = {
    "SHA1": hashlib.sha1,
    "SHA256": hashlib.sha256,
    "SHA512": hashlib.sha512,
}


def hotp(secret: bytes, counter: int, digits: int = 6, algorithm: str = "SHA1") -> str:
    """Generate an HOTP code per RFC 4226.

    Parameters
    ----------
    secret:
        The shared secret key, as raw bytes (NOT base32-encoded).
    counter:
        The moving factor / counter value (an 8-byte big-endian integer
        per the RFC).
    digits:
        Number of decimal digits in the resulting code (RFC 4226 defines
        6, but 7 and 8 are common extensions supported by most apps).
    algorithm:
        The HMAC digest algorithm to use. RFC 4226 mandates HMAC-SHA1;
        RFC 6238 (TOTP) permits SHA256/SHA512 as options.

    Returns
    -------
    A zero-padded decimal string of length `digits`.
    """
    if digits < 1 or digits > 10:
        raise ValueError("digits must be between 1 and 10")

    algorithm = algorithm.upper()
    if algorithm not in _DIGEST_MAP:
        raise ValueError(f"unsupported algorithm: {algorithm}")
    digestmod = _DIGEST_MAP[algorithm]

    # RFC 4226 Section 5.2: the counter is an 8-byte (64-bit) big-endian
    # integer, run through HMAC with the shared secret as the key.
    counter_bytes = struct.pack(">Q", counter)
    mac = hmac.new(secret, counter_bytes, digestmod).digest()

    # RFC 4226 Section 5.3: Dynamic Truncation (DT).
    # The low-order 4 bits of the last byte of the HMAC give an offset
    # into the digest; a 4-byte (31-bit, MSB masked off) chunk is read
    # from that offset and reduced modulo 10^digits.
    offset = mac[-1] & 0x0F
    truncated = mac[offset : offset + 4]
    code_int = struct.unpack(">I", truncated)[0] & 0x7FFFFFFF
    code_int %= 10 ** digits

    return str(code_int).zfill(digits)


# ---------------------------------------------------------------------------
# TOTP - RFC 6238
# ---------------------------------------------------------------------------

DEFAULT_TIME_STEP = 30
DEFAULT_DIGITS = 6
DEFAULT_ALGORITHM = "SHA1"


def totp(
    secret: bytes,
    for_time: float | None = None,
    time_step: int = DEFAULT_TIME_STEP,
    digits: int = DEFAULT_DIGITS,
    algorithm: str = DEFAULT_ALGORITHM,
    t0: int = 0,
) -> str:
    """Generate a TOTP code per RFC 6238.

    TOTP is simply HOTP where the moving factor (counter) is derived
    from the current time:

        counter = floor((current_unix_time - T0) / time_step)

    Parameters
    ----------
    secret:
        Raw shared secret bytes.
    for_time:
        Unix timestamp to generate the code for. Defaults to `time.time()`.
    time_step:
        The time step in seconds (RFC 6238 default: 30).
    digits:
        Code length (6, 7, or 8 are typical).
    algorithm:
        HMAC digest algorithm (SHA1, SHA256, or SHA512).
    t0:
        The Unix epoch time to start counting time steps from
        (RFC 6238 default: 0).
    """
    if for_time is None:
        for_time = time.time()
    counter = int((for_time - t0) // time_step)
    return hotp(secret, counter, digits=digits, algorithm=algorithm)


def verify_totp(
    secret: bytes,
    code: str,
    for_time: float | None = None,
    time_step: int = DEFAULT_TIME_STEP,
    digits: int = DEFAULT_DIGITS,
    algorithm: str = DEFAULT_ALGORITHM,
    t0: int = 0,
    window: int = 1,
) -> bool:
    """Verify a TOTP code, tolerating clock drift.

    `window` specifies how many time steps before/after the current one
    to also accept, to handle clock drift between the client generating
    the code and the server verifying it. A window of 1 (the default)
    accepts the current step plus one step in the past and one in the
    future (i.e. +/- `time_step` seconds, 90s of total tolerance at the
    default 30s step).

    Uses a constant-time string comparison (`hmac.compare_digest`) to
    avoid leaking timing information about the correct code.
    """
    if for_time is None:
        for_time = time.time()
    if window < 0:
        raise ValueError("window must be non-negative")

    counter = int((for_time - t0) // time_step)

    for error in range(-window, window + 1):
        candidate = hotp(secret, counter + error, digits=digits, algorithm=algorithm)
        if hmac.compare_digest(candidate, code):
            return True
    return False


# ---------------------------------------------------------------------------
# Secret generation & base32 helpers
# ---------------------------------------------------------------------------


def generate_secret(length: int = 20) -> str:
    """Generate a cryptographically secure random secret, base32-encoded.

    `length` is the number of raw random bytes (20 bytes = 160 bits is
    the RFC 4226 recommended minimum key length for HMAC-SHA1).

    Returns a base32-encoded string (the standard format used by
    authenticator apps), padded to a multiple of 8 characters as per
    RFC 4648.
    """
    if length < 1:
        raise ValueError("length must be a positive number of bytes")
    raw = secrets.token_bytes(length)
    return base64.b32encode(raw).decode("ascii")


def decode_secret(base32_secret: str) -> bytes:
    """Decode a base32 secret string into raw bytes.

    Accepts secrets with or without padding, and is case-insensitive
    (authenticator apps and users commonly type lowercase).
    """
    normalized = base32_secret.strip().replace(" ", "").upper()
    # Re-pad to a multiple of 8 chars if the padding was stripped, since
    # base64.b32decode requires correctly padded input.
    padding = (-len(normalized)) % 8
    normalized += "=" * padding
    return base64.b32decode(normalized)


# ---------------------------------------------------------------------------
# Provisioning URI (otpauth://) - for QR-code-based enrollment
# ---------------------------------------------------------------------------


def provisioning_uri(
    secret_base32: str,
    account_name: str,
    issuer: str | None = None,
    digits: int = DEFAULT_DIGITS,
    time_step: int = DEFAULT_TIME_STEP,
    algorithm: str = DEFAULT_ALGORITHM,
) -> str:
    """Build an `otpauth://totp/...` provisioning URI.

    This is the standard URI format that authenticator apps (Google
    Authenticator, Authy, 1Password, etc.) read from a QR code. This
    function only builds the string; rendering it as an actual QR code
    image is left to a QR library and is out of scope here.

    Format (per the de-facto Key URI spec used by Google Authenticator
    and adopted broadly):

        otpauth://totp/{issuer}:{account}?secret=BASE32&issuer={issuer}&
            algorithm=SHA1&digits=6&period=30
    """
    label = quote(account_name, safe="")
    if issuer:
        label = f"{quote(issuer, safe='')}:{label}"

    params = {
        "secret": secret_base32.replace("=", ""),
        "digits": str(digits),
        "period": str(time_step),
        "algorithm": algorithm.upper(),
    }
    if issuer:
        params["issuer"] = quote(issuer, safe="")

    query = "&".join(f"{k}={v}" for k, v in params.items())
    return f"otpauth://totp/{label}?{query}"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _cmd_generate(args: list[str]) -> int:
    issuer = "TOTP2FALibrary"
    account = "user@example.com"
    if len(args) >= 1:
        account = args[0]
    if len(args) >= 2:
        issuer = args[1]

    secret = generate_secret()
    uri = provisioning_uri(secret, account_name=account, issuer=issuer)

    print("Secret (base32):", secret)
    print("Provisioning URI:", uri)
    print()
    print("Scan the URI above as a QR code in an authenticator app, or")
    print("add it manually using the base32 secret.")
    return 0


def _cmd_code(args: list[str]) -> int:
    if len(args) < 1:
        print("usage: totp.py code <base32secret> [digits] [time_step]", file=sys.stderr)
        return 1
    secret_b32 = args[0]
    digits = int(args[1]) if len(args) >= 2 else DEFAULT_DIGITS
    time_step = int(args[2]) if len(args) >= 3 else DEFAULT_TIME_STEP

    secret = decode_secret(secret_b32)
    code = totp(secret, digits=digits, time_step=time_step)
    print(code)
    return 0


def _cmd_verify(args: list[str]) -> int:
    if len(args) < 2:
        print("usage: totp.py verify <base32secret> <code> [window]", file=sys.stderr)
        return 1
    secret_b32 = args[0]
    code = args[1]
    window = int(args[2]) if len(args) >= 3 else 1

    secret = decode_secret(secret_b32)
    ok = verify_totp(secret, code, window=window)
    print("valid" if ok else "invalid")
    return 0 if ok else 1


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    if not argv:
        print("usage: totp.py <generate|code|verify> [args...]", file=sys.stderr)
        return 1

    command, rest = argv[0], argv[1:]
    if command == "generate":
        return _cmd_generate(rest)
    elif command == "code":
        return _cmd_code(rest)
    elif command == "verify":
        return _cmd_verify(rest)
    else:
        print(f"unknown command: {command}", file=sys.stderr)
        print("usage: totp.py <generate|code|verify> [args...]", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
