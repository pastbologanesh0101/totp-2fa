# TOTP 2FA Library

A small, dependency-free Python implementation of two-factor authentication
via one-time passwords, built entirely from the RFCs:

- **HOTP** — HMAC-Based One-Time Password Algorithm ([RFC 4226](https://datatracker.ietf.org/doc/html/rfc4226))
- **TOTP** — Time-Based One-Time Password Algorithm ([RFC 6238](https://datatracker.ietf.org/doc/html/rfc6238))

No `pyotp`, no third-party dependencies at all — just `hmac`, `hashlib`,
`base64`, `struct`, `secrets`, and the rest of the Python standard library.
This is the exact algorithm that Google Authenticator, Authy, 1Password,
and every other TOTP-based authenticator app implement.

## How the algorithm actually works

### 1. HOTP — turning a counter into a 6-digit code (RFC 4226)

HOTP takes a **shared secret** (known only to the server and the user's
device/app) and a **counter** (an integer that both sides agree on), and
deterministically produces a short numeric code. Anyone without the secret
cannot predict the code, even if they know the counter.

Steps, per RFC 4226 Section 5:

1. **HMAC step.** Pack the counter as an 8-byte big-endian integer, and
   compute `HMAC-SHA1(key=secret, message=counter_bytes)`. This yields a
   20-byte digest (for SHA1; 32 bytes for SHA256, 64 for SHA512).
2. **Dynamic Truncation (DT).** Take the low-order 4 bits of the *last*
   byte of the digest — call it `offset` (0–15). Read the 4 bytes of the
   digest starting at that offset as a big-endian 31-bit integer (the
   top bit of the first byte is masked off with `& 0x7FFFFFFF` so the
   result is never negative).
3. **Modulo reduction.** Take that integer `mod 10^digits` (e.g. `mod
   1,000,000` for a 6-digit code), and zero-pad the result to `digits`
   characters.

This "dynamic" truncation (reading from a data-dependent offset rather
than a fixed one) is what makes HOTP resistant to certain attacks that a
naive fixed-offset truncation would be vulnerable to.

`totp.py`'s `hotp()` function implements exactly these three steps, with
support for HMAC-SHA1 (the RFC 4226 default), plus SHA256 and SHA512 as
options (used by some TOTP deployments per RFC 6238).

### 2. TOTP — deriving the counter from time (RFC 6238)

TOTP is HOTP with one twist: instead of an explicit counter that the
server increments after every login, the counter is derived from the
**current time**, so both sides can compute it independently without
any prior coordination:

```
counter = floor((current_unix_time - T0) / time_step)
```

- `T0` is normally `0` (the Unix epoch).
- `time_step` (often called `X` in the RFC) is normally `30` seconds.

So every 30 seconds, the counter increments by 1, and a new code becomes
valid. This is why the digits displayed in your authenticator app change
every 30 seconds with a little countdown ring.

### 3. Clock drift tolerance

Real device clocks are never perfectly in sync. If a user's phone clock
is a few seconds (or tens of seconds) ahead of or behind the server, a
naive "does the code match *right now's* counter" check will spuriously
reject valid codes.

The fix, which every real TOTP implementation uses, is a **verification
window**: instead of checking only the current counter, also check
`window` counters before and after it. `verify_totp()` in this library
accepts a `window` parameter (default `1`), which checks the current
30-second step plus one step in the past and one in the future — 90
seconds of total tolerance at the default step size. A code is accepted
if it matches *any* of those counters, using a constant-time comparison
(`hmac.compare_digest`) so verification doesn't leak timing information
about which counter (if any) matched.

### 4. Secrets and provisioning

- **Secret generation** uses `secrets.token_bytes()` (a CSPRNG, not
  `random`), producing 20 bytes (160 bits) by default — the minimum key
  length RFC 4226 recommends for HMAC-SHA1. The raw bytes are then
  base32-encoded (`base64.b32encode`), which is the standard textual
  format authenticator apps expect users to type in or embed in a QR
  code.
- **Provisioning URIs** (`otpauth://totp/...`) are the de-facto standard
  format (originated by Google Authenticator, now supported broadly)
  that a QR code encodes. Authenticator apps scan the QR code, parse
  this URI, and store the secret + parameters. This library generates a
  correctly-formatted and URL-encoded URI string; rendering it as an
  actual QR code image is left to a dedicated QR library (out of scope
  here — the point of this project is the OTP algorithm itself).

## Usage

### As a library

```python
import totp

# 1. Generate a new secret for a user.
secret_b32 = totp.generate_secret()  # e.g. "K7GWKPKAOHVQ7BXV67CDF5GKIFULJG6P"

# 2. Build a provisioning URI to show as a QR code during enrollment.
uri = totp.provisioning_uri(secret_b32, account_name="alice@example.com", issuer="MyApp")
print(uri)
# otpauth://totp/MyApp:alice%40example.com?secret=K7GW...&digits=6&period=30&algorithm=SHA1&issuer=MyApp

# 3. Generate the current code (e.g. for testing, or a server-side backup code).
secret_bytes = totp.decode_secret(secret_b32)
code = totp.totp(secret_bytes)
print(code)  # e.g. "188569"

# 4. Verify a code a user typed in, tolerating clock drift.
is_valid = totp.verify_totp(secret_bytes, code, window=1)
```

### Command line

```bash
# Generate a new secret + provisioning URI (optionally pass account and issuer names).
python totp.py generate [account_name] [issuer]

# Print the current valid code for a given base32 secret.
python totp.py code <base32secret> [digits] [time_step]

# Verify a code against the current time window (with drift tolerance).
python totp.py verify <base32secret> <code> [window]
```

Example session:

```bash
$ python totp.py generate alice@example.com MyApp
Secret (base32): K7GWKPKAOHVQ7BXV67CDF5GKIFULJG6P
Provisioning URI: otpauth://totp/MyApp:alice%40example.com?secret=K7GWKPKAOHVQ7BXV67CDF5GKIFULJG6P&digits=6&period=30&algorithm=SHA1&issuer=MyApp

$ python totp.py code K7GWKPKAOHVQ7BXV67CDF5GKIFULJG6P
188569

$ python totp.py verify K7GWKPKAOHVQ7BXV67CDF5GKIFULJG6P 188569
valid
```

To actually add the secret to a real authenticator app (Google
Authenticator, Authy, 1Password, etc.): take the `Provisioning URI`
printed above, render it as a QR code (any QR generator will do — the
string itself is the standard format the app expects), and scan it with
the app. From that point on, the app will show you the same rotating
6-digit code that `python totp.py code` computes, since both sides are
running the identical RFC 6238 algorithm against the same secret and
clock.

## Running the tests

```bash
pip install pytest   # only needed to run the test suite
python -m pytest tests/ -v
```

The test suite (`tests/test_totp.py`) includes, among others:

- The **exact official RFC 4226 Appendix D test vectors** — HOTP for
  secret `"12345678901234567890"` at counters 0 through 9, checked
  against the RFC's published 6-digit values.
- The **RFC 6238 Appendix B test vectors** for known `(secret,
  timestamp)` pairs (8-digit SHA1 codes at `T=59`, `T=1111111109`,
  `T=1111111111`, `T=1234567890`).
- `verify_totp()` accepting a code from the current window, accepting a
  code from the previous window within tolerance, and rejecting a code
  outside the tolerance window.
- `verify_totp()` correctly rejecting a wrong code.
- 6/7/8-digit configurations producing correctly-formatted codes.
- Base32 secret generation producing valid, correctly-padded output.
- Provisioning URIs being correctly formatted and URL-encoding special
  characters (spaces, `&`, `@`) in account names and issuers.

All tests pass against the official RFC values — this implementation
isn't just internally self-consistent, it's verified to be
interoperable with the published standard.

Continuous integration (`.github/workflows/tests.yml`) runs the full
suite on every push and pull request, against Python 3.11 and 3.12.

## Project layout

```
totp.py               # HOTP + TOTP implementation, secret/URI helpers, CLI
tests/test_totp.py    # Unit tests, including official RFC test vectors
.github/workflows/    # CI: runs tests on push/PR across Python versions
LICENSE               # MIT
```

## Security notes

This is an educational / portfolio implementation of the algorithm
itself. A couple of things worth calling out if you were to adapt this
for production use:

- Secrets should be stored encrypted at rest, never in plaintext.
- Rate-limit verification attempts server-side to prevent brute-forcing
  the 6-digit space.
- Consider tracking the last successfully used counter per user to
  prevent trivial replay of a just-used code within the drift window.

## License

MIT — see [LICENSE](LICENSE).
