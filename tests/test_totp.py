"""
Unit tests for the from-scratch HOTP (RFC 4226) / TOTP (RFC 6238)
implementation in totp.py.

Run with:
    python -m pytest tests/ -v
or:
    python -m unittest discover -s tests -v
"""

import base64
import os
import sys
import unittest
from urllib.parse import unquote

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import totp as totp_lib  # noqa: E402


# ---------------------------------------------------------------------------
# RFC 4226 Appendix D: official HOTP test vectors.
#
# Secret: "12345678901234567890" (ASCII, 20 bytes)
# HMAC-SHA1 based, 6-digit truncation.
# ---------------------------------------------------------------------------
RFC4226_SECRET = b"12345678901234567890"
RFC4226_VECTORS = {
    0: "755224",
    1: "287082",
    2: "359152",
    3: "969429",
    4: "338314",
    5: "254676",
    6: "287922",
    7: "162583",
    8: "399871",
    9: "520489",
}


class TestHOTPRFC4226Vectors(unittest.TestCase):
    """The most important tests: verify our HOTP implementation produces
    the EXACT values published in RFC 4226 Appendix D, for every counter
    value 0 through 9."""

    def test_all_official_vectors(self):
        for counter, expected_code in RFC4226_VECTORS.items():
            with self.subTest(counter=counter):
                actual = totp_lib.hotp(RFC4226_SECRET, counter, digits=6, algorithm="SHA1")
                self.assertEqual(
                    actual,
                    expected_code,
                    f"HOTP(counter={counter}) = {actual}, expected {expected_code}",
                )

    def test_vector_counter_0(self):
        self.assertEqual(totp_lib.hotp(RFC4226_SECRET, 0), "755224")

    def test_vector_counter_9(self):
        self.assertEqual(totp_lib.hotp(RFC4226_SECRET, 9), "520489")


class TestTOTPKnownTimestamps(unittest.TestCase):
    """RFC 6238 Appendix B also publishes test vectors, using the same
    ASCII secret "12345678901234567890" (truncated/repeated to match key
    length per algorithm) with 8-digit codes and a 30s step. We test the
    documented SHA1 vectors here, cross-checked against the RFC table.
    """

    # RFC 6238 uses a 20-byte secret for SHA1: "12345678901234567890"
    SECRET_SHA1 = b"12345678901234567890"

    def test_totp_at_time_59(self):
        # T=59 -> counter = floor(59/30) = 1 -> RFC 6238 SHA1 8-digit: 94287082
        code = totp_lib.totp(self.SECRET_SHA1, for_time=59, digits=8, algorithm="SHA1")
        self.assertEqual(code, "94287082")

    def test_totp_at_time_1111111109(self):
        # T=1111111109 -> counter = floor(1111111109/30) = 37037036
        # RFC 6238 SHA1 8-digit vector: 07081804
        code = totp_lib.totp(self.SECRET_SHA1, for_time=1111111109, digits=8, algorithm="SHA1")
        self.assertEqual(code, "07081804")

    def test_totp_at_time_1111111111(self):
        # RFC 6238 SHA1 8-digit vector: 14050471
        code = totp_lib.totp(self.SECRET_SHA1, for_time=1111111111, digits=8, algorithm="SHA1")
        self.assertEqual(code, "14050471")

    def test_totp_at_time_1234567890(self):
        # RFC 6238 SHA1 8-digit vector: 89005924
        code = totp_lib.totp(self.SECRET_SHA1, for_time=1234567890, digits=8, algorithm="SHA1")
        self.assertEqual(code, "89005924")

    def test_totp_6_digit_derivation_from_known_counter(self):
        # Cross-check: TOTP with time_step=30 at for_time=59 must equal
        # HOTP at counter 1 (59 // 30 == 1), regardless of digit count.
        expected_hotp = totp_lib.hotp(self.SECRET_SHA1, 1, digits=6, algorithm="SHA1")
        actual_totp = totp_lib.totp(self.SECRET_SHA1, for_time=59, digits=6, algorithm="SHA1")
        self.assertEqual(actual_totp, expected_hotp)


class TestVerifyTOTP(unittest.TestCase):
    def setUp(self):
        self.secret = totp_lib.decode_secret(totp_lib.generate_secret())
        self.time_step = 30
        self.now = 1_700_000_000  # arbitrary fixed reference time

    def test_verify_accepts_current_window_code(self):
        code = totp_lib.totp(self.secret, for_time=self.now, time_step=self.time_step)
        self.assertTrue(
            totp_lib.verify_totp(self.secret, code, for_time=self.now, time_step=self.time_step)
        )

    def test_verify_accepts_previous_window_within_tolerance(self):
        previous_step_time = self.now - self.time_step
        code = totp_lib.totp(self.secret, for_time=previous_step_time, time_step=self.time_step)
        # window=1 should accept a code from one step in the past.
        self.assertTrue(
            totp_lib.verify_totp(
                self.secret, code, for_time=self.now, time_step=self.time_step, window=1
            )
        )

    def test_verify_rejects_code_outside_tolerance(self):
        far_past_time = self.now - (5 * self.time_step)
        code = totp_lib.totp(self.secret, for_time=far_past_time, time_step=self.time_step)
        # window=1 only tolerates +/- 1 step; 5 steps back must fail.
        self.assertFalse(
            totp_lib.verify_totp(
                self.secret, code, for_time=self.now, time_step=self.time_step, window=1
            )
        )

    def test_verify_rejects_wrong_code(self):
        real_code = totp_lib.totp(self.secret, for_time=self.now, time_step=self.time_step)
        # Construct a definitely-different 6-digit code.
        wrong_code = "000000" if real_code != "000000" else "111111"
        self.assertFalse(
            totp_lib.verify_totp(
                self.secret, wrong_code, for_time=self.now, time_step=self.time_step
            )
        )

    def test_verify_accepts_next_window_within_tolerance(self):
        next_step_time = self.now + self.time_step
        code = totp_lib.totp(self.secret, for_time=next_step_time, time_step=self.time_step)
        self.assertTrue(
            totp_lib.verify_totp(
                self.secret, code, for_time=self.now, time_step=self.time_step, window=1
            )
        )


class TestDigitLengths(unittest.TestCase):
    def test_6_digit_code_format(self):
        code = totp_lib.hotp(RFC4226_SECRET, 0, digits=6)
        self.assertEqual(len(code), 6)
        self.assertTrue(code.isdigit())

    def test_7_digit_code_format(self):
        code = totp_lib.hotp(RFC4226_SECRET, 0, digits=7)
        self.assertEqual(len(code), 7)
        self.assertTrue(code.isdigit())

    def test_8_digit_code_format(self):
        code = totp_lib.hotp(RFC4226_SECRET, 0, digits=8)
        self.assertEqual(len(code), 8)
        self.assertTrue(code.isdigit())
        # The RFC 6238 8-digit vector for counter/time 59 is 94287082.
        self.assertEqual(
            totp_lib.totp(b"12345678901234567890", for_time=59, digits=8), "94287082"
        )


class TestSecretGeneration(unittest.TestCase):
    def test_generate_secret_is_valid_base32(self):
        secret = totp_lib.generate_secret()
        # Must decode without error, and re-encoding should round-trip.
        raw = base64.b32decode(secret)
        self.assertEqual(len(raw), 20)  # default length

    def test_generate_secret_padding(self):
        secret = totp_lib.generate_secret(length=10)
        # base32 output length must be a multiple of 8 (RFC 4648 padding).
        self.assertEqual(len(secret) % 8, 0)

    def test_generate_secret_is_random(self):
        s1 = totp_lib.generate_secret()
        s2 = totp_lib.generate_secret()
        self.assertNotEqual(s1, s2)

    def test_decode_secret_roundtrip(self):
        secret_b32 = totp_lib.generate_secret()
        raw = totp_lib.decode_secret(secret_b32)
        self.assertEqual(base64.b32encode(raw).decode("ascii"), secret_b32)

    def test_decode_secret_handles_missing_padding_and_lowercase(self):
        secret_b32 = totp_lib.generate_secret()
        stripped_lower = secret_b32.rstrip("=").lower()
        self.assertEqual(totp_lib.decode_secret(stripped_lower), totp_lib.decode_secret(secret_b32))


class TestProvisioningURI(unittest.TestCase):
    def test_basic_format(self):
        uri = totp_lib.provisioning_uri("JBSWY3DPEHPK3PXP", account_name="alice@example.com", issuer="MyApp")
        self.assertTrue(uri.startswith("otpauth://totp/"))
        self.assertIn("secret=JBSWY3DPEHPK3PXP", uri)
        self.assertIn("issuer=MyApp", uri)
        self.assertIn("digits=6", uri)
        self.assertIn("period=30", uri)
        self.assertIn("algorithm=SHA1", uri)

    def test_url_encodes_special_characters_in_account_and_issuer(self):
        uri = totp_lib.provisioning_uri(
            "JBSWY3DPEHPK3PXP",
            account_name="alice smith@example.com",
            issuer="My App & Co",
        )
        # Raw spaces/ampersands must not appear unescaped in the label.
        label_and_query = uri.split("otpauth://totp/", 1)[1]
        label = label_and_query.split("?", 1)[0]
        self.assertNotIn(" ", label)
        self.assertNotIn("&", label)
        # And the encoded label should decode back to the original values.
        issuer_part, account_part = label.split(":", 1)
        self.assertEqual(unquote(issuer_part), "My App & Co")
        self.assertEqual(unquote(account_part), "alice smith@example.com")

    def test_custom_digits_and_period_reflected(self):
        uri = totp_lib.provisioning_uri(
            "JBSWY3DPEHPK3PXP", account_name="bob@example.com", digits=8, time_step=60
        )
        self.assertIn("digits=8", uri)
        self.assertIn("period=60", uri)


class TestAlgorithmOptions(unittest.TestCase):
    def test_sha256_produces_different_code_than_sha1(self):
        code_sha1 = totp_lib.hotp(RFC4226_SECRET, 0, algorithm="SHA1")
        code_sha256 = totp_lib.hotp(RFC4226_SECRET, 0, algorithm="SHA256")
        self.assertNotEqual(code_sha1, code_sha256)

    def test_sha512_supported(self):
        code = totp_lib.hotp(RFC4226_SECRET, 0, algorithm="SHA512")
        self.assertEqual(len(code), 6)
        self.assertTrue(code.isdigit())

    def test_unsupported_algorithm_raises(self):
        with self.assertRaises(ValueError):
            totp_lib.hotp(RFC4226_SECRET, 0, algorithm="MD5")


if __name__ == "__main__":
    unittest.main()
