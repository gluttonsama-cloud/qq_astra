"""Synthetic OAuth validation only; no real tokens, accounts or signing keys.

Private fixture keys are ephemeral and remain in memory. Only public JWKS and
deliberately invalid placeholders are written to a temporary test directory.
"""

import json
import tempfile
import time
import unittest
from pathlib import Path

import jwt
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from .auth import Authenticator, AuthError, SCOPES


class AuthTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.other_rsa = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.ec_key = ec.generate_private_key(ec.SECP256R1())

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="synthetic-qq-oauth-")
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "public-jwks.json"
        self.rsa_jwk = self.public_jwk(self.rsa_key, "RS256", "rsa-test")
        self.ec_jwk = self.public_jwk(self.ec_key, "ES256", "ec-test")
        self.write_keys(self.rsa_jwk, self.ec_jwk)
        self.settings = dict(issuer="https://issuer.example/", public_resource_url="https://bridge.example/mcp",
                             owner_subject="synthetic-owner", jwks_path=self.path)
        self.auth = Authenticator(**self.settings)
        now = int(time.time())
        self.claims = {"iss": self.settings["issuer"], "aud": self.settings["public_resource_url"],
                       "sub": "synthetic-owner", "iat": now - 1, "nbf": now - 1, "exp": now + 300,
                       "scope": " ".join(SCOPES), "client_id": "synthetic-client", "jti": "synthetic-token"}

    @staticmethod
    def public_jwk(key, algorithm, kid):
        impl = jwt.algorithms.RSAAlgorithm if algorithm == "RS256" else jwt.algorithms.ECAlgorithm
        return {**json.loads(impl.to_jwk(key.public_key())), "alg": algorithm, "kid": kid,
                "use": "sig", "key_ops": ["verify"]}

    def write_keys(self, *keys):
        temporary = self.path.with_suffix(".new")
        temporary.write_text(json.dumps({"keys": list(keys)}))
        temporary.replace(self.path)

    def token(self, *, key=None, algorithm="RS256", headers=None, claims=None):
        return jwt.encode(self.claims if claims is None else claims, key or self.rsa_key,
                          algorithm=algorithm, headers={"typ": "at+jwt", "kid": "rsa-test", **(headers or {})})

    def check_rejected(self, token, status=401, required_scope="qq:read"):
        for authenticate in (self.auth.authenticate, self.auth.authenticate_with_expiry):
            with self.assertRaises(AuthError) as failure:
                authenticate("Bearer " + token, required_scope)
            self.assertEqual(failure.exception.status_code, status)

    def test_valid_tokens_metadata_and_challenges(self):
        for key, algorithm, kid, typ in ((self.rsa_key, "RS256", "rsa-test", "at+jwt"),
                                        (self.ec_key, "ES256", "ec-test", "application/at+JWT")):
            token = self.token(key=key, algorithm=algorithm, headers={"kid": kid, "typ": typ})
            for scope in (*SCOPES, None):
                self.assertEqual(self.auth.authenticate("Bearer " + token, scope), "synthetic-owner")
                owner, expiry = self.auth.authenticate_with_expiry("Bearer " + token, scope)
                self.assertEqual(owner, "synthetic-owner")
                self.assertIs(type(expiry), float)
                self.assertEqual(expiry, self.claims["exp"])
        fractional_expiry = self.claims["exp"] + 0.25
        token = self.token(claims={**self.claims, "exp": fractional_expiry})
        self.assertEqual(self.auth.authenticate_with_expiry("Bearer " + token, "qq:events")[1],
                         fractional_expiry)
        self.assertEqual(self.auth.metadata(), {"resource": self.settings["public_resource_url"],
            "authorization_servers": [self.settings["issuer"]], "scopes_supported": list(SCOPES),
            "bearer_methods_supported": ["header"]})
        self.assertEqual(self.auth.metadata_url, "https://bridge.example/.well-known/oauth-protected-resource/mcp")
        challenge = self.auth.www_authenticate("qq:reply", "insufficient_scope")
        self.assertIn('resource_metadata="' + self.auth.metadata_url + '"', challenge)
        self.assertIn('scope="qq:reply"', challenge)
        self.assertIn('error="insufficient_scope"', challenge)

    def test_reject_untrusted_identity_and_time_claims(self):
        now = int(time.time())
        changes = [{"iss": "https://other.example/"}, {"iss": self.settings["issuer"].rstrip("/")},
            {"aud": "https://bridge.example"}, {"aud": ["other"]},
            {"sub": "different-owner"}, {"sub": 123}, {"exp": now - 1}, {"iat": now + 60},
            {"nbf": now + 60}, {"iat": str(now - 1)}, {"iat": False}, {"exp": "not-a-date"},
            {"exp": now - 10, "iat": now - 5}, {"token_use": "id"}]
        for values in changes:
            with self.subTest(values=values):
                self.check_rejected(self.token(claims={**self.claims, **values}))
        for field in ("iss", "aud", "sub", "exp", "iat", "scope"):
            with self.subTest(missing=field):
                self.check_rejected(self.token(claims={k: v for k, v in self.claims.items() if k != field}))

    def test_reject_signature_algorithm_and_id_token_substitution(self):
        self.check_rejected(self.token(key=self.other_rsa))
        self.check_rejected(self.token(key="synthetic-test-only-secret-with-enough-length", algorithm="HS256"))
        self.check_rejected(jwt.encode(self.claims, key=None, algorithm="none", headers={"typ": "at+jwt", "kid": "rsa-test"}))
        for headers in ({"typ": "JWT"}, {"typ": None}, {"typ": "id+jwt"}, {"kid": "missing"},
                        {"kid": "ec-test"}, {"crit": ["unknown"]}, {"jku": "https://attacker.example/jwks"},
                        {"jwk": self.rsa_jwk}):
            with self.subTest(headers=headers):
                self.check_rejected(self.token(headers=headers))

    def test_scope_boundary_and_malformed_authorization(self):
        read_only = self.token(claims={**self.claims, "scope": "qq:read"})
        self.assertEqual(self.auth.authenticate("bearer " + read_only, "qq:read"), "synthetic-owner")
        for scope in ("qq:events", "qq:reply"):
            self.check_rejected(read_only, status=403, required_scope=scope)
        for scope in ("qq:reader", "", "qq:read,qq:reply"):
            self.check_rejected(self.token(claims={**self.claims, "scope": scope}), status=403)
        for scope in (["qq:read"], "qq:read\tqq:reply", " qq:read", "qq:read  qq:reply"):
            self.check_rejected(self.token(claims={**self.claims, "scope": scope}))
        for header in (None, "", "Basic " + read_only, "Bearer  " + read_only, "Bearer " + read_only + "\n", "Bearer " + "x" * 32768):
            with self.subTest(header_type=type(header)):
                with self.assertRaises(AuthError):
                    self.auth.authenticate(header, "qq:read")
        with self.assertRaises(AuthError):
            self.auth.authenticate("Bearer " + read_only, "unconfigured:scope")

    def test_configuration_and_key_rotation_fail_closed(self):
        old_token = self.token()
        new_jwk = self.public_jwk(self.other_rsa, "RS256", "new-test")
        new_token = self.token(key=self.other_rsa, headers={"kid": "new-test"})
        self.write_keys(self.rsa_jwk, new_jwk)
        self.assertEqual(self.auth.authenticate("Bearer " + new_token, "qq:read"), "synthetic-owner")
        self.assertEqual(self.auth.authenticate("Bearer " + old_token, "qq:read"), "synthetic-owner")
        self.write_keys(new_jwk)
        self.check_rejected(old_token)
        invalid_sets = [[], [self.rsa_jwk, self.rsa_jwk], [{**self.rsa_jwk, "d": "invalid-placeholder"}],
            [{**self.rsa_jwk, "alg": "HS256"}], [{**self.rsa_jwk, "kty": "EC"}],
            [{**self.rsa_jwk, "use": "enc"}], [{**self.rsa_jwk, "key_ops": ["sign"]}],
            [{**self.ec_jwk, "crv": "P-384"}], [{**self.rsa_jwk, "alg": None}],
            [{"kty": "RSA", "alg": "RS256", "kid": "broken"}]]
        for entries in invalid_sets:
            with self.subTest(invalid_jwks=entries):
                self.write_keys(*entries)
                self.check_rejected(new_token, status=503)
                with self.assertRaises(AuthError):
                    Authenticator(**self.settings)
        self.path.write_text("invalid json")
        self.check_rejected(new_token, status=503)
        self.path.unlink()
        self.check_rejected(new_token, status=503)
        self.write_keys(self.rsa_jwk)
        self.path.chmod(0o666)
        self.check_rejected(old_token, status=503)
        self.path.chmod(0o644)
        self.assertEqual(self.auth.authenticate("Bearer " + old_token, "qq:read"), "synthetic-owner")
        target = self.path.with_suffix(".target")
        self.path.replace(target)
        self.path.symlink_to(target)
        self.check_rejected(old_token, status=503)
        self.path.unlink()
        self.path.mkdir()
        self.check_rejected(old_token, status=503)
        self.path.rmdir()
        self.write_keys(self.rsa_jwk)
        self.path.parent.chmod(0o777)
        try:
            self.check_rejected(old_token, status=503)
            with self.assertRaises(AuthError):
                Authenticator(**self.settings)
        finally:
            self.path.parent.chmod(0o700)
        self.assertEqual(self.auth.authenticate("Bearer " + old_token, "qq:read"), "synthetic-owner")
        parent = self.path.parent / "checked-parent"
        parent.mkdir(mode=0o700)
        public_file = parent / "public.json"
        public_file.write_bytes(self.path.read_bytes())
        nested_settings = {**self.settings, "jwks_path": public_file}
        nested_auth = Authenticator(**nested_settings)
        target = parent.with_name("moved-parent")
        parent.rename(target)
        parent.symlink_to(target, target_is_directory=True)
        with self.assertRaises(AuthError) as failure:
            nested_auth.authenticate("Bearer " + old_token, "qq:read")
        self.assertEqual(failure.exception.status_code, 503)
        with self.assertRaises(AuthError):
            Authenticator(**nested_settings)
        for values in ({"issuer": "http://issuer.example"}, {"public_resource_url": "https://user:pass@bridge.example/mcp"},
                       {"public_resource_url": "https://bridge.example/mcp\r\nInjected: value"},
                       {"public_resource_url": "https://bridge.example/mcp?query=1"},
                       {"owner_subject": ""}, {"jwks_path": None}):
            with self.subTest(invalid_config=values):
                with self.assertRaises(AuthError):
                    Authenticator(**{**self.settings, **values})


if __name__ == "__main__":
    unittest.main()
