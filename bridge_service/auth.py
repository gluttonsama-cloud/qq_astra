"""Single-owner OAuth resource-server validation using PyJWT.

The operator supplies a public JWKS file or opts into fixed-issuer retrieval.
Only explicitly typed access tokens are accepted (RFC 9068); an IdP emitting
generic ``typ=JWT`` must be configured for access-token typing before use.
This module neither implements an OAuth authorization server nor performs login.
"""

import json
import math
import os
import re
import ssl
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import jwt
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from .state import StateError, read_public_key_file
from .webhooks import _PublicHTTPSConnection, _remaining, validate_callback_url, validate_proxy_url

SCOPES = ("qq:read", "qq:events", "qq:reply", "qq:media:read", "qq:media:send", "qq:qzone:publish")
_ALGORITHMS = {"RS256": "RSA", "ES256": "EC"}
_PRIVATE_FIELDS = {"d", "p", "q", "dp", "dq", "qi", "oth", "k"}
_TOKEN = re.compile(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\Z")
_SCOPE = re.compile(r'[\x21\x23-\x5b\x5d-\x7e]+(?: [\x21\x23-\x5b\x5d-\x7e]+)*\Z')
_JWKS_LIMIT = 1_048_576
_JWKS_TTL = 300
_JWKS_RETRY = 60
_JWKS_TIMEOUT = 5


class AuthError(Exception):
    """Safe-to-report authentication failure, without token or claim contents."""

    def __init__(self, message="invalid access token", *, status_code=401, error="invalid_token"):
        super().__init__(message)
        self.status_code = status_code
        self.error = error


def _configuration_error():
    return AuthError("authentication configuration unavailable", status_code=503, error=None)


def _https_url(value):
    if (not isinstance(value, str) or not value or not value.isascii()
            or any(ord(c) <= 32 or ord(c) == 127 or c in '\\"?#' for c in value)):
        raise _configuration_error()
    try:
        parts = urlsplit(value)
        if (parts.scheme != "https" or not parts.hostname or parts.username is not None
                or parts.password is not None or parts.query or parts.fragment):
            raise ValueError()
        parts.port  # Reject malformed or out-of-range port numbers.
    except ValueError:
        raise _configuration_error() from None
    return parts


def _parse_keys(raw):
    try:
        if len(raw) > _JWKS_LIMIT:
            raise ValueError()
        document = json.loads(raw)
        entries = document.get("keys") if isinstance(document, dict) else None
        if not isinstance(entries, list) or not 1 <= len(entries) <= 64:
            raise ValueError()
        keys = {}
        for item in entries:
            if not isinstance(item, dict) or _PRIVATE_FIELDS.intersection(item):
                raise ValueError()
            kid, algorithm = item.get("kid"), item.get("alg")
            if (not isinstance(kid, str) or not kid or len(kid) > 256 or kid in keys
                    or not isinstance(algorithm, str) or algorithm not in _ALGORITHMS
                    or item.get("kty") != _ALGORITHMS[algorithm]
                    or item.get("use", "sig") != "sig"
                    or item.get("key_ops", ["verify"]) != ["verify"]):
                raise ValueError()
            if algorithm == "ES256" and item.get("crv") != "P-256":
                raise ValueError()
            key = jwt.PyJWK.from_dict(item, algorithm=algorithm)
            if algorithm == "RS256":
                if not isinstance(key.key, rsa.RSAPublicKey) or key.key.key_size < 2048:
                    raise ValueError()
            elif (not isinstance(key.key, ec.EllipticCurvePublicKey)
                    or not isinstance(key.key.curve, ec.SECP256R1)):
                raise ValueError()
            keys[kid] = key
        return keys
    except (ValueError, TypeError, KeyError, RecursionError, jwt.PyJWTError):
        raise _configuration_error() from None


class _IssuerKeys:
    """Opt-in Auth0-style root issuer JWKS, with bounded in-memory caching.

    Construction is offline. No discovery document, token or response can
    select another URL. Failed refreshes clear the cache, including fresh keys;
    no stale fallback is allowed. One shared cooldown bounds unknown-kid probes.
    """

    def __init__(self, issuer, proxy_url=None, *, clock=time.monotonic):
        parts = _https_url(issuer)
        if parts.path not in ("", "/"):
            raise _configuration_error()
        self.url = issuer.rstrip("/") + "/.well-known/jwks.json"
        try:
            self.target = validate_callback_url(self.url)
            self.proxy = validate_proxy_url(proxy_url)
            self.context = ssl.create_default_context()
        except (ValueError, OSError):
            raise _configuration_error() from None
        self.clock, self.lock = clock, threading.Lock()
        self.keys, self.expires, self.next_refresh = {}, 0, 0

    def _fetch(self):
        deadline = time.monotonic() + _JWKS_TIMEOUT
        connection = _PublicHTTPSConnection(self.target.hostname, 443,
            timeout=_JWKS_TIMEOUT, context=self.context, deadline=deadline, proxy=self.proxy)
        response = None
        try:
            connection.request("GET", self.target.path, headers={
                "Accept": "application/jwk-set+json, application/json", "Accept-Encoding": "identity"})
            _remaining(deadline)
            response = connection.getresponse()
            _remaining(deadline)
            if (response.status != 200
                    or response.getheader("Content-Type", "").split(";", 1)[0].strip().lower()
                        not in ("application/json", "application/jwk-set+json")
                    or response.getheader("Content-Encoding", "identity").lower() != "identity"):
                raise _configuration_error()
            raw = response.read(_JWKS_LIMIT + 1)
            _remaining(deadline)
            return _parse_keys(raw)
        finally:
            try:
                if response is not None:
                    response.close()
            finally:
                connection.close()

    def get(self, kid):
        if not self.lock.acquire(timeout=_JWKS_TIMEOUT):
            raise _configuration_error()
        try:
            now = self.clock()
            if now < self.expires and kid in self.keys:
                return self.keys
            if now < self.next_refresh:
                if now >= self.expires:
                    raise _configuration_error()
                return self.keys  # Unknown kid is rejected without another fetch.
            try:
                keys = self._fetch()
            except Exception:
                self.keys, self.expires = {}, 0
                raise _configuration_error() from None
            finally:
                self.next_refresh = self.clock() + _JWKS_RETRY
            self.keys, self.expires = keys, self.clock() + _JWKS_TTL
            return self.keys
        finally:
            self.lock.release()


class Authenticator:
    """Validate signatures, resource, owner, time and one route-selected scope.

    ``jwks_path`` is an operator-managed local public-key file. It is read
    again for every authentication, so atomic replacement supports key rotation
    and removal takes effect immediately. Bad/missing replacement files fail
    closed; previously trusted keys are never retained as a fallback. Alternatively,
    ``jwks_from_issuer=True`` selects bounded HTTPS retrieval from the fixed issuer.
    """

    def __init__(self, *, issuer, public_resource_url, owner_subject, jwks_path=None,
                 jwks_from_issuer=False, jwks_proxy_url=None, local_metadata_port=None):
        _https_url(issuer)
        resource = _https_url(public_resource_url)
        if (not isinstance(owner_subject, str) or not owner_subject.strip()
                or len(owner_subject) > 1024 or any(ord(c) < 32 for c in owner_subject)):
            raise _configuration_error()
        if (type(jwks_from_issuer) is not bool
                or (jwks_from_issuer and jwks_path is not None)
                or (not jwks_from_issuer and (not isinstance(jwks_path, (str, Path)) or not str(jwks_path)))
                or (not jwks_from_issuer and jwks_proxy_url is not None)):
            raise _configuration_error()
        self.issuer = issuer
        self.public_resource_url = public_resource_url
        self.owner_subject = owner_subject
        # A subject is unique only within its issuer. Persist the full trust
        # boundary so changing identity provider/resource cannot adopt old state.
        self.binding_principal = json.dumps([issuer, public_resource_url, owner_subject], separators=(",", ":"))
        self.jwks_path = Path(os.path.abspath(os.path.expanduser(jwks_path))) if jwks_path is not None else None
        self.issuer_keys = _IssuerKeys(issuer, jwks_proxy_url) if jwks_from_issuer else None
        self.metadata_url = urlunsplit((resource.scheme, resource.netloc,
            "/.well-known/oauth-protected-resource" + resource.path.rstrip("/"), "", ""))
        if local_metadata_port is not None:
            if type(local_metadata_port) is not int or not 1024 <= local_metadata_port <= 65535:
                raise _configuration_error()
            self.metadata_url = (f"http://127.0.0.1:{local_metadata_port}"
                                 "/.well-known/oauth-protected-resource/mcp")
        if self.issuer_keys is None:
            self._load_keys()  # Local files are checked offline at startup.

    def _load_keys(self, kid=None):
        if self.issuer_keys is not None:
            return self.issuer_keys.get(kid)
        try:
            raw = read_public_key_file(self.jwks_path, max_bytes=_JWKS_LIMIT)
            return _parse_keys(raw)
        except (OSError, ValueError, TypeError, KeyError, RecursionError, StateError, jwt.PyJWTError):
            raise _configuration_error() from None

    def authenticate(self, authorization_header, required_scope=None):
        """Return only the verified owner subject; never an unverified claim."""
        return self.authenticate_with_expiry(authorization_header, required_scope)[0]

    def authenticate_with_expiry(self, authorization_header, required_scope=None):
        """Return the verified owner and signed expiry for a resource lease.

        A missing required scope is a 403; all invalid tokens are 401. A broken
        local trust configuration is a 503. Routes decide which scope they need.
        Expiry comes from the same signature-verified claims as the owner. The
        issuer sets token lifetime; this validator adds no maximum-age policy.
        """
        self._check_scope(required_scope)
        if not isinstance(authorization_header, str) or len(authorization_header) > 32768:
            raise AuthError()
        scheme, separator, token = authorization_header.partition(" ")
        if scheme.lower() != "bearer" or not separator or not _TOKEN.fullmatch(token):
            raise AuthError()
        try:
            header = jwt.get_unverified_header(token)
            token_type, kid = header.get("typ"), header.get("kid")
            if (not isinstance(token_type, str)
                    or token_type.lower() not in ("at+jwt", "application/at+jwt")
                    or not isinstance(kid, str) or not kid or len(kid) > 256
                    or header.get("alg") not in _ALGORITHMS
                    or any(name in header for name in ("crit", "b64", "jku", "jwk", "x5u"))):
                raise AuthError()
            keys = self._load_keys(kid)
            if kid not in keys:
                raise AuthError()
            key = keys[kid]
            if header.get("alg") != key.algorithm_name:
                raise AuthError()
            claims = jwt.decode(token, key=key.key, algorithms=[key.algorithm_name],
                issuer=self.issuer, audience=self.public_resource_url, subject=self.owner_subject,
                options={"require": ["iss", "aud", "sub", "exp", "iat", "scope"],
                         "strict_aud": False}, leeway=0)
            audiences = [claims["aud"]] if isinstance(claims["aud"], str) else claims["aud"]
            if (not isinstance(audiences, list) or not audiences
                    or any(not isinstance(value, str) or not value for value in audiences)
                    or self.public_resource_url not in audiences):
                raise AuthError()
            for name in ("exp", "iat", "nbf"):
                if name in claims and (type(claims[name]) not in (int, float)
                                       or not math.isfinite(claims[name])):
                    raise AuthError()
            if (claims["exp"] <= claims["iat"]
                    or ("nbf" in claims and claims["nbf"] >= claims["exp"])
                    or claims.get("token_use", "access") != "access"):
                raise AuthError()
            scope = claims["scope"]
            if not isinstance(scope, str) or (scope and not _SCOPE.fullmatch(scope)):
                raise AuthError()
        except (jwt.PyJWTError, ValueError, TypeError, OverflowError):
            raise AuthError() from None
        if required_scope is not None and required_scope not in scope.split(" "):
            raise AuthError("insufficient scope", status_code=403, error="insufficient_scope")
        return self.owner_subject, float(claims["exp"])

    @staticmethod
    def _check_scope(required_scope):
        if required_scope is not None and required_scope not in SCOPES:
            raise _configuration_error()

    def metadata(self):
        """RFC 9728 document served without authentication at metadata_url."""
        return {"resource": self.public_resource_url, "authorization_servers": [self.issuer],
                "scopes_supported": list(SCOPES), "bearer_methods_supported": ["header"]}

    def www_authenticate(self, required_scope=None, error=None):
        """Build a safe challenge; request-derived values must not enter headers."""
        self._check_scope(required_scope)
        if error not in (None, "invalid_token", "insufficient_scope"):
            raise _configuration_error()
        parts = [f'Bearer resource_metadata="{self.metadata_url}"']
        if required_scope is not None:
            parts.append(f'scope="{required_scope}"')
        if error is not None:
            parts.append(f'error="{error}"')
            description = ("Authorize the required tool permission" if error == "insufficient_scope"
                           else "A valid access token is required")
            parts.append(f'error_description="{description}"')
        return ", ".join(parts)
