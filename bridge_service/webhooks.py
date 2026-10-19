"""Standard Webhooks signing and opt-in, public-address-only HTTPS delivery.

No connection is made until ``PublicWebhookTransport.post`` is explicitly used.
Socket operations have a timeout; deployment must also bound DNS lookup time and
enforce an outbound network policy. No proxy environment variables are used.
"""

from __future__ import annotations

import base64
import binascii
from datetime import datetime, timezone
import http.client
import ipaddress
import math
import re
import socket
import ssl
from collections.abc import Mapping
from urllib.parse import SplitResult, urlsplit

from standardwebhooks import Webhook


MAX_BODY_BYTES = 256 * 1024
MAX_RESPONSE_BYTES = 64 * 1024


def validate_secret(secret: str) -> bytes:
    """Return a strictly validated 24–64-byte Standard Webhooks signing key."""
    if not isinstance(secret, str) or not secret.startswith("whsec_"):
        raise ValueError("signing secret must have the whsec_ prefix")
    encoded = secret[len("whsec_") :]
    try:
        # Standard Webhooks accepts padded or unpadded standard base64.
        key = base64.b64decode(encoded + "=" * (-len(encoded) % 4), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("signing secret must contain valid base64") from exc
    if not 24 <= len(key) <= 64:
        raise ValueError("signing key must decode to 24–64 bytes")
    # Reject noncanonical encodings and excess padding, not just bad characters.
    if encoded not in (base64.b64encode(key).decode(), base64.b64encode(key).decode().rstrip("=")):
        raise ValueError("signing secret must contain canonical base64")
    return key


def _header_id(value: str, name: str) -> None:
    if not isinstance(value, str) or not value or any(not 33 <= ord(c) <= 126 for c in value):
        raise ValueError(f"{name} must be a nonempty printable ASCII token")


def signed_headers(
    secret: str,
    event_id: str,
    body: bytes,
    now: float,
    subscription_id: str,
    old_secret: str | None = None,
) -> dict[str, str]:
    """Sign the caller's serialized UTF-8 JSON bytes, without serializing again.

    Call for every delivery attempt with its current time. The event ID stays
    stable across retries. Supply ``old_secret`` only during a rotation window.
    """
    _header_id(event_id, "event_id")
    _header_id(subscription_id, "subscription_id")
    if not isinstance(body, bytes):
        raise TypeError("body must be bytes")
    if len(body) > MAX_BODY_BYTES:
        raise ValueError("webhook body exceeds 256 KiB")
    if not math.isfinite(now) or now < 0:
        raise ValueError("now must be a finite nonnegative Unix timestamp")
    timestamp = math.floor(now)
    signed_at = datetime.fromtimestamp(timestamp, tz=timezone.utc)
    # The official Python library signs str, so decode strictly. UTF-8 round
    # trips without changing whitespace, escaping, key order, or Unicode bytes.
    data = body.decode("utf-8")
    signatures = [Webhook(validate_secret(secret)).sign(event_id, signed_at, data)]
    if old_secret is not None and old_secret != secret:
        signatures.append(Webhook(validate_secret(old_secret)).sign(event_id, signed_at, data))
    return {
        "Content-Type": "application/json",
        "webhook-id": event_id,
        "webhook-timestamp": str(timestamp),
        "webhook-signature": " ".join(signatures),
        "X-MCP-Subscription-Id": subscription_id,
    }


def validate_callback_url(url: str, *, allow_nonstandard_port: bool = False) -> SplitResult:
    """Validate syntax without DNS or network I/O; return the parsed HTTPS URL.

    Use percent-encoded ASCII URLs. Public-address checks are performed again
    at connection time by the transport, including for IP-literal callbacks.
    """
    if not isinstance(url, str) or not url or not url.isascii():
        raise ValueError("callback URL must be a nonempty ASCII URL")
    if any(ord(c) <= 32 or ord(c) == 127 for c in url) or "\\" in url:
        raise ValueError("callback URL contains whitespace or invalid characters")
    try:
        parsed = urlsplit(url)
        host = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise ValueError("callback URL is malformed") from exc
    if parsed.scheme != "https" or not host:
        raise ValueError("callback URL must use HTTPS with a hostname")
    if parsed.username is not None or parsed.password is not None or "#" in url:
        raise ValueError("callback URL cannot contain credentials or a fragment")
    if not allow_nonstandard_port and port not in (None, 443):
        raise ValueError("callback URL must use port 443")
    if port == 0 or parsed.netloc.endswith(":") or "%" in host:
        raise ValueError("callback URL has an invalid port or scoped hostname")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if len(host) > 253 or any(
            not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
            for label in host.split(".")
        ):
            raise ValueError("callback URL has an invalid hostname")
    return parsed


def _require_public_address(address: str) -> None:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError as exc:
        raise ValueError("callback resolved to an invalid address") from exc
    if (
        not ip.is_global
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_unspecified
    ):
        raise ValueError("callback must resolve exclusively to globally public addresses")
    if isinstance(ip, ipaddress.IPv6Address):
        # Avoid IPv4 translation/tunneling endpoints whose routing can reach
        # private IPv4 destinations even when the IPv6 prefix appears public.
        if ip.ipv4_mapped is not None or ip.sixtofour is not None or ip.teredo is not None:
            raise ValueError("callback cannot use IPv4 translation or tunnel addresses")
        if ip not in ipaddress.ip_network("2000::/3"):
            raise ValueError("callback must use public IPv6 global-unicast space")


class _PublicHTTPSConnection(http.client.HTTPSConnection):
    """Resolve once per connection, validate the entire set, and pin its IP."""

    def connect(self) -> None:
        if self._tunnel_host is not None:
            raise ValueError("webhook proxy tunnels are not supported")
        addresses = socket.getaddrinfo(self.host, self.port, type=socket.SOCK_STREAM)
        if not addresses:
            raise OSError("callback hostname resolved to no addresses")
        for family, socktype, proto, canonname, sockaddr in addresses:
            if family not in (socket.AF_INET, socket.AF_INET6) or socktype != socket.SOCK_STREAM:
                raise ValueError("callback resolved to an unsupported socket address")
            _require_public_address(sockaddr[0])
        # Direct socket.connect uses the validated numeric sockaddr. Calling
        # create_connection(hostname) here would introduce DNS rebinding.
        last_error = None
        for family, socktype, proto, canonname, sockaddr in addresses:
            raw_socket = socket.socket(family, socktype, proto)
            try:
                raw_socket.settimeout(self.timeout)
                raw_socket.connect(sockaddr)
                self.sock = self._context.wrap_socket(raw_socket, server_hostname=self.host)
                return
            except OSError as exc:
                raw_socket.close()
                last_error = exc
        assert last_error is not None
        raise last_error


class DisabledWebhookTransport:
    """Fail closed by default; never acknowledge or send a real callback."""

    def post(self, url: str, body: bytes, headers: Mapping[str, str]) -> tuple[int, bytes]:
        raise RuntimeError("webhook delivery is disabled")


class PublicWebhookTransport:
    """Explicit live transport; no redirects, proxies, cookies, or connection reuse."""

    def __init__(self, timeout: float = 10.0) -> None:
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("timeout must be finite and positive")
        self.timeout = timeout

    def post(self, url: str, body: bytes, headers: Mapping[str, str]) -> tuple[int, bytes]:
        parsed = validate_callback_url(url)
        if not isinstance(body, bytes):
            raise TypeError("body must be bytes")
        if len(body) > MAX_BODY_BYTES:
            raise ValueError("webhook body exceeds 256 KiB")
        # Keep Host and framing bound to the validated URL and exact body.
        if any(name.lower() in {"host", "content-length", "transfer-encoding", "connection"} for name in headers):
            raise ValueError("webhook headers cannot override host or HTTP framing")
        context = ssl.create_default_context()
        connection = _PublicHTTPSConnection(
            parsed.hostname, parsed.port or 443, timeout=self.timeout, context=context
        )
        target = parsed.path or "/"
        if parsed.query:
            target += "?" + parsed.query
        try:
            connection.request("POST", target, body=body, headers=dict(headers))
            response = connection.getresponse()
            response_body = response.read(MAX_RESPONSE_BYTES + 1)
            if len(response_body) > MAX_RESPONSE_BYTES:
                raise ValueError("webhook response exceeds 64 KiB")
            # In particular, 3xx is returned as-is; no redirect is ever followed.
            return response.status, response_body
        finally:
            connection.close()
