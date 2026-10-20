"""Standard Webhooks signing and opt-in, public-address-only HTTPS delivery.

No connection is made until ``PublicWebhookTransport.post`` is explicitly used.
A shared monotonic deadline bounds DNS and all network operations, including
slow-trickle response headers and bodies. Only an explicitly configured local
HTTP CONNECT proxy is supported; proxy environment variables are never used.
"""

from __future__ import annotations

import base64
import binascii
from datetime import datetime, timezone
import http.client
import io
import ipaddress
import math
import queue
import re
import socket
import ssl
import threading
import time
from collections.abc import Mapping
from urllib.parse import SplitResult, urlsplit

from standardwebhooks import Webhook


MAX_BODY_BYTES = 256 * 1024
MAX_RESPONSE_BYTES = 64 * 1024
MAX_CONNECT_HEADER_BYTES = 16 * 1024
# Python cannot cancel an OS getaddrinfo call. A timed-out resolver retains its
# slot until it returns; at most four daemon threads can remain stuck process-wide.
_DNS_SLOTS = threading.BoundedSemaphore(4)


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("webhook delivery deadline exceeded")
    return remaining


def _resolve(host: str, port: int, deadline: float) -> list:
    """Bound both resolver admission and waiting, without leaking new threads."""
    if not _DNS_SLOTS.acquire(timeout=_remaining(deadline)):
        raise TimeoutError("webhook DNS resolver capacity deadline exceeded")
    result = queue.Queue(maxsize=1)

    def resolve() -> None:
        try:
            # A thread delayed until after the caller's deadline does no work.
            _remaining(deadline)
            result.put((True, socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)))
        except Exception as exc:
            result.put((False, exc))
        finally:
            _DNS_SLOTS.release()

    try:
        threading.Thread(target=resolve, name="webhook-dns", daemon=True).start()
    except BaseException:
        _DNS_SLOTS.release()
        raise
    try:
        success, value = result.get(timeout=_remaining(deadline))
    except queue.Empty as exc:
        raise TimeoutError("webhook DNS lookup deadline exceeded") from exc
    _remaining(deadline)
    if not success:
        raise value
    return value


class _DeadlineReader(io.RawIOBase):
    """Refresh the remaining budget before every raw read, not each HTTP phase."""

    def __init__(self, raw, sock, deadline: float) -> None:
        super().__init__()
        self._raw, self._sock, self._deadline = raw, sock, deadline

    def readable(self) -> bool:
        return True

    def readinto(self, buffer) -> int:
        self._sock.settimeout(_remaining(self._deadline))
        count = self._raw.readinto(buffer)
        _remaining(self._deadline)
        return count

    def close(self) -> None:
        try:
            self._raw.close()
        finally:
            super().close()


class _DeadlineSocket:
    """Socket adapter used by http.client for deadline-aware sends and reads."""

    def __init__(self, sock, deadline: float) -> None:
        self._sock, self._deadline = sock, deadline

    def sendall(self, data) -> None:
        pending = memoryview(data)
        while pending:
            self._sock.settimeout(_remaining(self._deadline))
            sent = self._sock.send(pending)
            if sent == 0:
                raise ConnectionError("webhook socket closed during send")
            pending = pending[sent:]
        _remaining(self._deadline)

    def makefile(self, mode: str):
        # The unbuffered file retains the real socket's reference until the
        # response is closed, including HTTP/1.0 / Connection: close responses.
        raw = self._sock.makefile(mode, buffering=0)
        return io.BufferedReader(_DeadlineReader(raw, self._sock, self._deadline))

    def close(self) -> None:
        self._sock.close()


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


def validate_proxy_url(url: str | None) -> tuple[str, int] | None:
    """Accept only an operator-selected, credential-free loopback HTTP proxy."""
    if url is None:
        return None
    if (not isinstance(url, str) or not url or not url.isascii()
            or any(ord(c) <= 32 or ord(c) == 127 for c in url)
            or any(c in url for c in ("\\", "?", "#", "%"))):
        raise ValueError("invalid webhook proxy URL")
    try:
        parsed = urlsplit(url)
        host, port = parsed.hostname, parsed.port
    except ValueError:
        raise ValueError("invalid webhook proxy URL") from None
    if (parsed.scheme != "http" or host not in ("127.0.0.1", "::1")
            or port is None or not 1 <= port <= 65535
            or parsed.username is not None or parsed.password is not None
            or parsed.path not in ("", "/")):
        raise ValueError("webhook proxy must be a credential-free loopback HTTP URL with an explicit port")
    return host, port


def _connect_tunnel(sock, address: str, port: int, deadline: float) -> None:
    """CONNECT only to a validated numeric target, without reading TLS bytes."""
    ip = ipaddress.ip_address(address)
    authority = f"[{ip}]:{port}" if ip.version == 6 else f"{ip}:{port}"
    request = f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode("ascii")
    _DeadlineSocket(sock, deadline).sendall(request)
    header = bytearray()
    # One-byte reads avoid consuming tunneled TLS data into an HTTP buffer.
    # A small bound and one deadline also constrain slow or malicious proxies.
    while not header.endswith(b"\r\n\r\n"):
        if len(header) >= MAX_CONNECT_HEADER_BYTES:
            raise ValueError("proxy CONNECT response headers too large")
        sock.settimeout(_remaining(deadline))
        chunk = sock.recv(1)
        _remaining(deadline)
        if not chunk:
            raise OSError("proxy closed before completing CONNECT")
        header.extend(chunk)
    lines = bytes(header[:-4]).split(b"\r\n")
    if not re.fullmatch(rb"HTTP/1\.[01] 200(?: [\x20-\x7e]*)?", lines[0]):
        raise ValueError("proxy CONNECT did not return HTTP 200")
    for line in lines[1:]:
        if not re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+:[\t\x20-\x7e]*", line):
            raise ValueError("invalid proxy CONNECT response header")
        name, value = line.split(b":", 1)
        # No response body, redirects, proxy authentication or downgrade path.
        if (name.lower() == b"transfer-encoding"
                or (name.lower() == b"content-length" and value.strip() != b"0")):
            raise ValueError("proxy CONNECT response cannot contain a body")


class _PublicHTTPSConnection(http.client.HTTPSConnection):
    """Resolve once per connection, validate the entire set, and pin its IP."""

    def __init__(self, *args, deadline: float | None = None,
                 proxy: tuple[str, int] | None = None, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._deadline = deadline if deadline is not None else time.monotonic() + self.timeout
        self._proxy = proxy

    def connect(self) -> None:
        if self._tunnel_host is not None:
            raise ValueError("webhook proxy tunnels are not supported")
        addresses = _resolve(self.host, self.port, self._deadline)
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
            _remaining(self._deadline)
            connect_address = sockaddr
            if self._proxy is not None:
                proxy_host, proxy_port = self._proxy
                family = socket.AF_INET6 if proxy_host == "::1" else socket.AF_INET
                connect_address = (proxy_host, proxy_port, 0, 0) if family == socket.AF_INET6 else self._proxy
                socktype, proto = socket.SOCK_STREAM, socket.IPPROTO_TCP
            raw_socket = socket.socket(family, socktype, proto)
            connected_socket = raw_socket
            try:
                raw_socket.settimeout(_remaining(self._deadline))
                raw_socket.connect(connect_address)
                if self._proxy is not None:
                    _connect_tunnel(raw_socket, sockaddr[0], self.port, self._deadline)
                raw_socket.settimeout(_remaining(self._deadline))
                connected_socket = self._context.wrap_socket(raw_socket, server_hostname=self.host)
                _remaining(self._deadline)
                self.sock = _DeadlineSocket(connected_socket, self._deadline)
                return
            except OSError as exc:
                connected_socket.close()
                last_error = exc
            except BaseException:
                connected_socket.close()
                raise
        assert last_error is not None
        raise last_error


class DisabledWebhookTransport:
    """Fail closed by default; never acknowledge or send a real callback."""

    def post(self, url: str, body: bytes, headers: Mapping[str, str]) -> tuple[int, bytes]:
        raise RuntimeError("webhook delivery is disabled")


class PublicWebhookTransport:
    """Explicit live transport; no ambient proxies, redirects, cookies or reuse."""

    def __init__(self, timeout: float = 10.0, *, proxy_url: str | None = None) -> None:
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("timeout must be finite and positive")
        self.timeout = timeout
        self._proxy = validate_proxy_url(proxy_url)
        # Load the local trust store once, before any timed delivery starts.
        self._context = ssl.create_default_context()

    def post(self, url: str, body: bytes, headers: Mapping[str, str]) -> tuple[int, bytes]:
        deadline = time.monotonic() + self.timeout
        parsed = validate_callback_url(url)
        if not isinstance(body, bytes):
            raise TypeError("body must be bytes")
        if len(body) > MAX_BODY_BYTES:
            raise ValueError("webhook body exceeds 256 KiB")
        # Keep Host and framing bound to the validated URL and exact body.
        if any(name.lower() in {"host", "content-length", "transfer-encoding", "connection"} for name in headers):
            raise ValueError("webhook headers cannot override host or HTTP framing")
        _remaining(deadline)
        connection = _PublicHTTPSConnection(
            parsed.hostname, parsed.port or 443, timeout=self.timeout, context=self._context,
            deadline=deadline, proxy=self._proxy
        )
        target = parsed.path or "/"
        if parsed.query:
            target += "?" + parsed.query
        response = None
        try:
            _remaining(deadline)
            connection.request("POST", target, body=body, headers=dict(headers))
            _remaining(deadline)
            response = connection.getresponse()
            _remaining(deadline)
            response_body = response.read(MAX_RESPONSE_BYTES + 1)
            _remaining(deadline)
            if len(response_body) > MAX_RESPONSE_BYTES:
                raise ValueError("webhook response exceeds 64 KiB")
            # In particular, 3xx is returned as-is; no redirect is ever followed.
            return response.status, response_body
        finally:
            try:
                if response is not None:
                    response.close()
            finally:
                connection.close()
