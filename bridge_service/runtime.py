"""Configured OAuth resource server and one durable queue worker.

The process binds only loopback. An operator-managed HTTPS reverse proxy or
Secure MCP Tunnel supplies reachability; this module never provisions either.
"""

import argparse
import asyncio
import json
import os
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

import uvicorn
from .media import ImageFetcher, file_hosts
from .media_tools import TOOL_SCOPES

from .auth import Authenticator, AuthError
from .core import Bridge, RpcError, canonical
from .gateway import GatewayRejected, LoopbackOneBot, decode_event
from .state import StateDirectory, StateCipher, read_secret_file
from .webhooks import PublicWebhookTransport, validate_callback_url, validate_proxy_url


class QueueWorker:
    """One worker per locked state directory; no blind QQ-send replay."""

    def __init__(self, bridge):
        self.bridge, self.stop_event = bridge, threading.Event()
        self.thread, self.failed = None, False

    def start(self):
        if self.thread is not None:
            raise RuntimeError("worker already started")
        self.bridge.recover_interrupted_replies()
        self.thread = threading.Thread(target=self._run, name="qq-bridge-queue", daemon=False)
        self.thread.start()

    def _run(self):
        try:
            while not self.stop_event.is_set():
                worked = self.bridge.dispatch_reply()
                worked = self.bridge.operations.dispatch() or worked
                if self.stop_event.is_set():
                    break
                worked = self.bridge.dispatch_event() or worked
                if not worked:
                    self.stop_event.wait(0.5)
        except Exception:
            self.failed = True  # Expose only health, never exception text/secrets.

    @property
    def healthy(self):
        return bool(self.thread and self.thread.is_alive() and not self.failed and not self.stop_event.is_set())

    def stop(self):
        self.stop_event.set()
        if self.thread is not None:
            self.thread.join(timeout=45)
            if self.thread.is_alive():
                raise RuntimeError("worker did not stop; state lock must remain held")


class RateLimit:
    def __init__(self, *, rate=2, burst=30, clock=time.monotonic):
        self.rate, self.burst, self.clock = rate, burst, clock
        self.tokens, self.updated = float(burst), clock()

    def allow(self):
        now = self.clock()
        self.tokens = min(self.burst, self.tokens + max(0, now - self.updated) * self.rate)
        self.updated = now
        if self.tokens < 1:
            return False
        self.tokens -= 1
        return True


class Application:
    def __init__(self, bridge, authenticator, gateway_secret, *, port, worker=None, state=None):
        self.bridge, self.auth, self.gateway_secret = bridge, authenticator, gateway_secret
        self.worker, self.state, self.closing = worker or QueueWorker(bridge), state, False
        resource = urlsplit(authenticator.public_resource_url)
        # Transport routes are local contracts, independent of Tunnel's
        # connector-facing resource/audience (for example /v1/mcp/<id>).
        self.mcp_path = "/mcp"
        self.metadata_path = "/.well-known/oauth-protected-resource/mcp"
        self.local_host = f"127.0.0.1:{port}"
        self.hosts = {resource.netloc.lower(), self.local_host}
        self.origin = resource.scheme + "://" + resource.netloc
        self.limits = {"mcp": RateLimit(), "gateway": RateLimit(rate=5, burst=50),
                       "metadata": RateLimit(rate=1, burst=20)}

    async def _respond(self, send, status, value, extra=()):
        body = canonical(value).encode()
        await send({"type": "http.response.start", "status": status, "headers": [
            (b"content-type", b"application/json"), (b"content-length", str(len(body)).encode()),
            (b"cache-control", b"no-store"), *extra]})
        await send({"type": "http.response.body", "body": body})

    async def _lifespan(self, receive, send):
        while True:
            event = await receive()
            if event["type"] == "lifespan.startup":
                try:
                    self.worker.start()
                except Exception:
                    await send({"type": "lifespan.startup.failed", "message": "queue startup failed"})
                    return
                await send({"type": "lifespan.startup.complete"})
            elif event["type"] == "lifespan.shutdown":
                self.closing = True
                try:
                    await asyncio.to_thread(self.worker.stop)
                    if self.state is not None:
                        await asyncio.to_thread(self.state.backup)
                except Exception:
                    await send({"type": "lifespan.shutdown.failed", "message": "queue shutdown or private backup failed"})
                    return
                await send({"type": "lifespan.shutdown.complete"})
                return

    async def __call__(self, scope, receive, send):
        if scope["type"] == "lifespan":
            return await self._lifespan(receive, send)
        if scope["type"] != "http":
            return
        required_scope, request, parse_error = "qq:read", None, False
        try:
            raw_headers = scope.get("headers", [])
            headers = {k.decode("ascii").lower(): v.decode("latin1") for k, v in raw_headers}
            for name in (b"authorization", b"host", b"x-signature", b"x-self-id", b"content-length"):
                if sum(k.lower() == name for k, _ in raw_headers) > 1:
                    return await self._respond(send, 400, {"error": "duplicate security header"})
            if (headers.get("host", "").lower() not in self.hosts
                    or headers.get("origin") not in (None, self.origin)
                    or scope.get("client", ("",))[0] != "127.0.0.1"):
                return await self._respond(send, 403, {"error": "invalid origin or transport"})
            path, method = scope["path"], scope["method"]
            if path == "/onebot/events" and (headers.get("host", "").lower() != self.local_host or "origin" in headers):
                return await self._respond(send, 403, {"error": "gateway route is local only"})
            if scope.get("query_string"):
                return await self._respond(send, 400, {"error": "query parameters are not supported"})
            if path == "/healthz" and method == "GET":
                ready = self.worker.healthy and not self.closing
                return await self._respond(send, 200 if ready else 503, {"ready": ready})
            if path in (self.metadata_path, "/.well-known/oauth-protected-resource") and method == "GET":
                if not self.limits["metadata"].allow():
                    return await self._respond(send, 429, {"error": "rate limited"}, [(b"retry-after", b"1")])
                return await self._respond(send, 200, self.auth.metadata())
            if self.closing or not self.worker.healthy:
                return await self._respond(send, 503, {"error": "queue unavailable"})
            if path not in (self.mcp_path, "/onebot/events"):
                return await self._respond(send, 404, {"error": "not found"})
            if method != "POST":
                return await self._respond(send, 405, {"error": "POST required"}, [(b"allow", b"POST")])
            if not self.limits["mcp" if path == self.mcp_path else "gateway"].allow():
                return await self._respond(send, 429, {"error": "rate limited"}, [(b"retry-after", b"1")])
            if headers.get("content-type", "").split(";")[0] != "application/json" or headers.get("content-encoding"):
                return await self._respond(send, 415, {"error": "uncompressed JSON required"})
            if "content-length" in headers and not 0 < int(headers["content-length"]) <= 262144:
                return await self._respond(send, 413, {"error": "body too large"})
            body, started = bytearray(), time.monotonic()
            while True:
                message = await asyncio.wait_for(receive(), timeout=max(0.01, 10 - (time.monotonic() - started)))
                if message["type"] == "http.disconnect":
                    return
                body.extend(message.get("body", b""))
                if len(body) > 262144:
                    return await self._respond(send, 413, {"error": "body too large"})
                if not message.get("more_body"):
                    break
                if time.monotonic() - started >= 10:
                    raise TimeoutError()
            if path == "/onebot/events":
                record = decode_event(bytes(body), headers, self.gateway_secret,
                    account_id=int(self.bridge.filters["account_id"]), peer_id=int(self.bridge.filters["conversation_id"]), now=self.bridge.clock())
                await asyncio.to_thread(self.bridge.ingest, record)
                return await self._respond(send, 200, {})
            # Parse only to choose the auth response/scope; no tool is invoked
            # and no parser result is returned until token validation succeeds.
            try:
                request = json.loads(body)
            except (ValueError, UnicodeError):
                parse_error = True
            if isinstance(request, dict):
                method_name, params = request.get("method", ""), request.get("params", {})
                if method_name in ("events/subscribe", "events/unsubscribe"):
                    required_scope = "qq:events"
                elif method_name == "tools/call" and isinstance(params, dict) and params.get("name") == "qq_reply":
                    required_scope = "qq:reply"
                elif (method_name == "tools/call" and isinstance(params, dict)
                      and isinstance(params.get("name"), str) and params["name"] in TOOL_SCOPES):
                    required_scope = TOOL_SCOPES[params["name"]]
            _, expires_at = await asyncio.to_thread(self.auth.authenticate_with_expiry, headers.get("authorization"), required_scope)
            principal = self.auth.binding_principal
            if headers.get("mcp-protocol-version") not in (None, "2026-07-28"):
                return await self._respond(send, 400, {"error": "unsupported protocol version"})
            if parse_error:
                return await self._respond(send, 200, {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}})
            if isinstance(request, dict) and request.get("method") == "events/subscribe" and isinstance(request.get("params"), dict):
                params = dict(request["params"])
                remaining_ms = min(3600000, int((expires_at - time.time()) * 1000))
                if remaining_ms <= 0:
                    raise AuthError()
                ttl = params.get("ttlMs")
                if ttl is None or (type(ttl) is int and ttl > remaining_ms):
                    params["ttlMs"] = remaining_ms
                request = {**request, "params": params}
            result = await asyncio.to_thread(self.bridge.rpc, principal, request, access_deadline=expires_at)
            return await self._respond(send, 200, result)
        except AuthError as exc:
            challenge = self.auth.www_authenticate(required_scope, exc.error).encode("ascii")
            # Tool-level relinking needs the MCP result metadata, not only an
            # HTTP challenge. Do not turn a broken local trust store into login.
            if (exc.status_code in (401, 403) and isinstance(request, dict)
                    and request.get("jsonrpc") == "2.0" and type(request.get("id")) in (str, int)
                    and request.get("method") == "tools/call" and isinstance(request.get("params"), dict)
                    and isinstance(request["params"].get("name"), str)
                    and request["params"]["name"] in {"bridge_status", "qq_reply", *TOOL_SCOPES}
                    and isinstance(request["params"].get("arguments", {}), dict)):
                return await self._respond(send, 200, {"jsonrpc": "2.0", "id": request["id"], "result": {
                    "isError": True, "content": [{"type": "text", "text": "Authorization is required for this tool."}],
                    "_meta": {"mcp/www_authenticate": [challenge.decode("ascii")]}}})
            return await self._respond(send, exc.status_code, {"error": exc.error or "authentication unavailable"}, [(b"www-authenticate", challenge)])
        except GatewayRejected:
            return await self._respond(send, 403, {"error": "gateway message rejected"})
        except RpcError as exc:
            return await self._respond(send, 503 if exc.code == -32025 else 403, {"error": "message not accepted"})
        except TimeoutError:
            return await self._respond(send, 408, {"error": "request timed out"})
        except (ValueError, TypeError, UnicodeError):
            return await self._respond(send, 400, {"error": "invalid request"})
        except Exception:
            return await self._respond(send, 503, {"error": "service unavailable"})


def _validate_auth_options(config):
    remote = config.get("jwks_from_issuer", False)
    tunnel = config.get("secure_mcp_tunnel", False)
    if type(remote) is not bool or type(tunnel) is not bool:
        raise ValueError("JWKS source and Tunnel mode must be booleans")
    if (remote and "jwks_file" in config) or (not remote and "jwks_file" not in config):
        raise ValueError("select exactly one JWKS source")
    if not remote and config.get("jwks_proxy_url") is not None:
        raise ValueError("JWKS proxy requires issuer retrieval")
    validate_proxy_url(config.get("jwks_proxy_url"))


def load_config(path):
    # Configuration contains paths and public identifiers, never inline secrets.
    raw = read_secret_file(path, max_bytes=65536)
    config = json.loads(raw)
    required = {"public_resource_url", "oauth_issuer", "owner_subject", "onebot_url",
                "onebot_token_file", "state_key_file", "account_id", "peer_id"}
    optional = {"state_dir", "listen_port", "max_messages", "webhook_proxy_url", "jwks_file",
                "jwks_from_issuer", "jwks_proxy_url", "secure_mcp_tunnel", "file_download_hosts", "media_proxy_url"}
    if not isinstance(config, dict) or not required <= config.keys() or config.keys() - required - optional:
        raise ValueError("missing or unknown configuration fields")
    validate_callback_url(config["public_resource_url"])
    validate_proxy_url(config.get("webhook_proxy_url"))
    _validate_auth_options(config)
    url = urlsplit(config["public_resource_url"])
    if (url.query or "?" in config["public_resource_url"]
            or (not config.get("secure_mcp_tunnel", False) and url.path != "/mcp")):
        raise ValueError("resource must be query-free; direct HTTPS mode requires /mcp")
    port = config.get("listen_port", 8765)
    if type(port) is not int or not 1024 <= port <= 65535:
        raise ValueError("listen_port must be between 1024 and 65535")
    for field in ("account_id", "peer_id"):
        if type(config[field]) is not int or config[field] <= 0:
            raise ValueError("numeric account/friend binding required")
    for field in ("jwks_file", "onebot_token_file", "state_key_file", "state_dir"):
        if field in config:
            value = Path(config[field]).expanduser()
            config[field] = str(value if value.is_absolute() else Path(path).resolve().parent / value)
    return config


def validate_configuration(config):
    validate_proxy_url(config.get("webhook_proxy_url"))
    validate_proxy_url(config.get("media_proxy_url"))
    file_hosts(config.get("file_download_hosts", []))
    _validate_auth_options(config)
    auth = Authenticator(issuer=config["oauth_issuer"], public_resource_url=config["public_resource_url"],
                         owner_subject=config["owner_subject"], jwks_path=config.get("jwks_file"),
                         jwks_from_issuer=config.get("jwks_from_issuer", False),
                         jwks_proxy_url=config.get("jwks_proxy_url"),
                         local_metadata_port=config.get("listen_port", 8765) if config.get("secure_mcp_tunnel", False) else None)
    token = read_secret_file(config["onebot_token_file"])
    if len(token) < 32:
        raise ValueError("OneBot token must contain at least 32 characters")
    cipher = StateCipher(read_secret_file(config["state_key_file"]))
    gateway = LoopbackOneBot(config["onebot_url"], token, account_id=config["account_id"], peer_id=config["peer_id"])
    return auth, token, cipher, gateway


def create_application(config):
    """Load existing configuration; issuer JWKS retrieval starts on authentication."""
    auth, token, cipher, gateway = validate_configuration(config)
    state = StateDirectory(config.get("state_dir"))
    state.__enter__()
    try:
        bridge = Bridge(state.db_path, principal=auth.binding_principal, account_id=config["account_id"],
                        peer_id=config["peer_id"], cipher=cipher, production_auth_ready=True,
                        max_messages=config.get("max_messages", 10000),
                        media_fetcher=ImageFetcher(download_hosts=config.get("file_download_hosts", []), proxy_url=config.get("media_proxy_url")),
                        webhook_transport=PublicWebhookTransport(timeout=10, proxy_url=config.get("webhook_proxy_url")), gateway=gateway)
        return Application(bridge, auth, token, port=config.get("listen_port", 8765), state=state)
    except BaseException:
        state.__exit__(None, None, None)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--config")
    source.add_argument("--prepare-windows-directory", metavar="PATH", help="create/verify a private Windows project directory; no credentials or service")
    parser.add_argument("--check", action="store_true", help="validate configuration without opening a listener or sending traffic")
    args = parser.parse_args()
    app = None
    try:
        if args.prepare_windows_directory:
            if os.name != "nt" or args.check:
                raise ValueError("private Windows directory preparation requires Windows")
            from .windows_state import WindowsPrivateDirectory
            with WindowsPrivateDirectory(args.prepare_windows_directory):
                pass
            print("Private Windows directory verified. No credentials, listener or system service was created.")
            return
        config = load_config(args.config)
        if args.check:
            validate_configuration(config)
            print("Authentication settings and secret files valid; remote JWKS, network and account connectivity were not tested.")
            return
        if os.name == "posix":
            os.umask(0o077)
        app = create_application(config)
        uvicorn.run(app, host="127.0.0.1", port=config.get("listen_port", 8765), workers=1,
                    http="h11", ws="none", lifespan="on", proxy_headers=False,
                    limit_concurrency=16, backlog=32, timeout_keep_alive=5,
                    timeout_graceful_shutdown=45, access_log=False, log_level="warning")
    except Exception:
        # Config files may reference secrets; do not print exception contents.
        parser.exit(2, "Startup/operation failed closed. Check config, private file permissions, state integrity and single-instance ownership.\n")
    finally:
        if app is not None:
            app.closing = True
            app.worker.stop()  # Never release the single-instance lock while sends run.
            app.state.__exit__(None, None, None)


if __name__ == "__main__":
    main()
