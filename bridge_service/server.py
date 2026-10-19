"""Loopback-only fixture HTTP harness. Production startup fails closed.

This is not an OAuth server or a publicly deployable authentication substitute.
Neither a real QQ gateway nor public webhook transport can be enabled here.
"""

import argparse
import hmac
import json
import tempfile
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from .core import Bridge, RpcError, canonical
from .gateway import GatewayRejected, decode_event

FIXTURE_PRINCIPAL = "fixture-owner"
FIXTURE_TOKEN = "public-test-fixture-not-a-production-credential"
FIXTURE_GATEWAY_SECRET = "public-onebot-test-fixture"
FIXTURE_ACCOUNT, FIXTURE_PEER = 100001, 100002


def make_fixture_server(port=0, db_path=None):
    """Only synthetic fixture identities. No production credential inputs."""
    temp = tempfile.TemporaryDirectory(prefix="qq-astra-fixture-") if db_path is None else None
    bridge = Bridge(db_path or Path(temp.name) / "fixture.sqlite3", principal=FIXTURE_PRINCIPAL,
                    account_id=FIXTURE_ACCOUNT, peer_id=FIXTURE_PEER)
    bridge.recover_interrupted_replies()

    class Handler(BaseHTTPRequestHandler):
        server_version = "QQAstraFixture/0.1"

        def log_message(self, *_):
            pass  # Never log message bodies, tokens, signatures, or callback URLs.

        def setup(self):
            super().setup()
            self.connection.settimeout(5)

        def respond(self, code, body):
            data = canonical(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self):
            expected_host = "127.0.0.1:" + str(self.server.server_port)
            if (self.headers.get("Host") != expected_host or self.headers.get("Origin") is not None
                    or self.client_address[0] != "127.0.0.1"):
                return self.respond(403, {"error": "fixture loopback access only"})
            if (self.headers.get("Transfer-Encoding") or self.headers.get("Content-Encoding")
                    or len(self.headers.get_all("Content-Length", [])) != 1
                    or self.headers.get("Content-Type", "").split(";")[0] != "application/json"):
                return self.respond(400, {"error": "JSON with one Content-Length required"})
            try:
                size = int(self.headers["Content-Length"])
                if not 0 < size <= 262144:
                    return self.respond(413, {"error": "invalid body size"})
                raw = self.rfile.read(size)
                if len(raw) != size:
                    raise ValueError()
                if self.path == "/mcp":
                    if not hmac.compare_digest(self.headers.get("Authorization", ""), "Bearer " + FIXTURE_TOKEN):
                        return self.respond(401, {"error": "fixture authentication required"})
                    version = self.headers.get("MCP-Protocol-Version")
                    if version not in (None, "2026-07-28"):
                        return self.respond(400, {"error": "unsupported protocol version"})
                    try:
                        request = json.loads(raw)
                    except (ValueError, UnicodeError):
                        return self.respond(200, {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}})
                    result = bridge.rpc(FIXTURE_PRINCIPAL, request)
                    return self.respond(200, result)
                if self.path == "/onebot/events":
                    record = decode_event(raw, dict(self.headers), FIXTURE_GATEWAY_SECRET,
                                          account_id=FIXTURE_ACCOUNT, peer_id=FIXTURE_PEER, now=bridge.clock())
                    bridge.ingest(record)
                    # Empty JSON deliberately prevents OneBot quick-operation replies.
                    return self.respond(200, {})
                return self.respond(404, {"error": "not found"})
            except GatewayRejected:
                return self.respond(403, {"error": "gateway message rejected"})
            except RpcError:
                return self.respond(403, {"error": "binding unavailable"})
            except (ValueError, TypeError, UnicodeError):
                return self.respond(400, {"error": "invalid request"})
            except Exception:
                return self.respond(500, {"error": "request failed"})

    server = HTTPServer(("127.0.0.1", port), Handler)
    server.bridge, server.fixture_directory = bridge, temp
    return server


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", action="store_true", help="synthetic loopback harness only")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    if not args.fixture:
        parser.error("production startup disabled: verified OAuth principal, protected storage and deployment integration are not configured")
    with make_fixture_server(args.port) as server:
        print(f"Fixture only: http://127.0.0.1:{server.server_port}/mcp; no real QQ/dot delivery. Do not publish or tunnel this harness.")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            if server.fixture_directory:
                server.fixture_directory.cleanup()


if __name__ == "__main__":
    main()
