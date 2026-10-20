"""Disposable Windows media assembly check; no real QQ/dot or public network.

Runs the committed runtime in a child process with actual loopback HTTP peers.
Only this test maps fixed synthetic callback/image origins onto local HTTP peers.
This checks runtime/HTTP/storage integration, not public DNS/TLS or real dot vision.
"""
import argparse
import base64
import hashlib
import hmac
import http.client as http_client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time
import uuid

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
from bridge_service.core import EVENT, canonical
from bridge_service.test_service import SECRET, Callback
from bridge_service.test_media import picture, QQ_URL, FILE

CALLBACK = 'https://receiver.example/callback'
RESOURCE = 'https://bridge.example.invalid/v1/mcp/tunnel_synthetic'
ONEBOT = 'synthetic-only-onebot-secret-00000000'


def http(port, path, value=None, headers=None):
    conn = http_client.HTTPConnection('127.0.0.1', port, timeout=3)
    try:
        body = None if value is None else (value if isinstance(value, bytes) else canonical(value).encode())
        conn.request('GET' if value is None else 'POST', path, body, headers or {})
        response = conn.getresponse()
        data = response.read(262145)
        assert len(data) <= 262144, 'oversized fixture response'
        return response.status, data, dict(response.getheaders())
    finally:
        conn.close()


def wait_for(predicate, label, timeout=12):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            result = predicate()
            if result:
                return result
        except (OSError, http_client.HTTPException):
            pass
        threading.Event().wait(0.25)
    raise AssertionError(label)


class FixtureTransport:
    def __init__(self, port):
        self.port = port

    def post(self, url, body, headers):
        assert url == CALLBACK, 'unexpected callback origin'
        status, data, _ = http(self.port, '/callback', body, headers)
        return status, data


def child(config_path, callback_port):
    import uvicorn
    from bridge_service.runtime import create_application, load_config
    app = create_application(load_config(config_path))
    app.bridge.webhook_transport = FixtureTransport(callback_port)
    # Isolated test-only connection replacement: exercise the production GET,
    # limits, MIME verification and decoder over real loopback HTTP. Never
    # install this mapping in the runtime entry point or production transport.
    from bridge_service import media
    def fixture_connection(host, port, **kwargs):
        assert host in {'multimedia.nt.qq.com', 'gxh.vip.qq.com', 'uploads.example'} and port == 443
        return http_client.HTTPConnection('127.0.0.1', callback_port, timeout=3)
    media._PublicHTTPSConnection = fixture_connection
    server = uvicorn.Server(uvicorn.Config(app, host='127.0.0.1', port=load_config(config_path)['listen_port'],
        workers=1, http='h11', ws='none', lifespan='on', proxy_headers=False,
        access_log=False, log_config=None, log_level='critical', timeout_graceful_shutdown=15))
    def control():
        for line in sys.stdin:
            if line.strip() == 'stop':
                server.should_exit = True
                return
            if line.strip() == 'fail-worker':
                def fail():
                    raise RuntimeError('synthetic worker failure')
                app.bridge.dispatch_event = fail
        server.should_exit = True
    threading.Thread(target=control, daemon=True).start()
    try:
        server.run()
    finally:
        app.worker.stop()
        app.state.close()


class Receiver:
    def __init__(self):
        self.callback = Callback()
        self.verified = 0
        self.fail_once = False

    def handle(self, handler, body):
        from standardwebhooks import Webhook
        Webhook(SECRET).verify(body.decode(), dict(handler.headers))
        self.verified += 1
        status, data = self.callback.post(CALLBACK, body, dict(handler.headers))
        if json.loads(body).get('type') != 'verification' and self.fail_once:
            self.fail_once = False
            return 503, b''
        return status, data

    def events(self):
        return [json.loads(body) for _, body, _ in self.callback.requests if json.loads(body).get('type') != 'verification']


class QQ:
    def __init__(self):
        self.account, self.sends, self.ambiguous = 100001, [], False

    def handle(self, handler, body):
        assert handler.headers.get('Authorization') == 'Bearer ' + ONEBOT, 'wrong synthetic gateway auth'
        args = json.loads(body)
        if handler.path == '/get_login_info':
            data = {'user_id': self.account}
        elif handler.path == '/get_image':
            data = {'url': QQ_URL.replace('synthetic-old', 'synthetic-new')}
        elif handler.path == '/search_sys_faces':
            data = {'faces': [{'q_sid': '14', 'q_des': 'synthetic smile'}]}
        elif handler.path == '/fetch_face_entity':
            data = {'q_sid': '14'} if args['face_id'] == 14 else None
        elif handler.path == '/fetch_custom_face_detail':
            data = [{'emoji_id': 'saved_fixture', 'desc': 'synthetic saved sticker'}]
        else:
            if handler.path == '/send_qzone_msg':
                assert args['ugc_right'] in (16, 64) and isinstance(args['target_uins'], list)
            else:
                assert handler.path in ('/send_private_msg', '/send_custom_face') and args['user_id'] == 100002, 'unbound gateway action'
                if handler.path == '/send_private_msg':
                    assert args['auto_escape'] is True, 'missing text escaping'
            self.sends.append({'action': handler.path, 'params': args})
            if self.ambiguous:
                handler.close_connection = True
                return None
            data = {'tid': 'synthetic-post'} if handler.path == '/send_qzone_msg' else {'message_id': len(self.sends) + 900}
        return 200, canonical({'status': 'ok', 'retcode': 0, 'data': data}).encode()


def peer_server(peer):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass
        def do_GET(self):
            # Receiver doubles as a fixed synthetic image server.
            if not isinstance(peer, Receiver):
                self.send_error(404)
                return
            gif = self.path.split('?')[0].endswith('.gif')
            data = picture('GIF', 2) if gif else picture()
            self.send_response(200)
            self.send_header('Content-Type', 'image/gif' if gif else 'image/png')
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        def do_POST(self):
            try:
                count = int(self.headers['Content-Length'])
                assert 0 < count <= 262144
                result = peer.handle(self, self.rfile.read(count))
                if result is None:
                    return
                status, data = result
            except Exception:
                status, data = 400, b'{}'
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def main(parent_directory):
    import jwt
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives.asymmetric import rsa
    from bridge_service.windows_state import WindowsPrivateDirectory
    from bridge_service.windows_selfcheck import _test_directory, _cleanup_test_directory

    report = {'kind': 'synthetic_windows_media_assembly', 'real_qq_dot': False, 'public_dns_tls': False, 'checks': [], 'status': 'failed'}
    parent = Path(parent_directory).resolve(strict=True)
    root = _test_directory(parent, 'QQAstra-selfcheck-' + uuid.uuid4().hex)
    owned, process, servers, stage = False, None, [], 'private_fixture'
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    def start():
        return subprocess.Popen([sys.executable, str(Path(__file__).resolve()), '--child', str(root / 'config.json'), str(receiver_port)],
            cwd=REPO, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, text=True)
    def stop():
        nonlocal process
        if process is not None:
            if process.poll() is None:
                process.stdin.write('stop\n')
                process.stdin.flush()
            process.wait(timeout=20)
            assert process.returncode == 0, 'child did not shut down cleanly'
            process.stdin.close()
            process = None
    try:
        qq, receiver = QQ(), Receiver()
        servers = [peer_server(qq), peer_server(receiver)]
        qq_port, receiver_port = [server.server_address[1] for server in servers]
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1', 0))
            port = reservation.getsockname()[1]
        config = {'public_resource_url': RESOURCE, 'secure_mcp_tunnel': True, 'oauth_issuer': 'https://issuer.example/',
            'owner_subject': 'synthetic-owner', 'jwks_file': './public-jwks.json', 'onebot_url': f'http://127.0.0.1:{qq_port}',
            'onebot_token_file': './onebot.token', 'state_key_file': './state.key', 'state_dir': './state',
            'account_id': 100001, 'peer_id': 100002, 'listen_port': port, 'file_download_hosts': ['uploads.example']}
        jwk = {**json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private.public_key())), 'kid': 'synthetic', 'alg': 'RS256', 'use': 'sig'}
        with WindowsPrivateDirectory(root) as directory:
            owned = True
            files = {'config.json': canonical(config), 'public-jwks.json': canonical({'keys': [jwk]}),
                     'onebot.token': ONEBOT, 'state.key': Fernet.generate_key().decode()}
            for name, value in files.items():
                directory.create_file(name).write_text(value, encoding='utf-8')
        stage = 'offline_config_check'
        checked = subprocess.run([sys.executable, '-m', 'bridge_service.runtime', '--config', str(root / 'config.json'), '--check'],
            cwd=REPO, capture_output=True, timeout=15)
        assert checked.returncode == 0, 'private configured-path check failed'
        report['checks'].append('real CLI --check with Windows-protected synthetic files')
        def token(scope='qq:read qq:events qq:reply qq:media:read qq:media:send qq:qzone:publish', **claims):
            now = int(time.time())
            return jwt.encode({'iss': config['oauth_issuer'], 'aud': [RESOURCE, 'https://issuer.example/userinfo'],
                'sub': 'synthetic-owner', 'iat': now - 1, 'exp': now + 600, 'scope': scope, **claims},
                private, algorithm='RS256', headers={'typ': 'at+jwt', 'kid': 'synthetic'})
        def rpc(method, params=None, credential=None):
            # Stay within the production MCP rate limit (two requests/second).
            threading.Event().wait(0.51)
            status, data, _ = http(port, '/mcp', {'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params or {}},
                {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + (credential or token())})
            assert status == 200, 'RPC HTTP failure'
            return json.loads(data)
        def status():
            return json.loads(rpc('tools/call', {'name': 'bridge_status', 'arguments': {}})['result']['content'][0]['text'])
        def ingest(message_id, text='assembly-synthetic-private-message', segments=None):
            event = {'post_type': 'message', 'message_type': 'private', 'sub_type': 'friend', 'self_id': 100001,
                'user_id': 100002, 'sender': {'user_id': 100002}, 'message_id': message_id, 'time': int(time.time()),
                'message': segments or [{'type': 'text', 'data': {'text': text}}]}
            raw = canonical(event).encode()
            signature = 'sha1=' + hmac.new(ONEBOT.encode(), raw, hashlib.sha1).hexdigest()
            assert http(port, '/onebot/events', raw, {'Content-Type': 'application/json', 'X-Self-ID': '100001', 'X-Signature': signature})[0] == 200
            return raw
        def reply(event_id, text, **extra):
            return rpc('tools/call', {'name': 'qq_reply', 'arguments': {'event_id': event_id, 'text': text, **extra}})
        def replies(expected):
            wait_for(lambda: status()['replies'] == expected, 'reply state missing')
        stage = 'child_start_and_discovery'
        process = start()
        wait_for(lambda: http(port, '/healthz')[0] == 200, 'runtime not ready')
        assert json.loads(http(port, '/.well-known/oauth-protected-resource/mcp')[1])['resource'] == RESOURCE
        assert rpc('server/discover')['result']['supportedVersions'] == ['2026-07-28']
        assert http(port, '/mcp', {}, {'Content-Type': 'application/json'})[0] == 401
        report['checks'].append('child process startup, loopback HTTP, metadata and authenticated discovery')
        subscription = {'name': EVENT, 'arguments': {'account_id': '100001', 'conversation_id': '100002', 'sender_id': '100002'},
            'ttlMs': 600000, 'delivery': {'mode': 'webhook', 'url': CALLBACK, 'secret': SECRET}}
        stage = 'subscription_challenge'
        receiver.callback.challenge_ok = False
        assert rpc('events/subscribe', subscription)['error']['code'] == -32015
        assert status()['active_subscriptions'] == 0
        receiver.callback.challenge_ok = True
        assert 'result' in rpc('events/subscribe', subscription)
        assert receiver.verified == 2
        report['checks'].append('signed HTTP subscription challenge: wrong echo rejected, valid echo accepted')
        stage = 'dedup_and_reply'
        raw = ingest(77)
        signature = 'sha1=' + hmac.new(ONEBOT.encode(), raw, hashlib.sha1).hexdigest()
        assert http(port, '/onebot/events', raw, {'Content-Type': 'application/json', 'X-Self-ID': '100001', 'X-Signature': signature})[0] == 200
        assert http(port, '/onebot/events', raw, {'Content-Type': 'application/json', 'X-Self-ID': '100001', 'X-Signature': 'sha1=invalid'})[0] == 403
        wait_for(lambda: len(receiver.events()) == 1, 'event not delivered')
        first_event = receiver.events()[0]['eventId']
        assert status()['received_messages'] == 1
        args = {'event_id': first_event, 'text': 'assembly-synthetic-private-reply'}
        denied = rpc('tools/call', {'name': 'qq_reply', 'arguments': args}, token('qq:read'))
        assert denied['result']['isError'] and not qq.sends
        assert 'error' in reply(first_event, args['text'], user_id='999999')
        reply(first_event, args['text'])
        replies({'confirmed': 1})
        reply(first_event, args['text'])
        assert len(qq.sends) == 1
        report['checks'].append('signed OneBot ingress dedup, bad signature rejection, scoped/bound/idempotent reply over real HTTP')
        stage = 'delivery_and_gateway_failures'
        receiver.fail_once = True
        ingest(78)
        wait_for(lambda: len(receiver.events()) == 3, 'callback retry missing')
        assert receiver.events()[1]['eventId'] == receiver.events()[2]['eventId']
        second_event = receiver.events()[2]['eventId']
        qq.account = 999999
        reply(second_event, 'synthetic-account-mismatch')
        replies({'confirmed': 1, 'failed': 1})
        assert len(qq.sends) == 1
        qq.account, qq.ambiguous = 100001, True
        ingest(79)
        wait_for(lambda: len(receiver.events()) == 4, 'third event missing')
        third_event = receiver.events()[3]['eventId']
        reply(third_event, 'synthetic-ambiguous-reply')
        replies({'confirmed': 1, 'failed': 1, 'uncertain': 1})
        assert len(qq.sends) == 2
        report['checks'].append('503 event retry preserves event ID; account mismatch fails without send; lost send response becomes uncertain')
        stage = 'media_read_and_identity'
        qq.ambiguous = False
        ingest(80, segments=[{'type': 'image', 'data': {'file': 'fixture.png', 'url': QQ_URL}},
            {'type': 'mface', 'data': {'emoji_id': 'a' * 32, 'emoji_package_id': 10, 'key': 'synthetic'}}])
        wait_for(lambda: len(receiver.events()) == 5, 'media event missing')
        media_event = receiver.events()[-1]
        assert len(qq.sends) == 2, 'incoming event caused a write'
        assert 'rkey' not in canonical(media_event)
        identity = media_event['data']['sender_identity']
        assert (identity['qq_id'], identity['bot_qq_id'], identity['role']) == ('100002', '100001', 'bound_owner')
        def tool(name, arguments, credential=None):
            return rpc('tools/call', {'name': name, 'arguments': arguments}, credential)
        def value(name, arguments):
            result = tool(name, arguments)
            assert 'error' not in result and not result['result']['isError'], 'media tool failed: ' + name
            return json.loads(result['result']['content'][0]['text'])
        refs = [{'event_id': media_event['eventId'], 'attachment_id': entry['attachment_id']} for entry in media_event['data']['attachments']]
        assert tool('qq_read_image', refs[0], token('qq:read'))['result']['isError']
        visual = tool('qq_read_image', refs[0])['result']
        assert visual['content'][1]['type'] == 'image' and visual['content'][1]['mimeType'] == 'image/png'
        assert base64.b64decode(visual['content'][1]['data']).startswith(b'\x89PNG\r\n\x1a\n')
        assert json.loads(visual['content'][0]['text'])['sender_identity'] == identity
        assert tool('qq_read_image', {**refs[0], 'event_id': 'unknown'})['result']['isError']
        report['checks'].append('signed image/mface ingress carries fixed owner identity; real GET/decoder returns MCP PNG; scope and unrelated attachment rejected')
        stage = 'media_sends_and_space'
        operations = []
        def queue(name, arguments, expected='confirmed'):
            value(name, arguments)
            wait_for(lambda: value('qq_operation_status', {'request_id': arguments['request_id']})['state'] == expected,
                     'operation did not reach ' + expected)
            operations.append((name, arguments, expected))
        for fmt in ('PNG', 'GIF'):
            file = {**FILE, 'file_id': 'file_' + fmt, 'download_url': 'https://uploads.example/fixture.' + fmt.lower(),
                'mime_type': 'image/' + fmt.lower()}
            arguments = {'request_id': 'media_' + fmt, 'file': file, 'as_sticker': fmt == 'GIF'}
            assert tool('qq_send_image', arguments, token('qq:read qq:reply'))['result']['isError']
            queue('qq_send_image', arguments)
            segment = qq.sends[-1]['params']['message'][0]['data']
            assert segment['sub_type'] == int(fmt == 'GIF')
            assert base64.b64decode(segment['file'].removeprefix('base64://')) == picture(fmt, 2 if fmt == 'GIF' else 1)
        assert value('qq_list_faces', {'query': 'smile'})['faces'][0]['face_id'] == 14
        queue('qq_send_face', {'request_id': 'media_face', 'face_id': 14})
        assert value('qq_list_custom_faces', {'count': 10})['stickers'][0]['emoji_id'] == 'saved_fixture'
        queue('qq_send_custom_face', {'request_id': 'media_saved', 'emoji_id': 'saved_fixture'})
        assert qq.sends[-1]['action'] == '/send_custom_face'
        queue('qq_send_market_face', {'request_id': 'media_market', **refs[1]})
        assert qq.sends[-1]['params']['message'][0]['type'] == 'mface'
        post = {'request_id': 'media_space', 'content': 'assembly-synthetic-space-post', 'ugc_right': 64, 'target_uins': [], 'images': []}
        assert tool('qq_publish_qzone', post, token('qq:media:send'))['result']['isError']
        assert tool('qq_publish_qzone', {k: v for k, v in post.items() if k != 'ugc_right'})['result']['isError']
        queue('qq_publish_qzone', post)
        queue('qq_publish_qzone', {**post, 'request_id': 'media_space_image', 'ugc_right': 16, 'target_uins': [100002], 'images': [FILE]})
        assert qq.sends[-1]['action'] == '/send_qzone_msg' and qq.sends[-1]['params']['images'][0].startswith('base64://')
        qq.ambiguous = True
        queue('qq_send_face', {'request_id': 'media_unknown', 'face_id': 14}, 'uncertain')
        qq.ambiguous = False
        sends_before_restart = len(qq.sends)
        report['checks'].append('PNG/GIF bytes, system face, dedicated saved sticker, mface, explicit text/image space writes traverse simulated QQ HTTP; old scopes denied; lost response uncertain')
        stage = 'shutdown_backup_restart'
        stop()
        state = root / 'state'
        assert (state / 'bridge.backup.sqlite3').is_file()
        for path in state.glob('*.sqlite3*'):
            data = path.read_bytes()
            for text in (args['text'], 'assembly-synthetic-private-message', SECRET, 'synthetic-owner', post['content'], 'synthetic-old'):
                assert text.encode() not in data, 'plaintext fixture in persistent state'
        import sqlite3
        db = sqlite3.connect(state / 'bridge.sqlite3')
        try:
            assert db.execute('SELECT count(*) FROM operations WHERE payload IS NOT NULL').fetchone()[0] == 0
        finally:
            db.close()
        process = start()
        wait_for(lambda: http(port, '/healthz')[0] == 200, 'reopened runtime not ready')
        assert status()['replies'] == {'confirmed': 1, 'failed': 1, 'uncertain': 1}
        assert json.loads(reply(first_event, args['text'])['result']['content'][0]['text'])['state'] == 'confirmed'
        assert json.loads(reply(third_event, 'synthetic-ambiguous-reply')['result']['content'][0]['text'])['state'] == 'uncertain'
        for name, arguments, expected in operations:
            assert value(name, arguments)['state'] == expected
        assert tool('qq_read_image', refs[0])['result']['content'][1]['type'] == 'image'
        threading.Event().wait(1.1)
        assert len(qq.sends) == sends_before_restart
        report['checks'].append('graceful process exit creates encrypted backup; new process restores state without replaying confirmed/uncertain sends')
        stage = 'worker_failure'
        process.stdin.write('fail-worker\n')
        process.stdin.flush()
        wait_for(lambda: http(port, '/healthz')[0] == 503, 'worker failure not unhealthy')
        assert http(port, '/mcp', {}, {'Content-Type': 'application/json'})[0] == 503
        stop()
        report['checks'].append('worker crash produces HTTP 503 readiness and request failure, then clean shutdown')
        report.update(status='passed', verified_webhook_requests=receiver.verified,
            simulated_qq_http_sends=len(qq.sends), listener_addresses=['127.0.0.1'],
            git_tree=subprocess.check_output(['git', 'rev-parse', 'HEAD^{tree}'], cwd=REPO, text=True).strip(),
            tracked_worktree_dirty=bool(subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=no'], cwd=REPO, text=True).strip()))
    except Exception as exc:
        report.update(failure_stage=stage, failure_type=type(exc).__name__)
        import traceback
        report['failure_line'] = traceback.extract_tb(exc.__traceback__)[-1].lineno
        if hasattr(exc, 'safe_details'):
            report['details'] = exc.safe_details()
    finally:
        if process is not None:
            try:
                stop()
            except Exception:
                process.kill()
                process.wait(timeout=5)
                report['forced_child_cleanup'] = True
        for server in servers:
            server.shutdown()
            server.server_close()
        if owned:
            try:
                _cleanup_test_directory(root, parent)
                report['temporary_directory_removed'] = True
            except OSError:
                report.update(status='failed', cleanup_failed=True)
    print(json.dumps(report))
    return 0 if report['status'] == 'passed' else 2


if __name__ == '__main__':
    if sys.platform != 'win32':
        print('{"status":"not_tested","reason":"Windows required"}')
        sys.exit(2)
    if len(sys.argv) == 4 and sys.argv[1] == '--child':
        try:
            child(sys.argv[2], int(sys.argv[3]))
        except Exception:
            sys.exit(2)
    else:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument('--parent-directory', required=True, help='Existing approved parent for a new disposable protected directory')
        sys.exit(main(parser.parse_args().parent_directory))
