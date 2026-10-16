"""端到端测试用的源站：GET /payload 返回固定随机数据，POST /echo 回显 body 的 sha256。"""
import hashlib
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SIZE = 4 * 1024 * 1024
PAYLOAD = os.urandom(SIZE)
PAYLOAD_SHA = hashlib.sha256(PAYLOAD).hexdigest()


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def do_GET(self):
        if self.path != '/payload':
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header('Content-Type', 'application/octet-stream')
        self.send_header('Content-Length', str(len(PAYLOAD)))
        self.send_header('X-Payload-Sha256', PAYLOAD_SHA)
        self.end_headers()
        self.wfile.write(PAYLOAD)

    def do_POST(self):
        if self.path != '/echo':
            self.send_error(404)
            return
        length = int(self.headers.get('Content-Length') or 0)
        body = self.rfile.read(length) if length else b''
        digest = hashlib.sha256(body).hexdigest()
        out = f'{digest} {len(body)}'.encode()
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.send_header('Content-Length', str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *args):
        pass


if __name__ == '__main__':
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 18000
    print(f'origin ready on 127.0.0.1:{port} payload_sha={PAYLOAD_SHA}', flush=True)
    ThreadingHTTPServer(('127.0.0.1', port), Handler).serve_forever()
