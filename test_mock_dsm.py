#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
스캐너 테스트용 로컬 가짜 DSM 서버.
실제 DSM처럼 /webman/ping.cgi, /webman/global.js, /webman/index.cgi,
/webapi/query.cgi, /webapi/auth.cgi(POST), /webapi/entry.cgi 에 응답한다.
오직 127.0.0.1에서만 리슨하며, 스캐너 탐지 로직 검증에만 쓴다.

사용: python test_mock_dsm.py [port] [version] [build] [update]
예:   python test_mock_dsm.py 5000 7.2.2 72806 3
"""
import json
import re
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
VERSION = sys.argv[2] if len(sys.argv) > 2 else "7.2.2"
BUILD = sys.argv[3] if len(sys.argv) > 3 else "72806"
UPDATE = sys.argv[4] if len(sys.argv) > 4 else "3"

API_INFO = {
    "success": True,
    "data": {
        "SYNO.API.Auth": {"path": "auth.cgi", "minVersion": 1, "maxVersion": 7},
        "SYNO.Core.System.Info": {"path": "entry.cgi", "minVersion": 1, "maxVersion": 1},
        "SYNO.Core.Package.Server": {"path": "entry.cgi", "minVersion": 1, "maxVersion": 3},
        "SYNO.Photo": {"path": "entry.cgi", "minVersion": 1, "maxVersion": 5},
        "SYNO.SurveillanceStation.AudioStream": {"path": "entry.cgi", "minVersion": 1, "maxVersion": 2},
    },
}

GLOBAL_JS = f"""
var SYNO = {{}};
SYNO.SDS = SYNO.SDS || {{}};
SYNO.SDS.Version = "{VERSION}";
SYNO.SDS.BuildNumber = "{BUILD}";
SYNO.SDS.ProductType = "DSM";
"""

LOGIN_HTML = f"""<!DOCTYPE html>
<html><head><title>Synology DiskStation</title></head>
<body class="login">
<script>var SYNO = {{}}; SYNO.SDS = {{}}; SYNO.SDS.Version = "{VERSION}";</script>
<script src="webman/login/js/common.js?v={BUILD}"></script>
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # 조용히
        pass

    def _send(self, code, body, ctype="text/html; charset=utf-8"):
        raw = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        p = urllib.parse.urlparse(self.path)
        path = p.path
        if path == "/webman/ping.cgi":
            self._send(200, "pong", "text/plain")
        elif path == "/webman/global.js":
            self._send(200, GLOBAL_JS, "application/javascript")
        elif path == "/webman/index.cgi":
            self._send(200, LOGIN_HTML)
        elif path == "/webapi/query.cgi":
            self._send(200, json.dumps(API_INFO), "application/json")
        elif path == "/webapi/entry.cgi":
            q = urllib.parse.parse_qs(p.query)
            api = q.get("api", [""])[0]
            if api == "SYNO.Core.System.Info" and "_sid" in q:
                ver = f"{VERSION} ({BUILD} Update {UPDATE})"
                self._send(200, json.dumps({"success": True, "data": {"version": ver}}),
                           "application/json")
            elif api == "SYNO.Core.Package.Server" and "_sid" in q:
                pkgs = [
                    {"id": "SynologyPhotos", "name": "Synology Photos", "version": "1.7.0-07152"},
                    {"id": "SurveillanceStation", "name": "Surveillance Station", "version": "9.2.0-11289"},
                ]
                self._send(200, json.dumps({"success": True, "data": pkgs}), "application/json")
            else:
                self._send(200, json.dumps({"success": False}), "application/json")
        else:
            self._send(404, "not found")

    def do_POST(self):
        p = urllib.parse.urlparse(self.path)
        length = int(self.headers.get("Content-Length", 0))
        params = urllib.parse.parse_qs(self.rfile.read(length).decode())
        if p.path == "/webapi/auth.cgi":
            if params.get("account", [""])[0] == "admin" and params.get("passwd", [""])[0] == "test1234":
                self._send(200, json.dumps({"success": True, "data": {"sid": "MOCKSID123"}}),
                           "application/json")
            else:
                self._send(200, json.dumps({"success": False}), "application/json")
        else:
            self._send(404, "not found")


if __name__ == "__main__":
    srv = HTTPServer(("127.0.0.1", PORT), Handler)
    print(f"mock DSM on http://127.0.0.1:{PORT}  (DSM {VERSION} build {BUILD} update {UPDATE})")
    srv.serve_forever()
