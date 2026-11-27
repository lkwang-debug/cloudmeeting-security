#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""门禁检查 fixture 用的本地 mock 服务器（vuln/fixed 两种模式）。"""
import html
import json
import time
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

MODE = {"value": "vuln"}
IDOR_PATHS = {"/basis/v1/userInfo/queryUserPage", "/serv/v1/role/list",
              "/basis/v1/departInfo/queryDepartTree", "/serv/v1/terminal/page",
              "/serv/v1/user/list", "/serv/v1/recording/paastask", "/serv/v1/conf/list"}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, ctype="application/json"):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _token(self):
        return self.headers.get("token", "")

    def do_GET(self):
        u = urlparse(self.path)
        qs = parse_qs(u.query)
        if u.path == "/":
            return self._send(200, "<html>hello</html>", "text/html")
        if u.path == "/ui/login":
            return self._send(200, "<html>验证码 captcha</html>", "text/html")
        if u.path == "/search":
            q = " ".join(sum(qs.values(), []))
            if MODE["value"] == "vuln":
                return self._send(200, "<html>result: " + q + "</html>", "text/html")
            return self._send(200, "<html>result: " + html.escape(q) + "</html>", "text/html")
        if u.path == "/download":
            val = " ".join(sum(qs.values(), []))
            if MODE["value"] == "vuln" and "passwd" in val:
                return self._send(200, "root:x:0:0:root:/root:/bin/bash\n", "text/plain")
            return self._send(404, "not found", "text/plain")
        if u.path == "/fmapi/webservice/jaxws":
            if MODE["value"] == "vuln":
                return self._send(200, "<definitions><operation>getUserinfoList</operation></definitions>", "text/xml")
            return self._send(404, "not found", "text/plain")
        if u.path == "/meeting-resource-server/api/users/myself":
            if MODE["value"] == "vuln":
                return self._send(200, json.dumps({"userInfo": {"userId": 1, "password":
                                                                "A7A28E60FE5AE52A9A0A7BDB6B04C53A"}}))
            return self._send(200, json.dumps({"userInfo": {"userId": 1, "password": ""}}))
        if u.path == "/meeting-resource-server/security/company/users":
            return self._send(200, json.dumps({"resCode": 1, "result": {"items": []}}))
        if u.path == "/meeting/v1/roominfo/default":
            data = {}
            return self._send(200, json.dumps({"code": "0", "data": data}))
        if u.path in IDOR_PATHS:
            tok = self._token()
            if MODE["value"] == "vuln" or tok == "admin-token":
                return self._send(200, json.dumps({"code": "0", "data": {"records": [{"id": 1}]}}))
            return self._send(200, json.dumps({"code": "1003", "msg": "denied"}))
        return self._send(404, "not found", "text/plain")

    def do_POST(self):
        u = urlparse(self.path)
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        text = raw.decode("utf-8", "replace")
        if u.path in ("/login", "/auth/v1/login"):
            if MODE["value"] == "vuln" and ";sleep 3" in text:
                time.sleep(3.4)
            if MODE["value"] == "vuln":
                return self._send(200, json.dumps({"code": "0", "msg": "ok"}))
            return self._send(200, json.dumps({"code": "10000", "msg": "bad password"}))
        if u.path == "/meeting/v1/roominfo/page":
            return self._send(200, json.dumps({"code": "0", "data": {"records": [{"roomName": "r"}]}}))
        if u.path == "/meeting-resource-server/oauth2/token":
            if "grant_type=refresh_token" in text or "refresh_token" in text:
                if MODE["value"] == "vuln":
                    return self._send(200, json.dumps({"access_token": "admin-token", "expires_in": 3600}))
                return self._send(400, json.dumps({"error": "invalid_grant"}))
            return self._send(200, json.dumps({"access_token": "user-token", "expires_in": 3600}))
        if u.path == "/fmapi/webservice/jaxws":
            if MODE["value"] == "vuln":
                return self._send(200, "<getUserinfoListResult><username>admin</username></getUserinfoListResult>", "text/xml")
            return self._send(500, "<fault>error</fault>", "text/xml")
        if u.path.startswith(("/basis/v1/userInfo/importUser", "/serv/v1/recording/img/upload",
                              "/serv/v1/terminal/import", "/serv/v1/terminal/log/upload")):
            if MODE["value"] == "vuln":
                return self._send(200, json.dumps({"code": "0", "msg": "SUCCESS", "data": {"url": "/upload/x.php"}}))
            return self._send(200, json.dumps({"code": "2213", "msg": "template mismatch"}))
        if u.path in IDOR_PATHS:
            tok = self._token()
            if MODE["value"] == "vuln" or tok == "admin-token":
                return self._send(200, json.dumps({"code": "0", "data": {"records": [{"id": 1}]}}))
            return self._send(200, json.dumps({"code": "1003", "msg": "denied"}))
        return self._send(404, "not found", "text/plain")


def start_server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, "http://127.0.0.1:%d" % srv.server_address[1]
