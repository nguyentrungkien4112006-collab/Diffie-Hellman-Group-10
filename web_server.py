#!/usr/bin/env python3
"""
Web Server (Python HTTP + REST API) phục vụ Giao diện GUI Web (HTML/CSS/JS) cho đề tài:
Trao đổi khoá Diffie–Hellman (Nhóm 10 - An toàn và bảo mật thông tin).

Đặc điểm:
- Sử dụng thư viện chuẩn `http.server` của Python (không cần cài thêm Flask/FastAPI bên ngoài).
- Tách bạch hoàn toàn phần thuật toán lõi Python (`core/*`) và phần giao diện (`web_ui/index.html`).
- Tự động mở trình duyệt/màn hình GUI khi chạy `python3 web_server.py` (trừ khi truyền `--no-browser`).
"""

import json
import os
import sys
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

from core import (
    encrypt_decrypt_text_demo,
    run_full_dh_exchange,
    run_tiny_dh_exchange,
    simulate_mitm_attack,
    simulate_mitm_defense_authenticated_dh,
)
from tests.test_and_benchmark import run_all_tests, run_benchmarks

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UI_FILE = os.path.join(BASE_DIR, "web_ui", "index.html")


class DHRequestHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args) -> None:
        # Giữ log gọn gàng trên màn hình console
        sys.stderr.write(f"[Python-GUI-API] {self.address_string()} - {fmt % args}\n")

    def _send_json(self, payload: dict, status: int = 200) -> None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_OPTIONS(self) -> None:
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path in ("/", "/index.html"):
            with open(UI_FILE, "rb") as f:
                content = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
        elif parsed.path == "/api/tests":
            self._send_json(run_all_tests())
        elif parsed.path == "/api/benchmark":
            self._send_json(run_benchmarks())
        else:
            self._send_json({"error": "Endpoint không tồn tại"}, status=404)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        length = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(length).decode("utf-8")) if length > 0 else {}

        try:
            if parsed.path == "/api/tiny-dh":
                p = int(body.get("p", 353))
                g = int(body.get("g", 3))
                a = int(body.get("a", 97))
                b = int(body.get("b", 233))
                msg = str(body.get("message", "Xin chào Nhóm 10 - An toàn bảo mật thông tin!"))
                res = run_tiny_dh_exchange(p=p, g=g, a=a, b=b)
                res["cipher_demo"] = encrypt_decrypt_text_demo(
                    msg, res["alice"]["shared_secret_KA"], res["bob"]["shared_secret_KB"]
                )
                self._send_json(res)
            elif parsed.path == "/api/full-dh":
                mode = body.get("mode", "rfc3526_2048")
                bits = int(body.get("bits", 512))
                res = run_full_dh_exchange(mode=mode, custom_bits=bits)
                self._send_json(res)
            elif parsed.path == "/api/mitm":
                p = int(body.get("p", 353))
                g = int(body.get("g", 3))
                a = int(body.get("a", 97))
                b = int(body.get("b", 233))
                e1 = int(body.get("e1", 45))
                e2 = int(body.get("e2", 112))
                alice_msg = str(body.get("alice_msg", "Chuyển 50.000.000 VNĐ cho Bob (STK: 1903889911)"))
                eve_msg = str(body.get("eve_msg", "Chuyển 50.000.000 VNĐ cho Eve (STK: 9999666688)"))
                attack = simulate_mitm_attack(p, g, a, b, e1, e2, alice_msg, eve_msg)
                defense = simulate_mitm_defense_authenticated_dh(p, g, a, b, e1)
                self._send_json({"attack": attack, "defense": defense})
            else:
                self._send_json({"error": "Endpoint không tồn tại"}, status=404)
        except Exception as exc:
            self._send_json({"error": str(exc)}, status=400)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    url = f"http://127.0.0.1:{port}"
    server = HTTPServer(("0.0.0.0", port), DHRequestHandler)
    print(f"Server GUI Diffie-Hellman (Nhóm 10) đang chạy tại: {url}")
    if "--no-browser" not in sys.argv:
        threading.Thread(
            target=lambda: (time.sleep(0.4), webbrowser.open(url, new=1)),
            daemon=True,
        ).start()
    server.serve_forever()
