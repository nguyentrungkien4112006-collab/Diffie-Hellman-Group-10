#!/usr/bin/env python3
"""
Khởi chạy màn hình GUI Web tự động cho đề tài:
Trao đổi khoá Diffie–Hellman (Nhóm 10 - An toàn và bảo mật thông tin).

Khi chạy `python3 run_gui.py`:
1. Tự động khởi động Python Backend Server (`web_server.py`) ở chế độ nền trên cổng trống.
2. Tự động bật cửa sổ GUI như một ứng dụng độc lập (App Window Mode trên Chrome/Edge/Brave
   với cờ `--app=http://127.0.0.1:<port>`, hoặc mở tab trình duyệt mặc định nếu không có).
3. Nếu máy có sẵn Tkinter, hiển thị thêm một hộp điều khiển nhỏ gọn để bật lại cửa sổ GUI,
   xem trạng thái kết nối API Python, hoặc thoát server bất cứ lúc nào.
"""

import os
import shutil
import socket
import subprocess
import sys
import threading
import time
import webbrowser
from http.server import HTTPServer

from web_server import DHRequestHandler


def find_free_port(preferred: int = 8080) -> int:
    """Tìm cổng trống trên localhost (ưu tiên 8080)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        if s.connect_ex(("127.0.0.1", preferred)) != 0:
            return preferred
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def open_as_web_gui_window(url: str) -> None:
    """
    Ưu tiên mở URL dưới dạng cửa sổ GUI độc lập (App Mode - không có thanh địa chỉ/tab rườm rà)
    bằng Chrome / Microsoft Edge / Chromium, nếu không tìm thấy thì dùng webbrowser mặc định.
    """
    candidates = []
    if sys.platform.startswith("win"):
        program_files = [
            os.environ.get("PROGRAMFILES", r"C:\Program Files"),
            os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)"),
            os.environ.get("LOCALAPPDATA", ""),
        ]
        for base in program_files:
            if not base:
                continue
            candidates.extend([
                os.path.join(base, "Google", "Chrome", "Application", "chrome.exe"),
                os.path.join(base, "Microsoft", "Edge", "Application", "msedge.exe"),
                os.path.join(base, "BraveSoftware", "Brave-Browser", "Application", "brave.exe"),
            ])
    elif sys.platform == "darwin":
        candidates.extend([
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
            "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
        ])
    else:
        for cmd in ("google-chrome", "chromium", "chromium-browser", "microsoft-edge", "brave-browser"):
            found = shutil.which(cmd)
            if found:
                candidates.append(found)

    for exe in candidates:
        if exe and os.path.exists(exe):
            try:
                subprocess.Popen(
                    [exe, f"--app={url}", "--window-size=1360,860"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                return
            except Exception:
                pass

    webbrowser.open(url, new=1)


def main() -> None:
    port = find_free_port(8080)
    url = f"http://127.0.0.1:{port}"
    server = HTTPServer(("127.0.0.1", port), DHRequestHandler)

    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    print("=" * 76)
    print("  ĐÃ KHỞI ĐỘNG MÀN HÌNH GUI WEB: DIFFIE–HELLMAN (NHÓM 10 - TMDT CLC C)")
    print(f"  Địa chỉ GUI trực tiếp: {url}")
    print("  Đang tự động bật cửa sổ giao diện GUI...")
    print("=" * 76)

    time.sleep(0.4)
    open_as_web_gui_window(url)

    # Thử mở bảng điều khiển Tkinter nhỏ gọn nếu môi trường có GUI desktop
    try:
        import tkinter as tk

        root = tk.Tk()
        root.title("Nhóm 10 - Bộ khởi chạy GUI Diffie–Hellman")
        root.geometry("440x230")
        root.configure(bg="#0f172a")
        root.resizable(False, False)

        lbl_title = tk.Label(
            root,
            text="Hệ Trao đổi Khoá Diffie–Hellman (Nhóm 10)",
            fg="#f8fafc",
            bg="#0f172a",
            font=("Arial", 12, "bold"),
        )
        lbl_title.pack(pady=(16, 4))

        lbl_sub = tk.Label(
            root,
            text=f"Server Python đang chạy tại: {url}\nCửa sổ GUI Web đã được bật tự động.",
            fg="#94a3b8",
            bg="#0f172a",
            font=("Arial", 10),
        )
        lbl_sub.pack(pady=(0, 14))

        btn_open = tk.Button(
            root,
            text="Mở lại màn hình GUI Web",
            command=lambda: open_as_web_gui_window(url),
            bg="#2563eb",
            fg="#ffffff",
            font=("Arial", 10, "bold"),
            padx=14,
            pady=6,
            relief="flat",
        )
        btn_open.pack(pady=4)

        btn_quit = tk.Button(
            root,
            text="Đóng Server & Thoát",
            command=root.destroy,
            bg="#334155",
            fg="#e2e8f0",
            font=("Arial", 9),
            padx=12,
            pady=4,
            relief="flat",
        )
        btn_quit.pack(pady=6)

        root.mainloop()
        server.shutdown()
    except Exception:
        print("Nhấn Ctrl+C tại cửa sổ dòng lệnh này khi muốn tắt GUI Server.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nĐã tắt GUI Server.")
            server.shutdown()


if __name__ == "__main__":
    main()
