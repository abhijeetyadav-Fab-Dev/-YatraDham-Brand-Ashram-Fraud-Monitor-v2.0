#!/usr/bin/env python3
"""
Quick Launcher for YatraDham Brand & Ashram Fraud Monitor.
Starts the FastAPI backend and automatically opens the dashboard in the default browser.
"""
import os
import sys
import time
import webbrowser
import threading

# Reconfigure stdout for UTF-8 on Windows
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import socket

def find_available_port(start_port: int = 8090, max_attempts: int = 20) -> int:
    for p in range(start_port, start_port + max_attempts):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(("127.0.0.1", p)) != 0:
                return p
    return start_port

def open_browser(port: int):
    time.sleep(1.2)
    url = f"http://127.0.0.1:{port}"
    print(f"\n[Browser] Opening live dashboard at {url} ...\n")
    try:
        webbrowser.open(url)
    except Exception as e:
        print(f"[Browser] Could not auto-launch browser: {e}")

if __name__ == "__main__":
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    
    debug_mode = "--debug" in sys.argv or os.environ.get("DEBUG", "false").lower() in ("true", "1", "yes")
    if debug_mode:
        os.environ["DEBUG"] = "true"

    requested_port = int(os.environ.get("PORT", 8090))
    port = find_available_port(requested_port)
    if port != requested_port:
        print(f"⚠️ Port {requested_port} is busy. Switched to free port {port}.")

    print("=" * 68)
    print(" 🛡️  YATRADHAM BRAND & ASHRAM FRAUD MONITOR — LIVE APP")
    print("     Initiative from YatraDham.Org")
    print("=" * 68)
    print(f" 📡 REST API:         http://127.0.0.1:{port}/api/health")
    print(f" 📖 Interactive Docs: http://127.0.0.1:{port}/docs")
    print(f" 🖥️  Live Dashboard:   http://127.0.0.1:{port}/")
    print(f" 🐞 Debug Mode:       {'ENABLED' if debug_mode else 'DISABLED'}")
    print("=" * 68)
    print(f" Starting Uvicorn ASGI server on port {port} ...\n")

    threading.Thread(target=open_browser, args=(port,), daemon=True).start()
    
    import uvicorn
    uvicorn.run("server:app", host="127.0.0.1", port=port, reload=debug_mode, log_level="debug" if debug_mode else "info")
