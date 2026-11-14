"""Tiny test server: sends a fake SSH-style banner, then closes. Localhost only."""
import socket
import sys

port = int(sys.argv[1])
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port))
srv.listen(16)
while True:
    conn, _ = srv.accept()
    try:
        conn.sendall(b"SSH-2.0-TestBanner_1.0\r\n")
    finally:
        conn.close()
