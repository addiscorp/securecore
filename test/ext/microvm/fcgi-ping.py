#!/usr/bin/env python3
"""php-fpm's ping over FastCGI, for test/ext-microvm.sh (#101: one microVM per pool, each where
its pool listens): prints the response's body ("pong") or the error, exit 0 only on "pong".

  fcgi-ping.py unix:<path> | <host>:<port>
"""
import socket
import struct
import sys


def record(kind: int, content: bytes) -> bytes:
    return struct.pack(">BBHHBx", 1, kind, 1, len(content), 0) + content


def params(pairs: dict) -> bytes:
    out = b""
    for k, v in pairs.items():
        k, v = k.encode(), v.encode()
        out += bytes([len(k)]) + bytes([len(v)]) + k + v
    return out


def main() -> int:
    where = sys.argv[1]
    if where.startswith("unix:"):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        addr = where[5:]
    else:
        host, port = where.rsplit(":", 1)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        addr = (host, int(port))
    s.settimeout(10)
    s.connect(addr)
    p = params({"SCRIPT_NAME": "/fpm-ping", "SCRIPT_FILENAME": "/fpm-ping", "REQUEST_METHOD": "GET", "SERVER_PROTOCOL": "HTTP/1.1"})
    s.sendall(record(1, struct.pack(">HB5x", 1, 0)) + record(4, p) + record(4, b"") + record(5, b""))
    data = b""
    while True:
        chunk = s.recv(65536)
        if not chunk:
            break
        data += chunk
    body = b""
    i = 0
    while i + 8 <= len(data):
        _, kind, _, n, pad = struct.unpack(">BBHHB", data[i : i + 7])
        if kind == 6:
            body += data[i + 8 : i + 8 + n]
        i += 8 + n + pad
    text = body.split(b"\r\n\r\n", 1)[-1].decode(errors="replace").strip()
    print(text)
    return 0 if text == "pong" else 1


if __name__ == "__main__":
    sys.exit(main())
