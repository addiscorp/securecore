#!/usr/bin/env python3
"""The three unix-socket helpers test/ext-microvm.sh needs, so the test doesn't depend on socat.

  sock.py listen PATH      a stream socket at PATH (mode 0777) that accepts and closes, forever
  sock.py recv PATH OUT    a datagram socket at PATH; every datagram is appended to OUT
  sock.py connect PATH     stdin to the stream socket at PATH and its replies to stdout; after
                           stdin ends, waits up to 5 s for more replies (socat -t 5)
"""
import os
import selectors
import socket
import sys


def listen(path: str) -> None:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(path)
    os.chmod(path, 0o777)
    s.listen(16)
    while True:
        c, _ = s.accept()
        c.close()


def recv(path: str, out: str) -> None:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    s.bind(path)
    while True:
        data = s.recv(65536)
        with open(out, "ab") as f:
            f.write(data)


def connect(path: str) -> None:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(path)
    sel = selectors.DefaultSelector()
    sel.register(s, selectors.EVENT_READ)
    sel.register(sys.stdin.buffer, selectors.EVENT_READ)
    stdin_open = True
    while True:
        events = sel.select(timeout=None if stdin_open else 5)
        if not events:
            return
        for key, _ in events:
            if key.fileobj is s:
                data = s.recv(65536)
                if not data:
                    return
                sys.stdout.buffer.write(data)
                sys.stdout.buffer.flush()
            else:
                data = os.read(sys.stdin.fileno(), 65536)
                if data:
                    s.sendall(data)
                else:
                    stdin_open = False
                    sel.unregister(sys.stdin.buffer)


if __name__ == "__main__":
    mode, args = sys.argv[1], sys.argv[2:]
    {"listen": listen, "recv": recv, "connect": connect}[mode](*args)
