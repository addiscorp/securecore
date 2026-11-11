# Test fixture for test/ext-microvm.sh (addiscorp/securecore#71): a unix socket that answers each
# connection with the credentials the kernel gives for its peer (SO_PEERCRED), then closes. The
# guest reaches it through a connect[].socket forward, so the answer is who the host sees on the
# guest's connections: the jailed Firecracker's uid, never root's.
#   python3 -I peercred.py <socket path>
import os
import socket
import struct
import sys

path = sys.argv[1]
try:
    os.unlink(path)
except FileNotFoundError:
    pass
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(path)
os.chmod(path, 0o777)
s.listen(16)
while True:
    c, _ = s.accept()
    pid, uid, gid = struct.unpack("3i", c.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
    c.sendall(f"uid={uid} gid={gid}\n".encode())
    c.close()
