"""只接受连接、永不回包的监听，用来触发隧道侧的首字节超时重试。"""
import socket

s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', 18001))
s.listen(32)
print('silent listener ready on 127.0.0.1:18001', flush=True)
held = []
while True:
    c, _ = s.accept()
    held.append(c)
