import threading
import asyncio
import time
import socket



s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
s.sendto(b'abc', ('127.0.0.1', 9999))

for i in range(10):
    try:
        s.recv(1023)
    except BaseException as e:
        print('timeout')
    print(i)
print(s.gettimeout())