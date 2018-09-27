'''
Created on 2018-09-11 16:11

@author: qichengyue
'''
import asyncio
import time
import socket

import logging
logging.basicConfig(level=logging.INFO)

bstr = b'''GET / HTTP/1.1\r\nHost:172.22.134.1\r\nKeep-Alive:300\r\nConnection:Keep-Alive\r\n\r\n'''
'''
async def f():
    reader, writer = await asyncio.open_connection('172.22.134.1', 80)
    for i in range(1, 1000000):
        writer.write(str)
        await writer.drain()
        time.sleep(0.05)
        await reader.read(1024)
        logging.info('round:%s' %i)
        
loop = asyncio.get_event_loop()
loop.run_until_complete(f())
'''


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 655360)
s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 655360)

s.connect(('172.22.134.1', 80))

for i in range(1,100000):
    try:
        s.send(bstr)
        time.sleep(0.02)
        s.recv(1024)
    except ConnectionAbortedError as e:
        logging.error('ERROR: ConnectionAbortedError: %s, trying to reconnect...' % e)
        # s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # s.connect(('172.22.134.1', 80))
        break
    except BaseException as e:
        logging.error('ERROR: %s' %e)
        break
    
    logging.info('round:%s' %i)
    
s.close()
