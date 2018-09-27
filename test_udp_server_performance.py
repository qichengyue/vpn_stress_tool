'''
Created on 2018-09-12 10:15

@author: qichengyue
'''

import socket
import logging

logging.basicConfig(level=logging.INFO)

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
for i in range(1, 20000):
    s.sendto(('qicyikjkljkljkljkljkljkljkljadfklajdfkljafkljl%s' % i).encode(encoding='utf-8'), ('172.22.134.3', 9999))
    logging.info('round:%s ' % i)

print('Test done')
s.close()
