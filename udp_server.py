'''
Created on 2018-09-10 13:39

@author: qichengyue
'''
import socket
import sys 

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
port = 9999 # by default, listening on port 9999

if len(sys.argv) > 1:
    port = sys.argv[1]

s.bind(('0.0.0.0', int(port)))

print('UDP server started, bind on port:%s' %port)

while True:
    data, addr = s.recvfrom(1500)
    s.sendto(data, addr)