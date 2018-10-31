'''
Created on 2018-09-10 13:39

@author: qichengyue
'''
import socket
import sys 
from multiprocessing import Pool
import psutil

port = 9000  # by default, listening port start from 9000

if len(sys.argv) > 1:
    port = sys.argv[1]


def server_process(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    s.bind(('0.0.0.0', int(port)))
    
    print('UDP server started, bind on port:%s' % port)
    
    while True:
        data, addr = s.recvfrom(1500)
        s.sendto(data, addr)


if __name__ == '__main__':
    n = psutil.cpu_count()
    # will start n processes
    if n < 4:
        n = 4
    
    pool = Pool(n)
    for i in range(n):
        pool.apply_async(server_process, args=(port+i,))
    
    pool.close()
    pool.join()
