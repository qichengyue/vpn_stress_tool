import socket
import threading

from OpenSSL import SSL
from OpenSSL._util import lib
import os

DTLSv1_METHOD = 7
DTLSv12_METHOD = 8
host = '192.168.199.200'

SSL.Context._methods[DTLSv1_METHOD] = lib.DTLSv1_client_method
SSL.Context._methods[DTLSv12_METHOD] = lib.DTLS_client_method

ctx = SSL.Context(DTLSv12_METHOD)


def dtls_proxy(target_ip, target_port, listen_ip, listen_port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind((listen_ip, listen_port))

    data, dtls_client_addr = server_socket.recvfrom(1500)
    server_socket.sendto(data, (target_ip, target_port))

    while True:
        data, addr = server_socket.recvfrom(1500)
        if addr[0] == target_ip:
            # The packet is from VPN server side, sendto VPN client side
            server_socket.sendto(data, dtls_client_addr)
        else:
            # The packet is from VPN client side, send to VPN server side
            server_socket.sendto(data, (target_ip, target_port))


dtls_proxy_thread = threading.Thread(target=dtls_proxy, args=(host, 4567, '0.0.0.0', 8888))
dtls_proxy_thread.start()

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

con = SSL.Connection(ctx, s)
con.connect(('localhost', 8888))
con.do_handshake()
con.send(b'abc')

print('Socket FD: %s' % s.fileno())
print('Cipher:', con.get_cipher_name(), 'Protocol:', con.get_protocol_version_name())
