import socket
from OpenSSL import SSL
from OpenSSL._util import lib

DTLSv1_METHOD = 7
DTLSv12_METHOD = 8

SSL.Context._methods[DTLSv1_METHOD] = lib.DTLSv1_client_method
SSL.Context._methods[DTLSv12_METHOD] = lib.DTLS_client_method

ctx = SSL.Context(DTLSv12_METHOD)

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(('172.22.134.1', 4567))

con = SSL.Connection(ctx, s)
con.set_connect_state()
con.connect(('172.22.134.1', 4567))
con.do_handshake()

print('Cipher:', con.get_cipher_name(), 'Protocol:', con.get_protocol_version_name())