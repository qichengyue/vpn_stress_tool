import socket
from OpenSSL import SSL
from OpenSSL._util import lib

DTLSv1_METHOD = 7
DTLSv12_METHOD = 8
host = '192.168.199.200'

SSL.Context._methods[DTLSv1_METHOD] = lib.DTLSv1_client_method
SSL.Context._methods[DTLSv12_METHOD] = lib.DTLS_client_method

ctx = SSL.Context(DTLSv12_METHOD)


class vpn_dtls_socket(socket.socket):
    def __init__(self, family=-1, type=-1, proto=-1, fileno=None):
        super(vpn_dtls_socket, self).__init__(family, type, proto, fileno)
        self.coreid = 0

    def set_coreid(self, coreid):
        self.coreid = coreid

    def sendto(self, data, flags=None, *args, **kwargs):
        print('sendto invoked')
        tmp_data = b'\x03' + data
        super().sendto(b'abc', flags, *args, **kwargs)


s = vpn_dtls_socket(socket.AF_INET, socket.SOCK_DGRAM)

con = SSL.Connection(ctx, s)
con.connect((host, 4567))
con.do_handshake()
con.send(b'abc')

print('Cipher:', con.get_cipher_name(), 'Protocol:', con.get_protocol_version_name())
print('Receive:%s' %con.read(1024))