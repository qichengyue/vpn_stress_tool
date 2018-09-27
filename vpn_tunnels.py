import asyncio, aiohttp
from config import VIRTUAL_SITE_IP, BACKEND_IP, VIRTUAL_USERS, PAYLOAD_PACKET_SIZE,\
    PAYLOAD_TYPE, PAYLOAD_SRC_PORT, PAYLOAD_DST_PORT
import ssl
import struct
from utils import generate_icmp_pkt, generate_udp_pkt
import socket
import time
import requests, urllib3


urllib3.disable_warnings()
login_url = 'https://%s/prx/000/http/localhost/login' % VIRTUAL_SITE_IP
logout_url = 'https://%s/prx/000/http/localhost/logout' % VIRTUAL_SITE_IP
d = dict()
d['method'] = 'default_method_localdb'
d['uname'] = 't'
d['pwd'] = 't'
d['pwd1'] = ''
d['pwd2'] = ''


async def vpn_session():
    # Post login part

    # To accept cookie with IP address(By default only cookie with FQDN are legal)
    jar = aiohttp.CookieJar(unsafe=True)
    async with aiohttp.ClientSession(cookie_jar=jar) as session:
        async with session.post(login_url, ssl=False, data=d) as response:
            # Get cookie value of key 'ANsession5450706721064400' and 'AN_nav1'
            cookie_ANsession = ''
            cookie_AN_nav1 = ''
            for c in session.cookie_jar:
                if c.key == 'ANsession5450706721064400':
                    cookie_ANsession = c.value
                if c.key == 'AN_nav1':
                    cookie_AN_nav1 = c.value

            cookie = 'AN_nav1=' + cookie_AN_nav1 + ';ANsession5450706721064400=' + cookie_ANsession \
                     + ';ANStandalone=true'

            cookie = cookie.encode('utf-8')

    await asyncio.sleep(3)
    
    # create vpn tunnel
    ssl_ctx = ssl._create_unverified_context()
    reader, writer = await asyncio.open_connection(VIRTUAL_SITE_IP, 443, ssl=ssl_ctx)
    writer.write(b'Get /vpntunnel HTTP/1.1\r\nHost: %s\r\nCookie: %s\r\nappid: SSPVPN\r\nclientid: \
                d561652d-400b-4bfd-a4e4-7cfa8ce4d246\r\ncpuid: \r\nhostname: 5CD539976\r\n\r\n'
                 % (VIRTUAL_SITE_IP.encode(encoding='utf_8'), cookie))
    await writer.drain()

    # CLIENT_COMMONCONFIG_REQUEST
    client_common_config_request = bytearray(16)
    client_common_config_request[0] = 0x50  # CLIENT_COMMONCONFIG_REQUEST = 0x50
    writer.write(bytes(client_common_config_request))
    await writer.drain()
    server_common_config_response = await reader.read(1024)
    # extract common config from server response
    vpn_tundata = server_common_config_response[0:16]
    vpn_common_config = server_common_config_response[16:68]
    vcc_netpool_flags = vpn_common_config[4:8]
    
    # CLIENT_NETCONFIG_REQUEST
    client_net_config_request = bytearray(48)
    client_net_config_request[0] = 0x54  # CLIENT_NETCONFIG_REQUEST = 0x54
    client_net_config_request[12:16] = struct.pack('<L', 32)
    writer.write(bytes(client_net_config_request))
    await writer.drain()
    server_net_config_response = await reader.read(1024)
    # vnc_clientip = server_net_config_response[16:52][16:20]
    vnc_clientip = server_net_config_response[32:36]
    
    # Generate payload packet and send
    pkt = list()
    if PAYLOAD_TYPE == 'ICMP':
        pkt = generate_icmp_pkt(PAYLOAD_PACKET_SIZE, vnc_clientip, socket.inet_aton(BACKEND_IP))
    elif PAYLOAD_TYPE == 'UDP':
        pkt = generate_udp_pkt(PAYLOAD_PACKET_SIZE, vnc_clientip, socket.inet_aton(BACKEND_IP),
                               PAYLOAD_SRC_PORT, PAYLOAD_DST_PORT)
    
    for i in range(1000):
        writer.write(bytes(pkt))
        await writer.drain()
        # await reader.read(1500)
    
    # logout session
    time.sleep(3)
    requests.get(logout_url, verify=False, headers={'Cookie': cookie})


loop = asyncio.get_event_loop()
tasks = [vpn_session() for i in range(VIRTUAL_USERS)]
loop.run_until_complete(asyncio.wait(tasks))
