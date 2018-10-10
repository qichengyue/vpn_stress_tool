import asyncio, aiohttp
from config import VIRTUAL_SITE_IP, BACKEND_IP, VIRTUAL_USERS, PAYLOAD_PACKET_SIZE,\
    PAYLOAD_TYPE, PAYLOAD_SRC_PORT, PAYLOAD_DST_PORT, LOGGING_LEVEL,\
    TRAFFIC_LOAD_PER_TUNNEL, DURATION
import ssl
import struct
from utils import generate_icmp_pkt, generate_udp_pkt
import socket
import time
import requests, urllib3
import logging
import uuid
import psutil
from multiprocessing import Pool, Manager

logging.basicConfig(level=LOGGING_LEVEL, filename='vpn.log', filemode='w')


urllib3.disable_warnings()
login_url = 'https://%s/prx/000/http/localhost/login' % VIRTUAL_SITE_IP
logout_url = 'https://%s/prx/000/http/localhost/logout' % VIRTUAL_SITE_IP
d = dict()
d['method'] = ''
d['uname'] = 't'
d['pwd'] = 't'
d['pwd1'] = ''
d['pwd2'] = ''


async def vpn_session(virtual_hostname, statistics):
    # Post login part
    jar = aiohttp.CookieJar(unsafe=True)    # To accept cookie with IP address(By default only cookie with FQDN are legal)
    async with aiohttp.ClientSession(cookie_jar=jar) as session:
        # extract authenticate method(by default is 'default_method_localdb')
        async with session.get(login_url, ssl=False) as response:
            res_str = await response.text(encoding='utf-8')
            res_str = res_str[res_str.index('"name"') + 9 : len(res_str)]
            d['method'] = res_str[0: res_str.index(',')-1]
            
        # Post login part
        async with session.post(login_url, ssl=False, data=d) as response:
            # Get cookie value of key 'ANsession0005012650613566' and 'AN_nav1'
            cookie_ANsession = ''
            cookie_AN_nav1 = ''
            cookie_ANsession_flag = ''  # Get cookie key of value vpn, the cookie is like "Cookie: ANsession0005012650613566=vpn", for different AG the key part "ANsession0005012650613566" is different
            for c in session.cookie_jar:
                if c.key[0:9] == 'ANsession':
                    cookie_ANsession = c.value
                    cookie_ANsession_flag = c.key
                if c.key == 'AN_nav1':
                    cookie_AN_nav1 = c.value

            cookie = 'AN_nav1=' + cookie_AN_nav1 + ';' + cookie_ANsession_flag + '=' + cookie_ANsession \
                     + ';ANStandalone=true'

            cookie = cookie.encode('utf-8')

    await asyncio.sleep(3)
    
    # create vpn tunnel
    ssl_ctx = ssl._create_unverified_context()
    reader, writer = await asyncio.open_connection(VIRTUAL_SITE_IP, 443, ssl=ssl_ctx)
    writer.write(b'Get /vpntunnel HTTP/1.1\r\nHost: %s\r\nCookie: %s\r\nappid: SSPVPN\r\nclientid: \
                %s\r\ncpuid: \r\nhostname: %s\r\n\r\n'
                 % (VIRTUAL_SITE_IP.encode(encoding='utf-8'), cookie, str(uuid.uuid1()).encode(encoding='utf-8'), virtual_hostname.encode(encoding='utf-8')) )
    await writer.drain()
    await reader.read(1024)

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
    str_clientip = socket.inet_ntoa(vnc_clientip)
    
    # Generate payload packet and send
    pkt = list()
    if PAYLOAD_TYPE == 'ICMP':
        pkt = generate_icmp_pkt(PAYLOAD_PACKET_SIZE, vnc_clientip, socket.inet_aton(BACKEND_IP))
    elif PAYLOAD_TYPE == 'UDP':
        pkt = generate_udp_pkt(PAYLOAD_PACKET_SIZE, vnc_clientip, socket.inet_aton(BACKEND_IP),
                               PAYLOAD_SRC_PORT, PAYLOAD_DST_PORT)
    
    await asyncio.sleep(1)
    
    # now caculate total packets and interval
    total_packets = TRAFFIC_LOAD_PER_TUNNEL * DURATION * 1024 // PAYLOAD_PACKET_SIZE
    interval_packets = 20   # for performance reasons, one sleep for sevaral packets
    interval = round(PAYLOAD_PACKET_SIZE / (TRAFFIC_LOAD_PER_TUNNEL * 1024) * interval_packets * 0.9, 4)    # this 0.9 is an experimental value to make traffic load accurate
    
    # start traffic load
    start_time = time.time()
    for i in range(total_packets):
        writer.write(bytes(pkt))
        try:
            if not i % interval_packets:
                await asyncio.sleep(interval)
                
                # By the way, to caculate packet delay(ms)
                delay_start_time = time.time()
                await asyncio.wait_for(writer.drain(), timeout=5)
                await asyncio.wait_for(reader.read(PAYLOAD_PACKET_SIZE - 28), timeout=5) # ip hdr + icmp hdr or udp hdr = 28
                delay_end_time = time.time()
                statistics['delay_packets_number'] += 1
                statistics['delay'] += delay_end_time - delay_start_time    
            else:
                await asyncio.wait_for(writer.drain(), timeout=5)
                await asyncio.wait_for(reader.read(PAYLOAD_PACKET_SIZE - 28), timeout=5) # ip hdr + icmp hdr or udp hdr = 28
        except asyncio.TimeoutError:
            logging.warning('timeout error catched, virtual ip: %s' %str_clientip)
            statistics['timeout_err_count'] += 1
    
    end_time = time.time()
    throughput= total_packets * PAYLOAD_PACKET_SIZE / (end_time - start_time) / 1024    # KB/s 
    
    statistics['troughtput'] += throughput
    statistics['complete_tunnels'] += 1
    
    # logout
    time.sleep(3)
    requests.get(logout_url, verify=False, headers={'Cookie': cookie})

def run_proc(proc_name, vuser_number, statistics):
    loop = asyncio.get_event_loop()
    tasks = [vpn_session('proc-%s: vuser-%s' %(proc_name, i), statistics) for i in range(vuser_number)]
    loop.run_until_complete(asyncio.wait(tasks))

if __name__=='__main__':
    # Get processors number
    n = psutil.cpu_count(logical=True)
    print('Logical CPU count(s): %s' %n)
    
    # Shared data between processes, for statistics using
    manager = Manager()
    statistics = manager.dict()
    statistics['complete_tunnels'] = 0
    statistics['timeout_err_count'] = 0
    statistics['delay'] = 0
    statistics['delay_packets_number'] = 0
    statistics['troughtput'] = 0
    
    pool = Pool(n)
    for i in range(n):
        # dispatch VIRTUAL_USERS to the processes, will start n processes(n = cpu count)
        if i==0:
            vusers = VIRTUAL_USERS // n + VIRTUAL_USERS % n     # to make proc0 + proc1 + .. + proc(n-1) = VIRTUAL_USERS
            pool.apply_async(run_proc, args=(i, vusers, statistics) )
        else:
            vusers = VIRTUAL_USERS // n
            pool.apply_async(run_proc, args=(i, vusers, statistics) )

    print('All processes start successfully, total virtual users: %s' %VIRTUAL_USERS)
    print('Waiting for all subprocesses done...')
    pool.close()
    pool.join()
    print('All subprocess done.')
    
    print('=================Statistics===================')
    print('Timeout errors   : %s' %statistics['timeout_err_count'])
    print('Complete tunnels : %s of %s' %(statistics['complete_tunnels'], VIRTUAL_USERS))
    print('Througtput       : %s KB/s' %round(statistics['troughtput']/statistics['complete_tunnels'], 2))
    print('Delay            : %s ms' %round(statistics['delay']/statistics['delay_packets_number'] * 1000, 2))
    print('==============================================')