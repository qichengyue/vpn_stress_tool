import asyncio, aiohttp
import random

from OpenSSL import SSL

from config import VIRTUAL_SITE_IP, BACKEND_IP, VIRTUAL_USERS, PAYLOAD_PACKET_SIZE,\
    PAYLOAD_TYPE, PAYLOAD_SRC_PORT, PAYLOAD_DST_PORT, LOGGING_LEVEL,\
    TRAFFIC_LOAD_PER_TUNNEL, DURATION, TUNNEL_TYPE, IS_UDP_TUNNEL_ENCRYPT,\
    UDP_SERVER_PROCESS_NUMBER
import ssl
import struct
from utils import generate_icmp_pkt, generate_udp_pkt,\
    get_apt_control_packet_header, VpnUdpTunnelProtocol, udp_tunnel_socket,\
    encrypt_udp_payload_packet
import socket
import time
import urllib3
import logging
import uuid
import psutil
from multiprocessing import Pool, Manager
import threading
from OpenSSL._util import lib

DATEFMT = "[%Y-%m-%d %H:%M:%S]"
FORMAT = "%(asctime)s %(levelname)s %(funcName)s: %(message)s"
logging.basicConfig(level=LOGGING_LEVEL, format=FORMAT, datefmt=DATEFMT, filename='vpn.log', filemode='a')
logger = logging.getLogger(__name__)
# Prepare for DTLS tunnel
DTLSv1_METHOD = 7
DTLSv12_METHOD = 8
SSL.Context._methods[DTLSv1_METHOD] = lib.DTLSv1_client_method
SSL.Context._methods[DTLSv12_METHOD] = lib.DTLS_client_method

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
    jar = aiohttp.CookieJar(unsafe=True)  # To accept cookie with IP address(By default only cookie with FQDN are legal)
    async with aiohttp.ClientSession(cookie_jar=jar) as session:
        # extract authenticate method(by default is 'default_method_localdb')
        async with session.get(login_url, ssl=False) as response:
            res_str = await response.text(encoding='utf-8')
            res_str = res_str[res_str.index('"name"') + 9: len(res_str)]
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

    await asyncio.sleep(5)
    
    # create vpn tunnel
    ssl_ctx = ssl._create_unverified_context()
    reader, writer = await asyncio.open_connection(VIRTUAL_SITE_IP, 443, ssl=ssl_ctx)
    writer.write(b'Get /vpntunnel HTTP/1.1\r\nHost: %s\r\nCookie: %s\r\nappid: SSPVPN\r\nclientid: \
                %s\r\ncpuid: \r\nhostname: %s\r\n\r\n'
                 % (VIRTUAL_SITE_IP.encode(encoding='utf-8'), cookie, str(uuid.uuid1()).encode(encoding='utf-8'), virtual_hostname.encode(encoding='utf-8')))
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
    process_number = int(virtual_hostname[5: virtual_hostname.index(':')])  # virtual_host format is like: 'proc-%s: vuser-%s' %(proc_name, i), extract the process id to dispatch UDP payload to different UDP server port for load balance
    
    pkt = list()
    if PAYLOAD_TYPE == 'ICMP':
        pkt = generate_icmp_pkt(PAYLOAD_PACKET_SIZE, vnc_clientip, socket.inet_aton(BACKEND_IP))
        print('pkt after encrypt:', pkt)
    elif PAYLOAD_TYPE == 'UDP':
        pkt = generate_udp_pkt(PAYLOAD_PACKET_SIZE, vnc_clientip, socket.inet_aton(BACKEND_IP),
                               PAYLOAD_SRC_PORT, PAYLOAD_DST_PORT + process_number % UDP_SERVER_PROCESS_NUMBER)
    
    await asyncio.sleep(1)
    
    # now calculate total packets and interval_time
    total_packets = TRAFFIC_LOAD_PER_TUNNEL * DURATION * 1024 // PAYLOAD_PACKET_SIZE
    interval_count = 20   # for performance reasons, one sleep for several packets
    interval_time = round(PAYLOAD_PACKET_SIZE / (TRAFFIC_LOAD_PER_TUNNEL * 1024) * interval_count * 0.9, 4)    # this 0.9 is an experimental value to make traffic load accurate
    
    # If UDP tunnel
    if TUNNEL_TYPE == 'UDP':
        logging.info('start to get udp tunnel config...')
        uuid_packet = get_apt_control_packet_header()
        uuid_packet[3] = 0x34               # fixed value 34
        uuid_packet.extend([0x00, 0x04])    # 0x0004 is command code of ATP_SEND_CLIENTID
        uuid_packet.extend([0x00, 0x00])    # reserved segment
        client_udp_uuid = str(uuid.uuid1())
        uuid_packet.extend(struct.unpack('36B', client_udp_uuid.encode('utf-8')))
        writer.write(bytes(uuid_packet))
        await writer.drain()
        
        uuid_packet_response = await reader.read(2048)
        if uuid_packet_response[9] != 0xff:
            logging.warning('Received packet is not for UDP tunnel')
        
        coreid = socket.ntohs(struct.unpack('!H', uuid_packet_response[14:16])[0])
        udp_key = uuid_packet_response[20:len(uuid_packet_response)]
        udp_tunnel_port = struct.unpack('!I', uuid_packet_response[16:20])[0]
        logging.info('UDP tunnel port is: %s' % udp_tunnel_port)
        
        # start to create udp tunnel
        logging.info('start to create udp tunnel(send first packet to udp tunnel port..)')
        udp_tunnel_packet = bytearray(42)   # The first UDP packet, to create UDP tunnel
        udp_tunnel_packet[4: 4+len(client_udp_uuid)] = bytes(client_udp_uuid.encode('utf-8'))    # Fill uuid, the first 4 bytes is for core id and checksum
        # Fill udp tunnel type, encrypt off: 0x30(ASCII code of 0), encrypt on: 0x31(ASCII code of 1)
        udp_tunnel_packet[4+len(client_udp_uuid)] = 0x31 if IS_UDP_TUNNEL_ENCRYPT else 0x30
        udp_tunnel_packet[4+len(client_udp_uuid)+1] = 0x33   # Dispatch rule, 0x33 means all traffic through UDP tunnel
        udp_tunnel_packet[0] = coreid
        udp_tunnel_packet[1] = (len(udp_tunnel_packet) - 4 + 12) // 8
        udp_tunnel_packet[2] = udp_tunnel_packet[4] ^ udp_tunnel_packet[5]
        udp_tunnel_packet[3] = udp_tunnel_packet[1] ^ udp_tunnel_packet[2]
    
        # Now generate UDP tunnel payload packet
        if IS_UDP_TUNNEL_ENCRYPT:
            pkt = encrypt_udp_payload_packet(pkt, udp_key)
        # for payload part need add a special header
        udp_payload_packet_header = [x for x in range(4)]   # Init a list, length is 4 bytes
        udp_payload_packet_header[0] = coreid
        udp_payload_packet_header[1] = (len(pkt) + 12) // 8
        udp_payload_packet_header[2] = pkt[0] ^ pkt[3]
        udp_payload_packet_header[3] = udp_payload_packet_header[1] ^ udp_payload_packet_header[2]
        udp_payload_packet_header.extend(pkt)
        pkt = udp_payload_packet_header
        
        if not statistics['isThreadStarted']:
            statistics['isThreadStarted'] = True
            udp_tunnel_thread = threading.Thread(target=udp_tunnel_socket, args=(VIRTUAL_SITE_IP, udp_tunnel_port, udp_tunnel_packet, pkt, statistics, total_packets, interval_time, interval_count, logger))
            udp_tunnel_thread.start()
            # waiting for udp tunnel thread complete, we wait up to DURATION * 2 seconds
            for i in range(DURATION):
                if statistics['isThreadComplete']:
                    break
                else:
                    await asyncio.sleep(2)
        else:
            # create asyncio UDP socket
            loop = asyncio.get_running_loop()
            # Create coroutine socket and send first packet
            transport, protocol = await loop.create_datagram_endpoint(lambda: VpnUdpTunnelProtocol(logger, loop, udp_tunnel_packet),
                remote_addr=(VIRTUAL_SITE_IP, udp_tunnel_port))
            await asyncio.sleep(2)  # Sleep 2s and then start traffic load
            
            start_time = time.time()
            for i in range(total_packets):
                
                if not i % interval_count:
                    transport.sendto(bytes(pkt))
                    await asyncio.sleep(interval_time)
                else:
                    transport.sendto(bytes(pkt))
                
            end_time = time.time()
            throughput= total_packets * PAYLOAD_PACKET_SIZE / (end_time - start_time) / 1024    # KB/s 
            
            statistics['throughput'] += throughput
            statistics['complete_tunnels'] += 1
    
    # if DTLS tunnel
    isComplete = False  # complete flag, the dtls proxy thread will exit when client thread set isComplete = True
    if TUNNEL_TYPE[0:4] == 'DTLS':
        logging.info('start to get DTLS tunnel config...')
        uuid_packet = get_apt_control_packet_header()
        uuid_packet[3] = 0x34               # fixed value 34
        uuid_packet.extend([0x00, 0x04])    # 0x0004 is command code of ATP_SEND_CLIENTID
        uuid_packet.extend([0x00, 0x00])    # reserved segment
        client_udp_uuid = str(uuid.uuid1())
        uuid_packet.extend(struct.unpack('36B', client_udp_uuid.encode('utf-8')))
        writer.write(bytes(uuid_packet))
        await writer.drain()
        
        uuid_packet_response = await reader.read(2048)
        if uuid_packet_response[9] != 0xff:
            logging.warning('Received packet is not for DTLS tunnel')
        
        coreid = socket.ntohs(struct.unpack('!H', uuid_packet_response[14:16])[0])
        dtls_tunnel_port = struct.unpack('!I', uuid_packet_response[16:20])[0]
        logging.info('DTLS tunnel port is: %s' % dtls_tunnel_port)

        if TUNNEL_TYPE == 'DTLSv1':
            ctx = SSL.Context(DTLSv1_METHOD)
        elif TUNNEL_TYPE == 'DTLSv12':
            ctx = SSL.Context(DTLSv12_METHOD)
        else:
            print('WANING: your tunnel type is NOT valid, treated as DTLSv1')
            ctx = SSL.Context(DTLSv1_METHOD)

        # Each vuser has its own dtls proxy thread(each thread need a udp port to listen)
        dtls_proxy_port = random.randint(5000, 65500)

        def dtls_proxy(ag_ip, ag_port):
            logging.info('dtls proxy thread start...')
            listen_ip = '0.0.0.0'
            nonlocal dtls_proxy_port
            listen_port = dtls_proxy_port
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            # Try until socket has a valid port
            while True:
                try:
                    server_socket.bind((listen_ip, listen_port))
                    break
                except BaseException as e:
                    dtls_proxy_port = random.randint(5000, 65500)
                    server_socket.bind((listen_ip, listen_port))

            server_socket.settimeout(3)
            # Try until we got first packet
            data = bytes()
            dtls_client_addr = tuple()
            while True:
                try:
                    data, dtls_client_addr = server_socket.recvfrom(1500)  # The first packet is definitely come from dtls client
                    break
                except BaseException as e:
                    continue

            addr = ('0.0.0.0', dtls_tunnel_port)

            # for every packet timeout, counter++, if counter > 10, terminated thread
            counter = 0
            while not isComplete:
                if addr[0] == ag_ip:
                    # The packet is from VPN server side, sendto VPN client side
                    server_socket.sendto(data, dtls_client_addr)
                else:
                    # The packet is from VPN client side, add a 4 bytes header then send to VPN server side
                    header = [x for x in range(4)]  # init a 4 bytes list
                    header[0] = coreid
                    header[1] = (len(data) + 12) // 8
                    header[2] = data[0] ^ data[3]
                    header[3] = header[1] ^ header[2]
                    header.extend(data)
                    server_socket.sendto(bytes(header), (ag_ip, ag_port))
                try:
                    data, addr = server_socket.recvfrom(1500)
                    counter = 0  # reset counter for each success recv..
                except BaseException as e:
                    logging.info('read from socket timeout')
                    counter += 1
                    if counter > 10:
                        break
                    continue

        dtls_proxy_thread = threading.Thread(target=dtls_proxy, args=(VIRTUAL_SITE_IP, dtls_tunnel_port))
        dtls_proxy_thread.start()
        await asyncio.sleep(5)

        # After dlts proxy thread started, we start dtls client thread
        def dtls_client():
            nonlocal isComplete
            logging.info('dtls client thread start...')
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            ctx.set_options(lib.SSL_OP_NO_QUERY_MTU)
            ctx.set_timeout(3)
            logging.info('dtls connection ctx timeout value: %s' % ctx.get_timeout())
            con = SSL.Connection(ctx, s)
            lib.DTLS_set_link_mtu(con._ssl, 1500)
            con.connect(('127.0.0.1', dtls_proxy_port))
            logging.info('about to do dtls handshake..')
            con.do_handshake()
            logging.info('dtls handshake finished..')

            logging.info('start to create udp tunnel(send first packet to udp tunnel port..)')
            first_data_packet = bytearray(42)  # The first UDP packet, to create dtls tunnel and get "200 OK"
            # Fill uuid
            first_data_packet[0: len(client_udp_uuid)] = bytes(client_udp_uuid.encode('utf-8'))
            # Fill udp tunnel type, encrypt off: 0x30(ASCII code of 0), encrypt on: 0x31(ASCII code of 1), dtls: ?
            first_data_packet[len(client_udp_uuid)] = 0x31
            # Dispatch rule, 0x33 means all traffic through UDP tunnel
            first_data_packet[len(client_udp_uuid) + 1] = 0x33
            con.send(bytes(first_data_packet))
            retry = 5  # the max retry times for first packet
            for i in range(retry):
                try:
                    res = con.read(1500)
                    if res == b'200 OK':
                        logging.info('DTLS tunnel create success!')
                        logging.info('DTLS tunnel cipher: %s Protocol: %s' % (con.get_cipher_name(), con.get_protocol_version_name()))
                    else:
                        logging.warning('DTLS tunnel create failed, response code:%s' % res.decode('utf-8'))
                        isComplete = True
                    break
                except BaseException as e:
                    logging.warning('DTLS tunnel first packet NOT got right response, code:%s, start retry...' % e)
                    con.send(bytes(first_data_packet))

            # Start traffic load via DTLS tunnel
            logging.info('start traffic load via DTLS tunnel..')
            if not statistics['isThreadStarted']:
                statistics['isThreadStarted'] = True
                delay_packets_number = 0
                delay_time_total = 0

                start_time = time.time()
                for i in range(total_packets):
                    try:
                        if not i % interval_count:
                            delay_start_time = time.time()
                            con.send(bytes(pkt))
                            con.read(1500)
                            delay_end_time = time.time()
                            delay_packets_number += 1
                            delay_time_total += delay_end_time - delay_start_time
                            time.sleep(interval_time)
                        else:
                            con.send(bytes(pkt))
                            con.read(1500)
                    except BaseException as e:
                        logger.info('there is a DTLS thread payload timeout')

                end_time = time.time()

                throughput = total_packets * PAYLOAD_PACKET_SIZE / (end_time - start_time) / 1024  # KB/s
                statistics['delay_packets_number'] += delay_packets_number
                statistics['delay'] += delay_time_total
                statistics['throughput'] += throughput
                statistics['complete_tunnels'] += 1
                statistics['isThreadComplete'] = True
            else:
                start_time = time.time()
                for i in range(total_packets):
                    if not i % interval_count:
                        con.send(bytes(pkt))
                        time.sleep(interval_time)
                    else:
                        con.send(bytes(pkt))
                end_time = time.time()
                throughput = total_packets * PAYLOAD_PACKET_SIZE / (end_time - start_time) / 1024  # KB/s

                statistics['throughput'] += throughput
                statistics['complete_tunnels'] += 1

            isComplete = True
            logging.info('DTLS client thread complete..')

        dtls_client_thread = threading.Thread(target=dtls_client, args=())
        await asyncio.sleep(5)
        dtls_client_thread.start()
        dtls_proxy_thread.join()
        dtls_client_thread.join()

    # TCP tunnel traffic load
    if TUNNEL_TYPE == 'TCP':
        statistics['isThreadComplete'] = True   # TCP tunnel will not start the thread
        start_time = time.time()
        delay_packets_number = 0
        delay_time_total = 0.0
        for i in range(total_packets):
            writer.write(bytes(pkt))
            try:
                if not i % interval_count:
                    await asyncio.sleep(interval_time)
                    # By the way, to calculate packet delay(ms)
                    delay_start_time = time.time()
                    await asyncio.wait_for(writer.drain(), timeout=3)
                    await asyncio.wait_for(reader.read(PAYLOAD_PACKET_SIZE - 28), timeout=3)  # ip hdr + icmp hdr or udp hdr = 28
                    delay_end_time = time.time()
                    delay_packets_number += 1
                    delay_time_total += delay_end_time - delay_start_time
                else:
                    await asyncio.wait_for(writer.drain(), timeout=3)
                    await asyncio.wait_for(reader.read(PAYLOAD_PACKET_SIZE - 28), timeout=3)  # ip hdr + icmp hdr or udp hdr = 28
            except asyncio.TimeoutError:
                logging.warning('timeout error, virtual ip: %s' % str_clientip)
                statistics['timeout_err_count'] += 1

        end_time = time.time()
        throughput = total_packets * PAYLOAD_PACKET_SIZE / (end_time - start_time) / 1024    # KB/s
        
        statistics['delay_packets_number'] += delay_packets_number
        statistics['delay'] += delay_time_total
        statistics['throughput'] += throughput
        statistics['complete_tunnels'] += 1
    
    # logout session
    await asyncio.sleep(3)
    logging.info('All done! logout session..')
    reader, writer = await asyncio.open_connection(VIRTUAL_SITE_IP, 443, ssl=ssl_ctx)
    writer.write(b'Get /prx/000/http/localhost/logout HTTP/1.1\r\nHost: %s\r\nCookie: %s\r\n\r\n'
                 % (VIRTUAL_SITE_IP.encode(encoding='utf-8'), cookie))
    await writer.drain()
    await reader.read(1024)


def run_proc(proc_name, vuser_number, statistics):
    loop = asyncio.get_event_loop()
    tasks = [vpn_session('proc-%s: vuser-%s' % (proc_name, i), statistics) for i in range(vuser_number)]
    loop.run_until_complete(asyncio.wait(tasks))


if __name__ == '__main__':
    # Get processors number
    n = psutil.cpu_count(logical=True)
    print('Logical CPU count: %s' % n)
    
    # Shared data between processes, for statistics using
    manager = Manager()
    statistics = manager.dict()
    statistics['complete_tunnels'] = 0
    statistics['timeout_err_count'] = 0
    statistics['delay'] = 0
    statistics['delay_packets_number'] = 0
    statistics['throughput'] = 0
    
    # For UDP & DTLS tunnel delay value statistics, we need to start a single thread
    statistics['isThreadComplete'] = False
    statistics['isThreadStarted'] = False
    
    pool = Pool(n)
    for i in range(n):
        # dispatch VIRTUAL_USERS to the processes, will start n processes(n = cpu count)
        if i == 0:
            vusers = VIRTUAL_USERS // n + VIRTUAL_USERS % n     # to make proc0 + proc1 + .. + proc(n-1) = VIRTUAL_USERS
            if vusers > 0:
                pool.apply_async(run_proc, args=(i, vusers, statistics))
        else:
            vusers = VIRTUAL_USERS // n
            if vusers > 0:
                pool.apply_async(run_proc, args=(i, vusers, statistics))

    print('All processes start successfully, total virtual users: %s' % VIRTUAL_USERS)
    print('Waiting for all subprocesses done...')
    pool.close()
    pool.join()
    
    print('All subprocess done.')
    
    print('=================Statistics===================')
    print('Timeout errors   : %s' % statistics['timeout_err_count'])
    print('Complete tunnels : %s of %s' % (statistics['complete_tunnels'], VIRTUAL_USERS))
    print('Throughput       : %s KB/s' % round(statistics['throughput']/statistics['complete_tunnels'], 2))
    print('Delay            : %s ms' % round(statistics['delay']/statistics['delay_packets_number'] * 1000, 2))
    print('==============================================')
