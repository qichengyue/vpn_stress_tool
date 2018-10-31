'''
Created on 2018-08-23 15:34

@author: qichengyue
'''
import struct
import time
import asyncio
from config import PAYLOAD_PACKET_SIZE
import socket

# total_length: a integer, src_ip and dst_ip should be bytes like: b'\xac\x12dd'(172.18.100.100)


def generate_icmp_pkt(total_length, src_ip, dst_ip):
    ip_hdr = [
        0x45, 0x00,  # Version=4, IHL=5, Type of Service 0x00
        0x00, 0x00,  # Total length, to be calculated
        0xa3, 0x92, 0x00, 0x00,  # Identification(0xa3, 0x92, just a serial number) and fragment offset(0x00, 0x00)
        0x80, 0x01,  # TTL and protocol(0x01 = ICMP)
        0x00, 0x00,  # IP checksum
        0x00, 0x00, 0x00, 0x00,  # src IP
        0x00, 0x00, 0x00, 0x00,  # dst IP
    ]
    
    # fill in length segment of ip_hdr(16 bit)
    ip_hdr[2] = (total_length & 0xff00) >> 8    # high 8 bit
    ip_hdr[3] = (total_length & 0x00ff)         # low 8 bit
    
    # fill in src ip
    ip_hdr[12:16] = struct.unpack('!BBBB', src_ip)
    
    # fill in dst ip
    ip_hdr[16:20] = struct.unpack('!BBBB', dst_ip)
    
    # fill in ip checksum(A checksum for IP headers only, uncorrelated with data part))
    ip_checksum = checksum_calculator(ip_hdr)
    ip_hdr[10] = (ip_checksum & 0xff00) >> 8
    ip_hdr[11] = (ip_checksum & 0x00ff)
    
    # now craft ICMP part
    icmp_hdr = [
        0x08, 0x00,  # Type=0x08(ICMP Request)
        0x00, 0x00,  # icmp checksum, to be calculated
        0x01, 0x10,  # ICMP id
        0x20, 0x20,  # ICMP sequence number
    ]
    icmp_data_len = total_length - len(ip_hdr) - len(icmp_hdr)
    
    # fill in icmp data part
    icmp_data = list()
    data = 0x61     # icmp data is from 0x61-0x77
    for i in range(0, icmp_data_len):
        icmp_data.append(data)
        data += 1
        if(data == 0x78):
            data = 0x61
    
    # calculate icmp checksum, starts after ip header, include the whole rest packet
    icmp_checksum = checksum_calculator(icmp_hdr + icmp_data)
    icmp_hdr[2] = (icmp_checksum & 0xff00)>>8
    icmp_hdr[3] = (icmp_checksum & 0x00ff)
    
    return ip_hdr + icmp_hdr + icmp_data
    

def generate_udp_pkt(total_length, src_ip, dst_ip, src_port, dst_port):
    ip_hdr = [
        0x45, 0x00,  # Version=4, IHL=5, Type of Service 0x00
        0x00, 0x00,  # Total length, to be calculated
        0xa3, 0x92, 0x00, 0x00,  # Identification(0xa3, 0x92, just a serial number) and fragment offset(0x00, 0x00)
        0x80, 0x11,  # TTL and protocol(0x11 = UDP)
        0x00, 0x00,  # IP checksum
        0x00, 0x00, 0x00, 0x00,  # src IP
        0x00, 0x00, 0x00, 0x00,  # dst IP
    ]
    
    # fill in length segment of ip_hdr(16 bit)
    ip_hdr[2] = (total_length & 0xff00) >> 8    # high 8 bit
    ip_hdr[3] = (total_length & 0x00ff)         # low 8 bit
    
    # fill in src ip
    ip_hdr[12:16] = struct.unpack('!BBBB', src_ip)
    
    # fill in dst ip
    ip_hdr[16:20] = struct.unpack('!BBBB', dst_ip)
    
    # fill in ip checksum(A checksum for IP headers only, uncorrelated with data part))
    ip_checksum = checksum_calculator(ip_hdr)
    ip_hdr[10] = (ip_checksum & 0xff00) >> 8
    ip_hdr[11] = (ip_checksum & 0x00ff)
    
    # now prepare udp hdr
    udp_hdr = [
        0x00, 0x00,  # src port, to be calculated
        0x00, 0x00,  # dst port, to be calculated
        0x00, 0x00,  # udp length(udp header + data), to be calculated
        0x00, 0x00,  # checksum, to be calculated
    ]
    
    udp_total_length = total_length -len(ip_hdr)
    # fill in src port
    udp_hdr[0] = (src_port & 0xff00) >> 8
    udp_hdr[1] = (src_port & 0x00ff)
    # fill in dst port
    udp_hdr[2] = (dst_port & 0xff00) >> 8
    udp_hdr[3] = (dst_port & 0x00ff)
    # fill in udp length
    udp_hdr[4] = (udp_total_length & 0xff00) >> 8
    udp_hdr[5] = (udp_total_length & 0x00ff)

    udp_data_length = udp_total_length - len(udp_hdr)
    
    # fill in udp data part
    udp_data = list()
    data = 0x61     # will fill udp data with [0x61 - 0x77]
    for i in range(0, udp_data_length):
        udp_data.append(data)
        data += 1
        if data == 0x78:
            data = 0x61
    
    # udp checksum need a pseudo header(this pseudo header is only for calculating checksum)
    udp_pseudo_hdr = [
        0x00, 0x00, 0x00, 0x00,  # src ip addr, to be calculated
        0x00, 0x00, 0x00, 0x00,  # dst ip addr, to be calculated
        0x00, 0x11,  # fixed value
        0x00, 0x00,  # udp length(udp header + data), to be calculated
    ]
    # fill in src ip addr
    udp_pseudo_hdr[0:4] = struct.unpack('!BBBB', src_ip)
    # fill in dst ip addr
    udp_pseudo_hdr[4:8] = struct.unpack('!BBBB', dst_ip)
    # fill in udp pseudo header length
    udp_pseudo_hdr[10] = (udp_total_length & 0xff00) >> 8
    udp_pseudo_hdr[11] = (udp_total_length & 0x00ff)
    
    # calculate udp checksum, starts after ip header, include udp pseudo header and the whole rest packet
    udp_checksum = checksum_calculator(udp_pseudo_hdr + udp_hdr + udp_data)
    udp_hdr[6] = (udp_checksum & 0xff00) >> 8
    udp_hdr[7] = (udp_checksum & 0x00ff)
    
    return ip_hdr + udp_hdr + udp_data


# The algorithm of ip checksum and icmp checksum are the same
def checksum_calculator(data):
    checksum = 0
    length = len(data)
    
    # in case of the length is odd
    odd = length & 1
    length = length - odd
    
    for i in range(0, length, 2):
        h = data[i]
        l = data[i+1]
        checksum = checksum + ((h << 8) + l)
    
    if odd:
        checksum = checksum + (data[length] << 8)
    
    while checksum > 0xffff:
        checksum = ((checksum >> 16) + (checksum & 0xffff))
    
    checksum = 0xffff - checksum
    return checksum


# For create UDP tunnel
def get_apt_control_packet_header(): 
    atp_control_packet_header = [
        0x45, 0x00, 0x00, 0x14, 
        0x00, 0x00, 0x00, 0x00, 
        0x00, 0xff, 0x00, 0x00,
    ]
    return atp_control_packet_header


# A non-coroutine function. Since udp protocol is orderless and connectionless, so it is hard to calculate delay value
# via coroutine functions, so we start a thread use datagram socket(which is blocked) to get delay value
def udp_tunnel_socket(ip, port, pkt_init, pkt_payload, statistics, total_packets, interval_time, interval_count, logger):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    s.sendto(bytes(pkt_init), (ip, port))
    try:
        res = s.recv(1024)
    except BaseException as e:
        logger.warning('UDP thread tunnel create failed, reason: Timeout')
        return
    
    if res != b'200 OK':
        logger.warning('UDP thread create VPN tunnel failed, response code is not 200 OK')
        return
    
    delay_packets_number = 0
    delay_time_total = 0
    
    start_time = time.time()
    for i in range(total_packets):
        try:
            if not i % interval_count:
                delay_start_time = time.time()
                s.sendto(bytes(pkt_payload), (ip, port))
                s.recv(1500)
                delay_end_time = time.time()
                delay_packets_number += 1
                delay_time_total += delay_end_time - delay_start_time
                time.sleep(interval_time)
            else:
                s.sendto(bytes(pkt_payload), (ip, port))
                s.recv(1500)
        except BaseException as e:
            logger.info('there is a UDP thread payload timeout')
        
    end_time = time.time()
    
    throughput = total_packets * PAYLOAD_PACKET_SIZE / (end_time - start_time) / 1024    # KB/s
    statistics['delay_packets_number'] += delay_packets_number
    statistics['delay'] += delay_time_total
    statistics['throughput'] += throughput
    statistics['complete_tunnels'] += 1
    statistics['isThreadComplete'] = True
    

# For UDP support on asyncio module, we need a Protocol class to handle handle connection and packet
class VpnUdpTunnelProtocol:
    def __init__(self, logging, loop, udp_tunnel_packet):
        self.logging = logging
        self.loop = loop
        self.udp_tunnel_packet = udp_tunnel_packet
        self.transport = None
        self.is_tunnel_created = False
        self.on_con_lost = loop.create_future()

    def connection_made(self, transport):
        self.transport = transport
        self.logging.info('UDP connection build successfully')
        self.transport.sendto(bytes(self.udp_tunnel_packet))
        
    def datagram_received(self, data, addr):
        pass
    
    def error_received(self, exc):
        self.logging.error('UDP tunnel connection got an error, reason:%s' %exc)

    def connection_lost(self, exc):
        self.logging.error('UDP tunnel connection lost, reason: %s' %exc)
        self.on_con_lost.set_result(True)
        

def encrypt_udp_payload_packet(pkt, udpkey):
    encrypted_pkt = list()
    for i in range(len(pkt)//4):
        data = struct.unpack('!I', bytes(pkt[i*4 : i*4+4]))[0]
        key = struct.unpack('!I', bytes(udpkey[i*4 : i*4+4]))[0]
        encrypted_pkt.extend(struct.pack('!I', data ^ key))
    
    residue = len(pkt) % 4
    if residue > 0:
        index = len(pkt) - residue
        for i in range(residue):
            data = struct.unpack('!B', pkt[index+i])[0]
            key = struct.unpack('!B', udpkey[index+i])[0]
            encrypted_pkt.append(struct.pack('!B', data ^ key))
    
    return encrypted_pkt
