# IP address of virtual site
VIRTUAL_SITE_IP = '172.22.134.8'

# IP address of backend server
BACKEND_IP = '172.18.0.100'

# Concurrent virtual user count
VIRTUAL_USERS = 10

# Desired load per tunnel (KB/s)
TRAFFIC_LOAD_PER_TUNNEL = 100

# how long should the test run(with seconds)
DURATION = 120

# tunnel type UDP or TCP
TUNNEL_TYPE = 'TCP'

# encrypt UDP tunnel(1) or not(0)
IS_UDP_TUNNEL_ENCRYPT = 0

# payload type, 'ICMP' or 'UDP'
PAYLOAD_TYPE = 'UDP'

# payload src port
PAYLOAD_SRC_PORT = 8888

# payload dst port
PAYLOAD_DST_PORT = 9999

# payload packet size(Bytes)
PAYLOAD_PACKET_SIZE = 1200

# LOG LEVEL
LOGGING_LEVEL = 'INFO'