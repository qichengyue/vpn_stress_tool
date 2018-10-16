import logging

# IP address of virtual site
VIRTUAL_SITE_IP = '172.22.134.8'

# IP address of backend server
BACKEND_IP = '172.18.0.100'

# Concurrent virtual user count
VIRTUAL_USERS = 100

# Desired load per tunnel (KB/s)
TRAFFIC_LOAD_PER_TUNNEL = 200

# how long should the test run(with seconds)
DURATION = 30

# tunnel type 'TCP', 'UDP', 'DTLS'
TUNNEL_TYPE = 'UDP'

# encrypt UDP('True' or 'False')
IS_UDP_TUNNEL_ENCRYPT = False

# payload type, 'ICMP' or 'UDP'
PAYLOAD_TYPE = 'UDP'

# payload src port
PAYLOAD_SRC_PORT = 8888

# payload dst port
PAYLOAD_DST_PORT = 9999

# payload packet size(Bytes)
PAYLOAD_PACKET_SIZE = 1300

# LOG LEVEL, by default "logging.ERROR" (debug < info < warning < error < critical)
LOGGING_LEVEL = logging.INFO
