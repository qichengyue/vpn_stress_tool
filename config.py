import logging

# IP address of virtual site
VIRTUAL_SITE_IP = '172.22.134.8'

# IP address of backend server
BACKEND_IP = '172.18.0.100'

# Concurrent virtual user count
VIRTUAL_USERS = 1

# Desired load per tunnel (KB/s)
TRAFFIC_LOAD_PER_TUNNEL = 200

# how long should the test run(with seconds)
DURATION = 120

# tunnel type 'TCP', 'UDP', 'DTLS'
TUNNEL_TYPE = 'UDP'

# encrypt UDP('True' or 'False')
IS_UDP_TUNNEL_ENCRYPT = False

# payload type, 'ICMP' or 'UDP'
PAYLOAD_TYPE = 'UDP'

# payload src port
PAYLOAD_SRC_PORT = 8888

# payload dst port, default is 9000
PAYLOAD_DST_PORT = 9000

# UDP server processes, default value is 4 since the server side default process number is 4
UDP_SERVER_PROCESS_NUMBER = 4

# payload packet size(Bytes)
PAYLOAD_PACKET_SIZE = 1300

# LOG LEVEL, by default "logging.ERROR" (debug < info < warning < error < critical)
LOGGING_LEVEL = logging.INFO
