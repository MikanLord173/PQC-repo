import socket, time, json
from OBU.encode_packet import gen_packet
from OBU.fragment import send_fragment

# 配置參數
OBU_ID = "AMB-217"  # 車輛 ID，最多8字元
RSU_IP = "192.168.1.174" 
RSU_PORT = 5005
FREQUENCY = 5  # 發送頻率 (秒)

# 用計數器的方式取得ID
current_msg_id = 0

def get_next_id():
    global current_msg_id
    # 確保在 0~65535 之間循環
    current_msg_id = (current_msg_id + 1) % 65536
    return current_msg_id

# 建立 UDP Socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

def send_heartbeat():
    try:
        while True:
            packet = gen_packet(OBU_ID)  # 生成包含簽章的封包
            send_fragment(sock, get_next_id(), packet, (RSU_IP, RSU_PORT))  # 發送分片
            
            time.sleep(FREQUENCY)   # 定時發送
    except KeyboardInterrupt:
        print("\nOBU 已停止發送")
    finally:
        sock.close()

if __name__ == "__main__":
    send_heartbeat()