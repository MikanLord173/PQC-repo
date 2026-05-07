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

# 用於存儲已知 RSU 資訊，結構為 "RSUn": {"IP": "x.x.x.x", "PORT": 1234}
saved_RSU = {}

def get_next_id():
    global current_msg_id
    # 確保在 0~65535 之間循環
    current_msg_id = (current_msg_id + 1) % 65536
    return current_msg_id

# 檢查RSU是否已知，並更新已知RSU列表
def check_RSU():
    known_RSU = False
    RSU_counter = 1
    for key, val in saved_RSU.items():
        RSU_counter += 1
        if val['IP'] == RSU_IP and val['PORT'] == RSU_PORT:
            known_RSU = True
            break
    if not known_RSU:
        saved_RSU[f"RSU{RSU_counter}"] = {"IP": RSU_IP, "PORT": RSU_PORT}
        print(f"已記憶 RSU{RSU_counter}：IP={RSU_IP}, PORT={RSU_PORT}")
    return known_RSU

# 建立 UDP Socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

def send_heartbeat():
    try:
        while True:
            packet = gen_packet(OBU_ID, check_RSU())  # 生成包含簽章的封包
            send_fragment(sock, get_next_id(), packet, (RSU_IP, RSU_PORT))  # 發送分片
            
            time.sleep(FREQUENCY)   # 定時發送
    except KeyboardInterrupt:
        print("\nOBU 已停止發送")
    finally:
        with open("OBU/json/saved_RSU.json", "w") as f:
            json.dump(saved_RSU, f, indent=4)
        sock.close()

if __name__ == "__main__":
    with open("OBU/json/saved_RSU.json", "r") as f:
        for key, val in json.load(f).items():
            saved_RSU.append((val['IP'], val['PORT']))
    send_heartbeat()