import time, os, argparse
from OBU.encode_packet import gen_packet
from OBU.fragment import send_fragment
from OBU.setup import setup
from dotenv import load_dotenv
from socket import *
from pathlib import Path

load_dotenv()

# 配置參數
RSU_IP = os.getenv("RSU_IP", "192.168.1.174")
RSU_PORT = int(os.getenv("RSU_PORT", 5005))

# 用計數器的方式取得ID
current_msg_id = 0

def get_next_id():
    global current_msg_id
    # 確保在 0~65535 之間循環
    current_msg_id = (current_msg_id + 1) % 65536
    return current_msg_id

# 建立 UDP Socket
sock = socket(AF_INET, SOCK_DGRAM)

def send_heartbeat(obu_id, freq):
    try:
        while True:
            packet = gen_packet(obu_id)  # 生成包含簽章的封包
            send_fragment(sock, get_next_id(), packet, (RSU_IP, RSU_PORT))  # 發送分片
            
            time.sleep(freq)   # 定時發送
    except KeyboardInterrupt:
        print(f"\n[{obu_id}] 已停止發送封包")
    finally:
        sock.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("obu_id", type=str, help="緊急車輛的編號")
    parser.add_argument("-f", "--freq", type=float, default=5, help="發送分片的頻率(秒)，預設為 5")
    args = parser.parse_args()

    cert_path = Path(f"./cert/{args.obu_id}_cert.bin")
    if not cert_path.is_file():
        print(f"[{args.obu_id}] 未偵測到該車輛的憑證，正在初始化...")
        setup(args.obu_id)

    print(f"[{args.obu_id}] 即將發送封包...")
    send_heartbeat(args.obu_id, args.freq)