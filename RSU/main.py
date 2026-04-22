import socket, time
import RSU.parse as parse

# 配置參數
RSU_IP = "0.0.0.0"  # 監聽所有可用的網路介面
RSU_PORT = 5005     # 自定義連接埠
BUFFER_SIZE = 4096  # 預留稍大緩衝區，為之後的 PQC 簽章做準備

# 要改成用 (msg_id, addr) 當 key，這樣就不會有不同車輛的訊息混在一起了
reassemble_buffer = {}  # 用於存儲分片資料的緩衝區，key 為 (msg_id, addr)，value 為分片列表

def receive_data(sock):
    try:
        while True:
            # 接收資料
            # data: 接收到的位元組資料
            # addr: 發送端的 (IP, Port)
            data, addr = sock.recvfrom(BUFFER_SIZE)

            header_bytes = data[:4]  # 前 4 個位元組是 header
            chunk_bytes = data[4:]  # 剩下的位元組是封包本身內容

            # Header (4 bytes)：目前分片序列號(1) | 總分片數(1) | 訊息ID(2)
            seq_num, total_frags, msg_id = parse.parse_header(header_bytes)
            if seq_num is None:
                print(f"[來自 {addr}] 收到無效的 header，忽略此訊息")
                continue

            if (msg_id, addr) not in reassemble_buffer:
                reassemble_buffer[(msg_id, addr)] = [None] * total_frags  # 初始化分片列表

            print(f"[來自 {addr}] 收到ID為 {msg_id} 的分片 ({seq_num}/{total_frags})。")

            # 將分片存入緩衝區
            reassemble_buffer[(msg_id, addr)][seq_num-1] = chunk_bytes

            # 檢查是否所有分片都已收到
            if all(fragment is not None for fragment in reassemble_buffer[(msg_id, addr)]):
                print(f"[來自 {addr}] 已收到ID為 {msg_id} 的所有分片。")
                # 重組訊息
                packet = b''.join(reassemble_buffer[(msg_id, addr)])  # 將分片列表中的位元組串接成完整封包
                # 清除緩衝區
                del reassemble_buffer[(msg_id, addr)]

                payload = parse.parse_packet(packet)  # 將重組後的訊息轉回位元組並解析

                if payload:
                    print(f"\n[來自 {addr}] 驗證成功，切換緊急綠燈！")
                    print(f"總耗時：{time.time() - payload['full_timestamp']} 秒")
                    print(f"\n完整訊息：")
                    for key, value in payload.items():
                        print(f"{key}: {value}")
                else:
                    print(f"[來自 {addr}] 驗證失敗，拒絕通行。")
    except KeyboardInterrupt:
        print("\nRSU 已手動關閉")
    finally:
        sock.close()

if __name__ == "__main__":
    # 建立 UDP Socket
    # socket.AF_INET 代表使用 IPv4
    # socket.SOCK_DGRAM 代表使用 UDP 協議
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # 將 Socket 綁定到 IP 與 Port
    sock.bind((RSU_IP, RSU_PORT))
    print(f"--- RSU 已啟動，正在監聽連接埠 {RSU_PORT} ---")
    receive_data(sock)