import time, os, asyncio
import RSU.parse as parse
from dotenv import load_dotenv
from socket import *

load_dotenv()

# 配置參數
RSU_PORT = int(os.getenv("RSU_PORT", 5005))     # 自定義連接埠
BUFFER_SIZE = 4096  # 預留稍大緩衝區，為之後的 PQC 簽章做準備

# 要改成用 (msg_id, addr) 當 key，這樣就不會有不同車輛的訊息混在一起了
reassemble_buffer = {}  # 用於存儲分片資料的緩衝區，key 為 (msg_id, addr)，value 為分片列表

def get_local_ip():
    s = socket(AF_INET, SOCK_DGRAM)
    try:
        # 這裡的 IP 是 Google Public DNS，不需要真的連通
        # 只是藉由測試連線來逼作業系統吐出目前作用中的區域網路 IP
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    except Exception:
        # 如果完全沒網路（例如單機離線），就退回 localhost
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip

class RSUProtocol(asyncio.DatagramProtocol):
    def __init__(self):
        # 將原本全域的緩衝區封裝進物件內部
        self.reassemble_buffer = {}

    def connection_made(self, transport):
        self.transport = transport
        print(f"--- RSU 已啟動，IP：{get_local_ip()}，正在監聽 UDP 連接埠 {RSU_PORT} ---")

        # 啟動背景巡邏任務，負責清除超時分片
        self.loop = asyncio.get_running_loop()
        self.cleanup_task = self.loop.create_task(self._cleanup_routine())

    async def _cleanup_routine(self):
        """背景巡邏任務：每秒檢查一次，清除超過 2 秒未集齊的分片"""
        TIMEOUT_SECONDS = 2.0  # 車聯網環境 2 秒沒收齊基本上就是掉包了
        
        while True:
            await asyncio.sleep(1.0)  # 每 1 秒執行一次檢查
            now = time.time()
            expired_keys = []
            
            for key, data in self.reassemble_buffer.items():
                if now - data['timestamp'] > TIMEOUT_SECONDS:
                    expired_keys.append(key)
            
            # 刪除超時的緩衝區資料
            for key in expired_keys:
                print(f"[超時清除] ID {key[0]} 的分片等候超時，已從記憶體釋放。")
                del self.reassemble_buffer[key]

    def datagram_received(self, data, addr):
        """
        這個函式會在每次收到 UDP 封包時被底層自動呼叫。
        注意：這裡面絕對不能有任何會 Block (阻塞) 的操作！
        """
        try:
            header_bytes = data[:4] # 前 4 個位元組是 header
            chunk_bytes = data[4:]  # 剩下的位元組是封包本身內容

            # Header (4 bytes)：目前分片序列號(1) | 總分片數(1) | 訊息ID(2)
            seq_num, total_frags, msg_id = parse.parse_header(header_bytes)
            if seq_num is None:
                print(f"[來自 {addr}] 收到無效的 header，忽略此訊息")
                return

            key = (msg_id, addr)
            
            # 如果是新訊息，初始化結構並打上時間戳印
            if key not in self.reassemble_buffer:
                self.reassemble_buffer[key] = {
                    'fragments': [None] * total_frags,
                    'timestamp': time.time()
                }
            else:
                # 如果是後續分片，更新時間戳印 (重新計算超時)
                self.reassemble_buffer[key]['timestamp'] = time.time()

            print(f"[來自 {addr}] 收到ID為 {msg_id} 的分片 ({seq_num}/{total_frags})。")
            # 存入分片
            self.reassemble_buffer[key]['fragments'][seq_num-1] = chunk_bytes

            # 檢查是否所有分片都已收到
            if all(fragment is not None for fragment in self.reassemble_buffer[key]['fragments']):
                print(f"[來自 {addr}] 已收到ID為 {msg_id} 的所有分片，開始背景驗證...")
                packet = b''.join(self.reassemble_buffer[key]['fragments'])  # 將分片列表中的位元組串接成完整封包
                del self.reassemble_buffer[key]
                
                # 關鍵點：將耗時的解析與 PQC 驗證任務丟到背景 Thread 執行
                # 並不會卡住目前的 datagram_received 接收下一個封包
                asyncio.create_task(self.process_full_packet(packet, addr))
        except Exception as e:
            print(f"datagram_received 發生致命錯誤: {e}")

    async def process_full_packet(self, packet, addr):
        """
        在背景執行的非同步任務
        """
        try:
            # asyncio.to_thread 會將 CPU 密集的 parse_packet 丟到 ThreadPool 執行
            # 這需要 Python 3.9+ 支援
            payload = await asyncio.to_thread(parse.parse_packet, packet)

            if payload:
                print(f"\n[來自 {addr}] 驗證成功，切換緊急綠燈！")
                print(f"總耗時：{time.time() - payload['full_timestamp']} 秒")
                print(f"\n完整訊息：")
                for key, value in payload.items():
                    if key == 'coreData':
                        print(f"{key}: ", end="{\n")
                        for sub_key, sub_value in value.items():
                            print(f"  {sub_key}: {sub_value}")
                        print("}")
                    else:
                        print(f"{key}: {value}")
                print()
            else:
                print(f"❌ [來自 {addr}] 驗證失敗，拒絕通行。\n")
        except Exception as e:
            print(f"處理封包時發生錯誤: {e}")

async def main():
    # 預先載入 CA 公鑰到記憶體 (稍後說明)
    parse.preload_ca_keys()

    loop = asyncio.get_running_loop()
    # 建立 UDP Endpoint 並綁定我們的 RSUProtocol
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: RSUProtocol(),
        local_addr=('0.0.0.0', RSU_PORT)
    )

    try:
        # 讓程式永遠保持運行
        await asyncio.Event().wait()
    except KeyboardInterrupt:
        print("\nRSU 已手動關閉")
    finally:
        transport.close()

if __name__ == "__main__":
    # 啟動 Asyncio Event Loop
    asyncio.run(main())