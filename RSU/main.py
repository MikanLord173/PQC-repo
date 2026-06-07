import logging, json, time, os, asyncio, statistics
import RSU.parse as parse
from dotenv import load_dotenv
from socket import *
from datetime import datetime

load_dotenv()

# 配置參數
RSU_PORT = int(os.getenv("RSU_PORT", 5005))     # 自定義連接埠
BUFFER_SIZE = 4096  # 預留稍大緩衝區，為之後的 PQC 簽章做準備

# 要改成用 (msg_id, addr) 當 key，這樣就不會有不同車輛的訊息混在一起了
reassemble_buffer = {}  # 用於存儲分片資料的緩衝區，key 為 (msg_id, addr)，value 為分片列表

# 自定義 JSON 格式的 Logger
class JSONFormatter(logging.Formatter):
    def _clean_bytes(self, obj):
        """遞迴檢查物件，將所有 bytes 強制轉換為字串"""
        if isinstance(obj, dict):
            return {k: self._clean_bytes(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._clean_bytes(v) for v in obj]
        elif isinstance(obj, bytes):
            try:
                # 試著當作文字解碼，並去掉結尾的空字元
                return obj.decode('utf-8').strip(chr(0))
            except UnicodeDecodeError:
                # 如果是公鑰、簽章等非文字的 bytes，就轉成 hex 碼記錄
                return f"hex:{obj.hex()}"
        return obj

    def format(self, record):
        log_record = {
            "time": datetime.fromtimestamp(record.created).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
            "level": record.levelname,
            "message": record.getMessage()
        }
        if hasattr(record, 'extra_data'):
            # 呼叫防禦型過濾器，確保絕對不會有 bytes 混進去
            clean_extra = self._clean_bytes(record.extra_data)
            log_record.update(clean_extra)
            
        return json.dumps(log_record, ensure_ascii=False) # ensure_ascii=False 可正常顯示中文

# 初始化 Logger
logger = logging.getLogger("RSU_Logger")
logger.setLevel(logging.INFO)

# 寫入檔案 (按天自動切割檔案，避免單一檔案過大)
from logging.handlers import TimedRotatingFileHandler
file_handler = TimedRotatingFileHandler("rsu_traffic.jsonl", when="midnight", backupCount=7)
file_handler.setFormatter(JSONFormatter())
logger.addHandler(file_handler)

# 如果也想在終端機看到傳統文字，可以再加一個 StreamHandler
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter('[%(levelname)s] %(message)s'))
logger.addHandler(console_handler)

class TrafficStats:
    def __init__(self):
        self.reset()

    def reset(self):
        # 紀錄這段期間內出現過的 OBU ID
        self.connected_obus = set()
        # 總處理封包數與成功數
        self.total_processed = 0
        self.success_count = 0
        # 紀錄所有成功的驗證耗時
        self.latencies = []

    def add_record(self, obu_id, is_success, latency=None):
        if obu_id is None:
            obu_id = "Unknown"
        elif isinstance(obu_id, bytes):
            try:
                obu_id = obu_id.decode('utf-8').strip(chr(0))
            except:
                obu_id = "Unknown"

        self.connected_obus.add(str(obu_id))
        self.total_processed += 1
        if is_success:
            self.success_count += 1
        if latency is not None:
            self.latencies.append(latency)

# 建立一個全域的統計物件
global_stats = TrafficStats()

async def periodic_summary_reporter(interval_seconds=60):
    """每隔 interval_seconds 結算一次數據並輸出"""
    summary_file = "RSU/reports/rsu_summary_report.txt"
    
    # 寫入檔案標頭 (如果是第一次建立)
    if not os.path.exists(summary_file):
        with open(summary_file, "w", encoding="utf-8") as f:
            f.write("=== RSU 定時效能統整報表 ===\n")

    while True:
        await asyncio.sleep(interval_seconds)
        
        now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        total = global_stats.total_processed
        success = global_stats.success_count
        obus = list(global_stats.connected_obus)
        lats = global_stats.latencies
        
        # 1. 準備報表內容
        report_lines = [
            f"\n[{now_str}] 週期結算 (過去 {interval_seconds} 秒):",
            f"  - 總處理封包 : {total} 筆",
        ]
        
        if total > 0:
            success_rate = (success / total) * 100
            report_lines.append(f"  - 成功通過數 : {success} 筆 ({success_rate:.1f}%)")
            report_lines.append(f"  - 連線的車輛 : {len(obus)} 台 ({', '.join(obus[:5])}{'...' if len(obus)>5 else ''})")
            
            if lats:
                avg_lat = statistics.mean(lats)
                max_lat = max(lats)
                min_lat = min(lats)
                report_lines.append(f"  - 驗證耗時   : 平均 {avg_lat:.4f}s | 最快 {min_lat:.4f}s | 最慢 {max_lat:.4f}s")
        else:
            report_lines.append("  - 狀態       : 閒置中，無封包進站")

        report_text = "\n".join(report_lines)
        
        # 2. 輸出到終端機 (給你看直觀狀況)
        print(f"\n\033[96m{report_text}\033[0m\n") # 使用 ANSI 亮青色讓它在終端機中很顯眼
        
        # 3. 輸出到統整檔案 (給未來寫報告用)
        with open(summary_file, "a", encoding="utf-8") as f:
            f.write(report_text + "\n")
            
        # 4. 重置統計數據，開始下一個週期 (Windowed 模式)
        # 如果你想記錄「從開機到現在的總和」，就把這行拿掉
        global_stats.reset()

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
                # 超時丟棄時的記錄 (在 _cleanup_routine 中)
                logger.warning(
                    "分片重組超時，已丟棄",
                    extra={"extra_data": {
                        "event": "TIMEOUT_DROP",
                        "msg_id": key[0],
                        "drop_reason": "Missing fragments after 2.0s"
                    }}
                )
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
                # 非法分片 header
                logger.warning(
                    "非法分片 header，已丟棄",
                    extra={"extra_data": {
                        "event": "INVALID_HEADER",
                        "msg_id": msg_id,
                        "drop_reason": "Invalid fragment header"
                    }}
                )
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

            logger.info(
                f"收到ID為 {msg_id} 的分片 ({seq_num}/{total_frags})",
                extra={"extra_data": {
                    "event": "FRAGMENT_RECEIVED",
                    "msg_id": msg_id,
                }}
            )
            # 存入分片
            self.reassemble_buffer[key]['fragments'][seq_num-1] = chunk_bytes

            # 檢查是否所有分片都已收到
            if all(fragment is not None for fragment in self.reassemble_buffer[key]['fragments']):
                # 驗證成功時的記錄
                logger.info(
                    f"集齊來自 ID = {msg_id} 的所有分片",
                    extra={"extra_data": {
                        "event": "ALL_FRAGMENTS_COLLECTED",
                        "msg_id": msg_id,
                    }}
                )
                packet = b''.join(self.reassemble_buffer[key]['fragments'])  # 將分片列表中的位元組串接成完整封包
                del self.reassemble_buffer[key]
                
                # 關鍵點：將耗時的解析與 PQC 驗證任務丟到背景 Thread 執行
                # 並不會卡住目前的 datagram_received 接收下一個封包
                asyncio.create_task(self.process_full_packet(packet, addr))
        except Exception as e:
            logger.error(
                    f"發生致命錯誤: {e}",
                    extra={"extra_data": {
                        "event": "FATAL_ERROR",
                        "msg_id": msg_id,
                    }}
                )

    async def process_full_packet(self, packet, addr):
        """
        在背景執行的非同步任務
        """
        try:
            # asyncio.to_thread 會將 CPU 密集的 parse_packet 丟到 ThreadPool 執行
            # 這需要 Python 3.9+ 支援
            payload = await asyncio.to_thread(parse.parse_packet, packet=packet, logger=logger)

            if payload:
                # 驗證成功時的記錄
                obu_id = payload.get("stationID")
                process_duration = time.time() - payload['full_timestamp']
                logger.info(
                    "授權緊急車輛通行",
                    extra={"extra_data": {
                        "event": "GRANT_GREEN_LIGHT",
                        "obu_id": obu_id,
                        "verify_duration_sec": process_duration
                    }}
                )
                global_stats.add_record(obu_id=obu_id, is_success=True, latency=process_duration)
            else:
                global_stats.add_record(obu_id="Unknown", is_success=False)
        except Exception as e:
            print(f"處理封包時發生錯誤: {e}")

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

async def main():
    # 預先載入 CA 公鑰到記憶體 (稍後說明)
    parse.preload_ca_keys()

    loop = asyncio.get_running_loop()
    # 啟動定時統整任務，設定為每 10 秒輸出一次 (測試時可以設短一點)
    loop.create_task(periodic_summary_reporter(interval_seconds=10))
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