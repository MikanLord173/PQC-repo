import struct, time
from OBU.encode_packet import gen_packet

MAX_PAYLOAD = 1400  # 為了保險，我們設 1400，預留空間給 Header

def send_fragment(sock, msg_id, packet, dst: tuple):

    total_frags = (len(packet) + MAX_PAYLOAD - 1) // MAX_PAYLOAD    # 計算需要分幾片

    for i in range(total_frags):
        seq_num = i + 1

        # 取得切片內容
        start = i * MAX_PAYLOAD
        end = min(start + MAX_PAYLOAD, len(packet))
        chunk = packet[start:end]
        
        # Header (4 bytes)：目前分片序列號(1) | 總分片數(1) | 訊息ID(2)
        app_header = struct.pack('!BBH', seq_num, total_frags, msg_id)
        
        # 合併發送
        udp_packet = app_header + chunk
        sock.sendto(udp_packet, dst)
        print(f"發送碎片 {seq_num}/{total_frags}, 大小: {len(udp_packet)} bytes")
    print()