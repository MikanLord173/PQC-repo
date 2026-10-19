import struct, time, hashlib, math

# ─── MTU 嚴格限制 ───────────────────────────────────────────────────────────
# 每個 sendto() 的 UDP payload 上限（含 4B App Header）
# 1500B Ethernet MTU - 20B IP - 8B UDP = 1472B 理論最大值
# 取 1400B 保留 72B 安全邊際（DSRC/C-V2X 無線鏈路協議開銷）
MAX_UDP   = 1400            # 嚴格每片 UDP 封包上限（bytes）
APP_HDR   = 4               # App Header: seq(1B) | total(1B) | msg_id(2B)
MAX_CHUNK = MAX_UDP - APP_HDR  # 1396B，非 F1 片最大 payload
# ────────────────────────────────────────────────────────────────────────────


def _min_fragments(total_len: int) -> int:
    """
    計算在 MAX_UDP 嚴格限制下，承載 total_len 位元組所需的最少分片數。

    推導：
    - F1 需額外承載雜湊承諾 = 1 + (N-1)*32 bytes
    - F1 最大內容 = MAX_CHUNK - hash_commit = 1395 - (N-1)*32
    - 非 F1 每片最大內容 = MAX_CHUNK = 1396
    - 條件：[1395 - (N-1)*32] + (N-1)*1396 ≥ total_len
    →  N ≥ 1 + ceil((total_len - 1395) / (MAX_CHUNK - 32))
    """
    HASH_COMMIT_OVERHEAD = 32  # 每增一片，F1 多承載 32B SHA-256
    F1_BASE_OVERHEAD     = 1   # num_hashes 欄位（1B）
    F1_MAX_SINGLE        = MAX_CHUNK - F1_BASE_OVERHEAD  # = 1395

    if total_len <= F1_MAX_SINGLE:
        return 1

    effective_per_extra_frag = MAX_CHUNK - HASH_COMMIT_OVERHEAD  # = 1364
    return 1 + math.ceil((total_len - F1_MAX_SINGLE) / effective_per_extra_frag)


def make_fragments(packet: bytes, msg_id: int = 1):
    """
    嚴格 MTU 合規非均勻動態切片（每個 UDP 封包含 App Header ≤ MAX_UDP=1400B）：

    1. 動態計算最少分片數，消除微型尾片，零 IP 二次碎片化。
    2. F1 填滿至嚴格 MTU 上界（帶雜湊承諾後恰好 = MAX_UDP）。
    3. 其餘片均勻瓜分剩餘資料，每片嚴格 ≤ MAX_CHUNK。
    4. 內建 assert 自動驗算，任何超限會即時報錯。

    封包大小估算（參考值，實際依 JSON payload 而異）：
      Full 模式  ~4246B → 4 片（F1≈1400B, F2~F4≈987B each）
      Short 模式 ~2934B → 3 片（F1≈1400B, F2~F3≈802B each）
    """
    total_len   = len(packet)
    total_frags = _min_fragments(total_len)

    # 1. 計算 F1 雜湊承諾佔用
    hash_commit_size = 1 + (total_frags - 1) * 32  # num_hashes(1B) + hashes

    # 2. F1 可承載的最大原始資料量（確保 F1 UDP 恰好 ≤ MAX_UDP）
    f1_max_content = MAX_CHUNK - hash_commit_size

    # 3. 切出 F1 原始資料（盡量填滿）
    f1_content_len = min(f1_max_content, total_len)
    raw_chunks = [packet[:f1_content_len]]

    # 4. 均勻切分剩餘資料給 F2..FN
    if total_frags > 1:
        remaining    = packet[f1_content_len:]
        other_count  = total_frags - 1
        chunk_size   = math.ceil(len(remaining) / other_count)
        # 雙重保護：ceil 結果不得超過 MAX_CHUNK
        chunk_size   = min(chunk_size, MAX_CHUNK)
        for i in range(other_count):
            start = i * chunk_size
            end   = min(start + chunk_size, len(remaining))
            if start < len(remaining):
                raw_chunks.append(remaining[start:end])

    # 5. 計算後續分片 (F2, F3...) 的 SHA-256 雜湊承諾
    #    格式：num_hashes (1B) | H_2 (32B) | H_3 (32B) ...
    tail_hashes = struct.pack('!B', total_frags - 1)
    for chunk in raw_chunks[1:]:
        tail_hashes += hashlib.sha256(chunk).digest()

    # 將雜湊承諾注入 F1 開頭
    f1_with_commitment = tail_hashes + raw_chunks[0]

    # 6. 組裝最終 UDP 封包（含 App Header）
    packets = []
    for i in range(total_frags):
        seq_num    = i + 1
        chunk      = f1_with_commitment if seq_num == 1 else raw_chunks[i]
        app_header = struct.pack('!BBH', seq_num, total_frags, msg_id)
        udp_pkt    = app_header + chunk

        # 嚴格 MTU 驗算（上線後可移除，開發期保留）
        assert len(udp_pkt) <= MAX_UDP, (
            f"[fragment.py] ❌ 分片 {seq_num}/{total_frags} 超過 MTU！"
            f"({len(udp_pkt)}B > {MAX_UDP}B) "
            f"total_len={total_len}, hash_commit={hash_commit_size}"
        )
        packets.append(udp_pkt)

    return packets


def send_fragment(sock, msg_id, packet, dst: tuple, duplicate_f1: bool = True):
    """
    依照分片雜湊承諾發送分片。

    duplicate_f1=True  → 尾端多發一次 F1 備用包（策略 B，預設）
    duplicate_f1=False → 不發任何備用包（策略 A，無冗餘基線）
    """
    packets     = make_fragments(packet, msg_id)
    total_frags = len(packets)

    for i, udp_packet in enumerate(packets):
        seq_num = i + 1
        sock.sendto(udp_packet, dst)
        print(f"  發送碎片 {seq_num}/{total_frags}，大小: {len(udp_packet)}B / {MAX_UDP}B 上限")

    # 尾端多發一次 F1 備用包（時間分集防掉包）
    if duplicate_f1 and total_frags > 0:
        sock.sendto(packets[0], dst)
        print(f"  發送碎片 1/{total_frags} [備用 F1]，大小: {len(packets[0])}B")

    print()