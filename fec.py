import struct, math, hashlib

# ─── XOR 協定常數（OBU/RSU 共用） ─────────────────────────────────────────────
XOR_MODE_FLAG  = 0x80   # total_frags byte 高位元：標識 XOR 模式
PARITY_SEQ     = 0      # seq_num = 0 專屬修復分片 FP
F1_MAX_XOR_UDP = 650    # F1 UDP 封包上限（約 600B，實際約 576~608B）
#   設計理由：封包掉包率與封包長度成指數正比；
#   F1 攜帶 ECQV 輕量認證資料（SRM + ECC + ECQV，約 500~600B），保持短小以極大化空中存活率。
#   F2..FN 承載 PQC 簽章 / 公鑰等重量資料，由 XOR 修復分片 FP 覆蓋保護。
# ─────────────────────────────────────────────────────────────────────────────

try:
    from OBU.fragment import MAX_UDP, APP_HDR, MAX_CHUNK
except ImportError:
    MAX_UDP   = 1400
    APP_HDR   = 4
    MAX_CHUNK = MAX_UDP - APP_HDR   # 1396


def _pad(block: bytes, length: int) -> bytes:
    """補零至指定長度"""
    return block + b'\x00' * (length - len(block))


# ─── 佈局計算 ─────────────────────────────────────────────────────────────────

def get_auth_len(packet: bytes) -> int:
    """
    計算 F1 輕量認證層所需的完整長度：
    msg_len (2B) | message (msg_len B) | ecc_sig_len (1B) | ecc_sig | ID (8B) | P_U (33B) | pqc_pub_hash (32B)
    確保 F1 完整涵蓋 ECQV 輕量驗證所需的所有欄位，避免截斷 pqc_pub_hash 造成簽章校驗失敗。
    """
    if len(packet) < 2:
        return len(packet)
    msg_len = struct.unpack('!H', packet[:2])[0]
    ecc_offset = 2 + msg_len
    if len(packet) < ecc_offset + 1:
        return len(packet)
    ecc_sig_len = struct.unpack('!B', packet[ecc_offset : ecc_offset + 1])[0]
    auth_len = 2 + msg_len + 1 + ecc_sig_len + 8 + 33 + 32
    return min(auth_len, len(packet))


def _xor_layout(packet_or_len):
    """
    計算 XOR 模式分片佈局，回傳 (f1_raw_size, n_heavy, heavy_block_len)。

    - F1 恰好承載完整的輕量認證區段 (get_auth_len)，保證 F1 獨立通過 ECC 驗證（閃黃燈）。
    - F1 UDP = APP_HDR(4B) + hash_commit(1 + n_heavy*32) + f1_raw ≤ F1_MAX_XOR_UDP (約 600B)。
    - F2..FN 均分剩餘的重量 PQC 簽章與公鑰資料，每片 UDP ≤ MAX_UDP (1400B)。
    """
    if isinstance(packet_or_len, (bytes, bytearray)):
        total_len   = len(packet_or_len)
        f1_raw_size = get_auth_len(packet_or_len)
    else:
        total_len   = int(packet_or_len)
        f1_raw_size = min(507, total_len)

    heavy_total = total_len - f1_raw_size
    if heavy_total <= 0:
        return f1_raw_size, 0, 0

    for n_heavy in range(2, 16):
        heavy_block = math.ceil(heavy_total / n_heavy)
        if heavy_block <= MAX_CHUNK:
            return f1_raw_size, n_heavy, heavy_block
    raise ValueError(f"[fec] 無法在 XOR 模式下佈局 {total_len}B 封包")


# ─── OBU 端：XOR 編碼 ─────────────────────────────────────────────────────────

def make_fragments_xor(packet: bytes, msg_id: int):
    """
    混合 XOR 分片設計（F1 輕量 + F2..FN XOR 保護）：

    F1（seq=1）：
      - 僅承載輕量認證資料（SRM JSON + ECC 簽章 + ECQV 憑證 ID）
      - UDP ≤ F1_MAX_XOR_UDP = 600B，空中 airtime 極短，存活率最高
      - 內含 SHA-256 雜湊承諾（覆蓋 F2..FN），RSU 可即時驗證後續分片完整性
      - 由 RSU 的 verify_f1_ecc() 驗證 → 觸發閃黃燈

    F2..FN（seq=2..N）：
      - 承載重量 PQC 簽章與公鑰，均勻切分，每片 UDP ≤ MAX_UDP = 1400B
      - 受 XOR 修復分片 FP 保護（任一重量片遺失皆可還原）

    FP（seq=0）：
      - XOR(F2..FN)，F1 不納入（F1 自身存活率足夠）
      - FP payload：heavy_total_len(4B) | block_len(4B) | xor_data(block_len B)

    App Header（4B，全片共用）：
      seq   (1B)：1..N 為資料片，0 為 FP
      total (1B)：(n_data & 0x7F) | XOR_MODE_FLAG (0x80)
      msg_id(2B)：訊息識別碼

    Returns:
      data_packets  (list[bytes])  : [F1, F2, ..., FN]，含 App Header
      parity_packet (bytes)        : FP，含 App Header；若無重量片則為 None
    """
    total_len = len(packet)
    f1_raw_size, n_heavy, heavy_block_len = _xor_layout(packet)
    n_data     = 1 + n_heavy
    total_wire = (n_data & 0x7F) | XOR_MODE_FLAG

    # ── F1 原始資料 ──────────────────────────────────────────────────────────
    f1_raw = packet[:f1_raw_size]
    heavy  = packet[f1_raw_size:]

    # ── 重量分片（F2..FN） ───────────────────────────────────────────────────
    heavy_frags = []
    for i in range(n_heavy):
        s = i * heavy_block_len
        e = min(s + heavy_block_len, len(heavy))
        heavy_frags.append(heavy[s:e] if s < len(heavy) else b'')

    # ── F1 雜湊承諾（覆蓋 F2..FN 的原始 chunk，供 RSU 即時驗證）─────────────
    hashes = struct.pack('!B', n_heavy)
    for chunk in heavy_frags:
        hashes += hashlib.sha256(chunk).digest()
    f1_with_commitment = hashes + f1_raw

    # ── 組裝 UDP 封包 ────────────────────────────────────────────────────────
    data_packets = []

    # F1
    f1_pkt = struct.pack('!BBH', 1, total_wire, msg_id) + f1_with_commitment
    assert len(f1_pkt) <= MAX_UDP, (
        f"[fec] F1 超過 MTU ({len(f1_pkt)}B > {MAX_UDP}B)"
    )
    assert len(f1_pkt) <= F1_MAX_XOR_UDP, (
        f"[fec] F1 超過輕量上限 ({len(f1_pkt)}B > {F1_MAX_XOR_UDP}B)"
    )
    data_packets.append(f1_pkt)

    # F2..FN
    for i, chunk in enumerate(heavy_frags):
        seq = i + 2
        pkt = struct.pack('!BBH', seq, total_wire, msg_id) + chunk
        assert len(pkt) <= MAX_UDP, (
            f"[fec] F{seq} 超過 MTU ({len(pkt)}B > {MAX_UDP}B)"
        )
        data_packets.append(pkt)

    # ── FP = XOR(F2..FN) ─────────────────────────────────────────────────────
    parity_packet = None
    if n_heavy > 0 and len(heavy) > 0:
        parity = bytearray(heavy_block_len)
        for chunk in heavy_frags:
            padded = _pad(chunk, heavy_block_len)
            for j, b in enumerate(padded):
                parity[j] ^= b

        fp_payload = struct.pack('!II', len(heavy), heavy_block_len) + bytes(parity)
        fp_pkt     = struct.pack('!BBH', PARITY_SEQ, total_wire, msg_id) + fp_payload
        assert len(fp_pkt) <= MAX_UDP, (
            f"[fec] FP 超過 MTU ({len(fp_pkt)}B > {MAX_UDP}B)"
        )
        parity_packet = fp_pkt

    return data_packets, parity_packet


def send_fragment_xor(sock, msg_id: int, packet: bytes, dst: tuple):
    """
    XOR 模式發送（策略 C）：
      F1 (小) → F2 (大) → F3 (大) [→ F4 (大) for Full mode] → FP (parity)
      共 n_data+1 個 UDP 包，不發備用 F1。

    實驗對照：
      --mode none → 策略 A（無冗餘基線）
      --mode dup  → 策略 B（F1 複製）
      --mode xor  → 策略 C（本函式）
    """
    data_pkts, fp_pkt = make_fragments_xor(packet, msg_id)
    n = len(data_pkts)

    for i, pkt in enumerate(data_pkts):
        label = "F1(輕量)" if i == 0 else f"F{i+1}(重量)"
        sock.sendto(pkt, dst)
        print(f"  [XOR] {label}  {len(pkt)}B / {MAX_UDP}B")

    if fp_pkt is not None:
        sock.sendto(fp_pkt, dst)
        print(f"  [XOR] FP(修復)  {len(fp_pkt)}B / {MAX_UDP}B")
    print()


# ─── RSU 端：XOR 解碼 ─────────────────────────────────────────────────────────

def recover_xor_heavy(received_heavy: dict, parity_payload: bytes,
                      n_heavy: int, f1_raw: bytes) -> bytes:
    """
    XOR 還原缺失的重量分片，並拼接 F1 回傳完整封包。

    Args:
      received_heavy  : {0-indexed: raw_bytes}，0 = F2，1 = F3，...
                        長度必須恰好 = n_heavy - 1（缺一片）
      parity_payload  : FP 的 chunk_bytes（去掉 4B App Header）
      n_heavy         : 重量分片總數（不含 F1）
      f1_raw          : F1 原始資料（verify_f1_ecc 提取的 raw_f1）

    Returns:
      bytes : F1_raw + F2 + F3 + ...（完整認證封包，已截去補零）
      None  : 輸入異常，無法還原
    """
    if len(received_heavy) != n_heavy - 1:
        return None
    if len(parity_payload) < 8:
        return None

    heavy_total = struct.unpack('!I', parity_payload[0:4])[0]
    block_len   = struct.unpack('!I', parity_payload[4:8])[0]
    xor_data    = bytearray(parity_payload[8: 8 + block_len])

    if len(xor_data) < block_len:
        return None

    # XOR 還原：missing_block = xor_data XOR all_received
    for blk in received_heavy.values():
        padded = _pad(blk, block_len)
        for j in range(block_len):
            xor_data[j] ^= padded[j]

    missing_idx = next(i for i in range(n_heavy) if i not in received_heavy)

    all_blocks = dict(received_heavy)
    all_blocks[missing_idx] = bytes(xor_data)

    # 重組 heavy 區段並截去補零
    heavy_raw = b''.join(all_blocks[i] for i in range(n_heavy))[:heavy_total]

    return f1_raw + heavy_raw
