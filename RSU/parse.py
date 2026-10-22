import struct, oqs, json, time, hashlib, os
from collections import OrderedDict
from ecdsa import NIST256p, VerifyingKey
import ecdsa.ellipticcurve as ellipticcurve
from cryptography.hazmat.primitives import serialization

PQC_SIG_NAME = "ML-DSA-44"

# 純記憶體 LRU 快取：支援多路口隔離與有線骨幹預同步 TTL
# 每路口容量上限設為 500 台車 (僅佔用約 150 KB RAM)，徹底消除內存耗竭 DoS
MAX_CACHE_SIZE = 500
INTERSECTION_KEY_CACHE = {}
INTERSECTION_PQC_CACHE = {}

def get_key_cache(rsu_id=1):
    if rsu_id not in INTERSECTION_KEY_CACHE:
        INTERSECTION_KEY_CACHE[rsu_id] = OrderedDict()
    return INTERSECTION_KEY_CACHE[rsu_id]

def get_pqc_cache(rsu_id=1):
    if rsu_id not in INTERSECTION_PQC_CACHE:
        INTERSECTION_PQC_CACHE[rsu_id] = OrderedDict()
    return INTERSECTION_PQC_CACHE[rsu_id]

# 預設單路口相容視圖
MEMORY_KEY_CACHE = get_key_cache(1)
PQC_PUB_CACHE    = get_pqc_cache(1)

def query_key_cache(cache_key, rsu_id=1):
    cache = get_key_cache(rsu_id)
    if cache_key not in cache:
        return None
    entry = cache[cache_key]
    if isinstance(entry, dict) and "expire_at" in entry:
        if entry["expire_at"] is not None and time.time() > entry["expire_at"]:
            del cache[cache_key]
            return None
        cache.move_to_end(cache_key)
        return entry["vk"]
    cache.move_to_end(cache_key)
    return entry

def query_pqc_pub_cache(obu_id_raw, rsu_id=1):
    cache = get_pqc_cache(rsu_id)
    if obu_id_raw not in cache:
        return None
    entry = cache[obu_id_raw]
    if isinstance(entry, dict) and "expire_at" in entry:
        if entry["expire_at"] is not None and time.time() > entry["expire_at"]:
            del cache[obu_id_raw]
            return None
        cache.move_to_end(obu_id_raw)
        return entry["pub"]
    cache.move_to_end(obu_id_raw)
    return entry

def update_key_cache(cache_key, vk, rsu_id=1, expire_at=None):
    """驗證通過後才寫入：更新並維護 LRU 隊列上限"""
    cache = get_key_cache(rsu_id)
    cache[cache_key] = {"vk": vk, "expire_at": expire_at} if expire_at else vk
    cache.move_to_end(cache_key)
    if len(cache) > MAX_CACHE_SIZE:
        cache.popitem(last=False)

def update_pqc_pub_cache(obu_id_raw, pqc_pub, rsu_id=1, expire_at=None):
    """記憶體快取車輛的 PQC 公鑰 (1312 bytes)"""
    cache = get_pqc_cache(rsu_id)
    cache[obu_id_raw] = {"pub": pqc_pub, "expire_at": expire_at} if expire_at else pqc_pub
    cache.move_to_end(obu_id_raw)
    if len(cache) > MAX_CACHE_SIZE:
        cache.popitem(last=False)

def inject_prewarm_cache(target_rsu_id: int, obu_id_raw: bytes, P_U_bytes: bytes, vk, pqc_pub: bytes, expire_at: float = None):
    """
    路側有線骨幹 (Backhaul) 預同步注入：
    直接將 RSU-1 算好的 vk (Q_U) 與 PQC 公鑰注入目標下游路口的記憶體快取。
    下游路口免算點乘重構，達成零冷啟動！
    """
    cache_key = (obu_id_raw, P_U_bytes)
    update_key_cache(cache_key, vk, rsu_id=target_rsu_id, expire_at=expire_at)
    update_pqc_pub_cache(obu_id_raw, pqc_pub, rsu_id=target_rsu_id, expire_at=expire_at)

def purge_obu_cache(obu_id, rsu_id=1):
    """
    清除單一車輛在指定路口的快取 (PQC 公鑰 + ECQV 重構公鑰)。
    用於 Short 模式驗簽失敗：視為快取過期/不同步，清除後回 status=6 要求車輛以 Full 模式補憑證。
    obu_id 可為字串 (如 "AMB-217") 或封包內的 8B 原始 ID (不足補 \\x00)。
    """
    if isinstance(obu_id, str):
        obu_id_raw = obu_id.encode('utf-8').ljust(8, b'\x00')[:8]
    else:
        obu_id_raw = bytes(obu_id)

    get_pqc_cache(rsu_id).pop(obu_id_raw, None)
    # ECQV 公鑰快取以 (obu_id_raw, P_U) 為鍵，同一車可能有多個 P_U，全部清除
    key_cache = get_key_cache(rsu_id)
    for cache_key in [k for k in key_cache if k[0] == obu_id_raw]:
        del key_cache[cache_key]

def clear_all_caches(rsu_id=None):
    """清空快取 (供單元測試與環境重置使用)"""
    if rsu_id is None:
        INTERSECTION_KEY_CACHE.clear()
        INTERSECTION_PQC_CACHE.clear()
    else:
        if rsu_id in INTERSECTION_KEY_CACHE:
            INTERSECTION_KEY_CACHE[rsu_id].clear()
        if rsu_id in INTERSECTION_PQC_CACHE:
            INTERSECTION_PQC_CACHE[rsu_id].clear()

LAST_VERIFIED_AUTH = {}
LAST_PARSE_STATUS  = "OK"

XOR_MODE_FLAG = 0x80   # total_frags byte 高位元：標識 XOR 模式封包

def parse_header(header_bytes):
    """
    Header (4 bytes)：序號(1) | 總分片數(1) | 訊息ID(2)

    total_frags byte 編碼：
      bit7 (0x80) = XOR_MODE_FLAG → 1 表示 XOR 模式，0 表示 DUP/一般模式
      bit6..0     = 實際分片數（1~127）

    Returns:
      (seq_num, total_frags, msg_id, is_xor)
      解析失敗時回傳 (None, None, None, False)
    """
    try:
        seq_num, total_wire, msg_id = struct.unpack('!BBH', header_bytes)
    except struct.error as e:
        print(f"Header 解析失敗：{e}")
        return None, None, None, False
    is_xor      = bool(total_wire & XOR_MODE_FLAG)
    total_frags = total_wire & 0x7F
    return seq_num, total_frags, msg_id, is_xor

def reconstruct_obu_pubkey(obu_id_bytes: bytes, P_U_bytes: bytes, pqc_pub_hash: bytes):
    """
    ECQV 公鑰重構公式：
      1. e = SHA256(ID || P_U || pqc_pub_hash) mod n
      2. Q_U = e * P_U + Q_CA
    """
    curve = NIST256p
    n = curve.order

    # 1. 讀取 CA ECC 根公鑰 Q_CA
    with open("RSU/keys/ca_ecc_pub.key", "rb") as f:
        ca_ecc_pub_obj = serialization.load_der_public_key(f.read())
    ca_numbers = ca_ecc_pub_obj.public_numbers()
    Q_CA = ellipticcurve.PointJacobi(curve.curve, ca_numbers.x, ca_numbers.y, 1)

    # 2. 算糾纏值 e
    entangled_data = obu_id_bytes + P_U_bytes + pqc_pub_hash
    e = int(hashlib.sha256(entangled_data).hexdigest(), 16) % n

    # 3. 執行橢圓曲線乘加運算
    P_U = ellipticcurve.PointJacobi.from_bytes(curve.curve, P_U_bytes)
    Q_U = (e * P_U) + Q_CA

    return VerifyingKey.from_public_point(Q_U, curve=NIST256p)

def verify_f1_ecc(f1_chunk, rsu_id=1):
    """
    從 F1 碎片中提取分片承諾雜湊清單、BSM 訊息與 ECC 簽章並進行快速驗證
    F1 佈局：
      num_hashes (1B) | [H_2 (32B)] | [H_3 (32B)]... |
      msg_len (2B) | msg | ecc_sig_len (1B) | ecc_sig | ID (8B) | P_U (33B) | pqc_pub_hash (32B)
    """
    try:
        # 1. 提取後續分片雜湊承諾 (Fragment Commitment)
        start = 0
        num_hashes = int(struct.unpack('!B', f1_chunk[:1])[0])
        start += 1
        expected_hashes = {}
        for idx in range(num_hashes):
            seq = idx + 2
            expected_hashes[seq] = f1_chunk[start : start + 32]
            start += 32

        # 2. 提取 Payload
        end = start + 2
        msg_len = int(struct.unpack('!H', f1_chunk[start:end])[0])
        start = end
        end += msg_len
        payload_bytes = f1_chunk[start:end]

        # 提取 OBU ECC 簽章
        start = end
        end += 1
        ecc_sig_len = int(struct.unpack('!B', f1_chunk[start:end])[0])
        start = end
        end += ecc_sig_len
        ecc_sig = f1_chunk[start:end]

        # 提取 ECQV 輕量憑證開頭：ID (8B) | P_U (33B) | pqc_pub_hash (32B)
        start = end
        end += 8
        obu_id_raw = f1_chunk[start:end]
        obu_id_str = obu_id_raw.decode('utf-8').rstrip('\x00')

        start = end
        end += 33
        P_U_bytes = f1_chunk[start:end]

        start = end
        end += 32
        pqc_pub_hash = f1_chunk[start:end]

        # 1. 優先查純記憶體快取 (支援有線骨幹預熱注入之 vk，0 ns，無磁碟 I/O，免重算 Q_U 點乘)
        cache_key = (obu_id_raw, P_U_bytes) # 複合金鑰
        vk = query_key_cache(cache_key, rsu_id=rsu_id)
        if vk is not None:
            pass  # 命中快取！免重構 Q_U 點乘！
        else:
            # 未命中則現場從 33-byte P_U 自癒重構 (徹底消除狀態失步)
            vk = reconstruct_obu_pubkey(obu_id_raw, P_U_bytes, pqc_pub_hash)

        # 先驗證簽章！
        if not vk.verify(ecc_sig, payload_bytes, hashfunc=hashlib.sha256):
            return False, obu_id_str, None, None, None

        # 3. 簽章通過才安全寫入
        update_key_cache(cache_key, vk, rsu_id=rsu_id)

        # 檢查時間戳防重放攻擊 (150ms)
        f1_data = json.loads(payload_bytes.decode('utf-8'))
        f1_latency = time.time() - f1_data.get("full_timestamp", 0)
        if f1_latency > 0.15:
            print(f"F1 訊息已過期 (延遲 {f1_latency*1000:.1f}ms > 150ms)，疑似重放攻擊")
            return False, obu_id_str, None, None, None

        # raw_f1_data 為扣除開頭承諾標頭後的純粹分片資料 (供後續組裝)
        raw_f1_data = f1_chunk[1 + num_hashes * 32 :]
        return True, obu_id_str, payload_bytes, expected_hashes, raw_f1_data

    except Exception as e:
        print(f"F1 ECC 簽章驗證失敗：{e}")
        return False, None, None, None, None

def parse_packet(packet, rsu_id=1):
    """
    完整封包解析與驗證：
    封包格式：
      msg_len (2B) | payload | ecc_sig_len (1B) | ecc_sig |
      ID (8B) | P_U (33B) | pqc_pub_hash (32B) | ca_pqc_sig_len (2B) | ca_pqc_sig |
      pqc_pub_len (2B) | pqc_pub | pqc_sig_len (2B) | pqc_sig
    """
    global LAST_VERIFIED_AUTH, LAST_PARSE_STATUS
    # 【修正】每次解析前重設狀態，避免沿用上一個封包的結果。
    # 否則 ECC 驗簽失敗或解析例外 (未設定狀態的失敗路徑) 會殘留前一包的 FULL_SIG_FAIL，
    # 導致 RSU 誤將無辜車輛加入密碼學硬黑名單。
    LAST_PARSE_STATUS = "PENDING"
    try:
        end = 2
        msg_len = int(struct.unpack('!H', packet[:end])[0])
        start = end
        end += msg_len
        payload_bytes = packet[start:end]

        # ECC 簽章
        start = end
        end += 1
        obu_ecc_sig_len = int(struct.unpack('!B', packet[start:end])[0])
        start = end
        end += obu_ecc_sig_len
        obu_ecc_sig = packet[start:end]

        # ECQV 憑證欄位
        start = end
        end += 8
        obu_id_raw = packet[start:end]
        obu_id_str = obu_id_raw.decode('utf-8').rstrip('\x00')
        start = end
        end += 33
        P_U_bytes = packet[start:end]
        start = end
        end += 32
        pqc_pub_hash = packet[start:end]
        # 提取 OBU 的 PQC 公鑰 (若 pqc_pub_len == 0 則為 Short 模式，由記憶體快取還原)
        start = end
        end += 2
        pqc_pub_len = int(struct.unpack('!H', packet[start:end])[0])
        is_short_mode = (pqc_pub_len == 0)
        
        if is_short_mode:
            # 二次通訊 (Short 模式)：從記憶體快取還原 PQC 公鑰
            obu_pqc_pub = query_pqc_pub_cache(obu_id_raw, rsu_id=rsu_id)
            if obu_pqc_pub is not None:
                pass
            else:
                LAST_PARSE_STATUS = "NEED_CERT"
                print(f"收到 Short 封包但路口 {rsu_id} 記憶體查無快取公鑰 (車輛: {obu_id_str})，需退回 Full 模式補憑證")
                return None
        else:
            # 首次通訊 (Full 模式)：接收完整 1312B 公鑰
            start = end
            end += pqc_pub_len
            obu_pqc_pub = packet[start:end]

            # 1. 雜湊綁定檢查 (防 DoS 注入攻擊)：檢查完整公鑰是否吻合 F1 裡的 pqc_pub_hash
            if hashlib.sha256(obu_pqc_pub).digest() != pqc_pub_hash:
                LAST_PARSE_STATUS = "PQC_PUB_HASH_MISMATCH"
                print(f"PQC 公鑰雜湊不符，疑似偽造公鑰攻擊！(車輛: {obu_id_str})")
                return None

            # 【修正】此處僅完成雜湊綁定檢查，尚未驗證 ML-DSA / ECC 簽章，
            # 因此不在這裡寫入快取；改到所有簽章驗證通過後才寫入 (真正的 Verify-then-Cache)。

        # 2. 提取 OBU 的 PQC 簽章
        start = end
        end += 2
        obu_pqc_sig_len = int(struct.unpack('!H', packet[start:end])[0])
        start = end
        end += obu_pqc_sig_len
        obu_pqc_sig = packet[start:end]

        # 3. 驗證 OBU 的 PQC 簽章 (ML-DSA-44 抗量子安全)
        with oqs.Signature(PQC_SIG_NAME) as verifier:
            if not verifier.verify(payload_bytes, obu_pqc_sig, obu_pqc_pub):
                if is_short_mode:
                    # Short 模式公鑰來自本地快取，快取若不同步或損毀可能導致失敗，不可斷定為惡意
                    LAST_PARSE_STATUS = "SHORT_SIG_FAIL"
                    print(f"OBU Short 模式後量子簽章驗證失敗 (可能是快取過期/不同步)！(車輛: {obu_id_str})")
                else:
                    # Full 模式公鑰經由 F1 雜湊綁定承諾，簽章失敗構成強偽造證據
                    LAST_PARSE_STATUS = "FULL_SIG_FAIL"
                    print(f"OBU Full 模式後量子簽章驗證失敗！(車輛: {obu_id_str})")
                return None

        # 驗證 OBU 的 ECC 簽章
        cache_key = (obu_id_raw, P_U_bytes)
        vk = query_key_cache(cache_key, rsu_id=rsu_id)
        if vk is not None:
            pass  # 命中快取！免重算 Q_U
        else:
            vk = reconstruct_obu_pubkey(obu_id_raw, P_U_bytes, pqc_pub_hash)
        if not vk.verify(obu_ecc_sig, payload_bytes, hashfunc=hashlib.sha256):
            LAST_PARSE_STATUS = "ECC_SIG_FAIL"
            print(f"OBU ECC 簽章驗證失敗(車輛: {obu_id_str})")
            return None
        update_key_cache(cache_key, vk, rsu_id=rsu_id)
        # Full 模式：ML-DSA-44 與 ECC 簽章皆已通過，此時才將 PQC 公鑰寫入快取 (Verify-then-Cache)
        if not is_short_mode:
            update_pqc_pub_cache(obu_id_raw, obu_pqc_pub, rsu_id=rsu_id)

        # 記錄已驗證認證資料供骨幹預熱使用
        LAST_VERIFIED_AUTH = {
            "obu_id_raw": obu_id_raw,
            "obu_id_str": obu_id_str,
            "P_U_bytes": P_U_bytes,
            "vk": vk,
            "pqc_pub": obu_pqc_pub
        }
        LAST_PARSE_STATUS = "OK"

        print(f"ECQV + ML-DSA-44 驗證全部通過")
        return json.loads(payload_bytes.decode('utf-8'))

    except Exception as e:
        LAST_PARSE_STATUS = "PARSE_ERROR"
        print(f"封包解析失敗：{e}")
        return None