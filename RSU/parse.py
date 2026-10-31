import struct, oqs, json, time, hashlib, os
from collections import OrderedDict
from ecdsa import NIST256p, VerifyingKey
import ecdsa.ellipticcurve as ellipticcurve
from cryptography.hazmat.primitives import serialization
import pki


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

def ecqv_cache_key(obu_id_raw: bytes, role: int, P_U_bytes: bytes, pqc_pub_hash: bytes):
    """
    【安全修正 F-7】ECQV 公鑰快取鍵必須涵蓋 Q_U 的全部輸入 (ID, role, P_U, H(pk_PQC))。
    原本只用 (ID, P_U)：快取命中後，宣稱不同 pqc_pub_hash 的封包仍沿用舊 Q_U 驗 ECC，
    中間人可轉送合法 SRM 並換上自己的 PQC 公鑰與簽章，通過驗證並污染 PQC 公鑰快取；
    量子攻擊者只要破解車輛自己的 ECDSA 金鑰 (不需 CA 金鑰) 就能取得綠燈。
    """
    return (obu_id_raw, role, P_U_bytes, pqc_pub_hash)

def inject_prewarm_cache(target_rsu_id: int, obu_id_raw: bytes, P_U_bytes: bytes, vk, pqc_pub: bytes,
                         expire_at: float = None, role: int = None):
    """
    路側有線骨幹 (Backhaul) 預同步注入：
    直接將 RSU-1 算好的 vk (Q_U) 與 PQC 公鑰注入目標下游路口的記憶體快取。
    下游路口免算點乘重構，達成零冷啟動！
    role：憑證角色 (快取鍵的一部分，必填)
    """
    if role is None:
        raise ValueError("inject_prewarm_cache 需要憑證角色 role")
    cache_key = ecqv_cache_key(obu_id_raw, role, P_U_bytes, hashlib.sha256(pqc_pub).digest())
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
    # ECQV 公鑰快取以 (obu_id_raw, role, P_U, pqc_pub_hash) 為鍵，同一車可能有多筆，全部清除
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

def reconstruct_obu_pubkey(obu_id_bytes: bytes, P_U_bytes: bytes, pqc_pub_hash: bytes, role: int):
    """
    ECQV 公鑰重構公式：
      1. e = SHA256(ID || role || P_U || pqc_pub_hash) mod n   (【安全修正 F-2】角色納入糾纏值)
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
    e = pki.ecqv_e(obu_id_bytes, role, P_U_bytes, pqc_pub_hash)

    # 3. 執行橢圓曲線乘加運算
    P_U = ellipticcurve.PointJacobi.from_bytes(curve.curve, P_U_bytes)
    Q_U = (e * P_U) + Q_CA

    return VerifyingKey.from_public_point(Q_U, curve=NIST256p)

ECQV_FIELDS_LEN = 8 + 1 + 33 + 32 + 32   # ID | role | P_U | pqc_pub_hash | pqc_sig_hash

_CA_PQC_PUB = None

def _ca_pqc_pub():
    """CA 後量子根公鑰 (RSU setup 時取得，原本從未使用)。"""
    global _CA_PQC_PUB
    if _CA_PQC_PUB is None:
        with open("RSU/keys/ca_pqc_pub.key", "rb") as f:
            _CA_PQC_PUB = f.read()
    return _CA_PQC_PUB

def _read_ecqv_fields(buf, start):
    """ID (8B) | role (1B) | P_U (33B) | pqc_pub_hash (32B) | pqc_sig_hash (32B)"""
    obu_id_raw   = buf[start : start + 8]
    role         = buf[start + 8]
    P_U_bytes    = buf[start + 9 : start + 42]
    pqc_pub_hash = buf[start + 42 : start + 74]
    pqc_sig_hash = buf[start + 74 : start + 106]
    return obu_id_raw, role, P_U_bytes, pqc_pub_hash, pqc_sig_hash, start + ECQV_FIELDS_LEN

def role_authorized(cert_role: int, payload: dict) -> bool:
    """
    【安全修正 F-2】原本 RSU 只看 SRM 自稱的 role，任何已註冊車輛都能自稱救護車。
    現在角色由 CA 寫入憑證 (綁進 ECQV 糾纏值)，必須是緊急車輛角色，且與 SRM 宣稱的 role 一致。
    """
    claimed = payload.get("requestor", {}).get("type", {}).get("role")
    return cert_role in pki.EMERGENCY_ROLES and claimed == cert_role

def srm_targets_rsu(payload: dict, rsu_id: int) -> bool:
    """
    【安全修正 F-8】SRM 請求的目標路口必須是本路口。原本 RSU 不檢查，攻擊者在 150ms 內把救護車發給
    路口 2 的合法 SRM 轉送 (wormhole) 到路口 1，路口 1 也會放行，讓沒有救護車接近的路口切成緊急綠燈。
    """
    reqs = payload.get("requests") or [{}]
    return reqs[0].get("request", {}).get("id", {}).get("id") == rsu_id

def _get_vk(obu_id_raw, role, P_U_bytes, pqc_pub_hash, rsu_id):
    """優先查快取 (鍵涵蓋 Q_U 全部輸入)，未命中則現場重構 Q_U。回傳 (vk, cache_key)。"""
    cache_key = ecqv_cache_key(obu_id_raw, role, P_U_bytes, pqc_pub_hash)
    vk = query_key_cache(cache_key, rsu_id=rsu_id)
    if vk is None:
        vk = reconstruct_obu_pubkey(obu_id_raw, P_U_bytes, pqc_pub_hash, role)
    return vk, cache_key

def verify_f1_ecc(f1_chunk, rsu_id=1):
    """
    從 F1 碎片中提取分片承諾雜湊清單、SRM 訊息與 ECC 簽章並進行快速驗證
    F1 佈局：
      num_hashes (1B) | [H_2 (32B)] | [H_3 (32B)]... |
      msg_len (2B) | msg | ecc_sig_len (1B) | ecc_sig |
      ID (8B) | role (1B) | P_U (33B) | pqc_pub_hash (32B) | pqc_sig_hash (32B)
    ECC 簽章涵蓋 msg ‖ pqc_sig_hash (F-1)；角色須為緊急車輛且與 SRM 一致 (F-2)。
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

        # 提取 ECQV 輕量憑證欄位
        obu_id_raw, role, P_U_bytes, pqc_pub_hash, pqc_sig_hash, end = _read_ecqv_fields(f1_chunk, end)
        if len(pqc_sig_hash) != 32:
            return False, None, None, None, None
        obu_id_str = obu_id_raw.decode('utf-8').rstrip('\x00')

        # 1. 優先查純記憶體快取 (支援有線骨幹預熱注入之 vk，免重算 Q_U 點乘)
        vk, cache_key = _get_vk(obu_id_raw, role, P_U_bytes, pqc_pub_hash, rsu_id)

        # 先驗證簽章！
        if not vk.verify(ecc_sig, pki.obu_ecc_tbs(payload_bytes, pqc_sig_hash), hashfunc=hashlib.sha256):
            return False, obu_id_str, None, None, None

        # 3. 簽章通過才安全寫入
        update_key_cache(cache_key, vk, rsu_id=rsu_id)

        f1_data = json.loads(payload_bytes.decode('utf-8'))
        if not role_authorized(role, f1_data):
            print(f"車輛 {obu_id_str} 憑證角色 {role} 無緊急優先權或與 SRM 宣稱角色不符，拒絕閃黃燈")
            return False, obu_id_str, None, None, None
        if not srm_targets_rsu(f1_data, rsu_id):
            print(f"車輛 {obu_id_str} 的 SRM 目標路口不是本路口 {rsu_id}，疑似轉送攻擊，拒絕閃黃燈")
            return False, obu_id_str, None, None, None

        # 檢查時間戳防重放攻擊 (150ms)
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
      ID (8B) | role (1B) | P_U (33B) | pqc_pub_hash (32B) | pqc_sig_hash (32B) |
      pqc_pub_len (2B) | [pqc_pub | ca_cert_len (2B) | ca_pqc_cert] | pqc_sig_len (2B) | pqc_sig
    驗證順序：ECC (含角色) → H(sig_PQC) 比對 → PQC 公鑰綁定 / CA 後量子憑證 → ML-DSA。
    先確認 ECC 簽章涵蓋的 H(sig_PQC) 與收到的簽章一致，ML-DSA 失敗才能歸責於車輛本身 (F-1)。
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
        obu_id_raw, role, P_U_bytes, pqc_pub_hash, pqc_sig_hash, end = _read_ecqv_fields(packet, end)
        obu_id_str = obu_id_raw.decode('utf-8').rstrip('\x00')

        # 提取 OBU 的 PQC 公鑰 (若 pqc_pub_len == 0 則為 Short 模式，由記憶體快取還原)
        start = end
        end += 2
        pqc_pub_len = int(struct.unpack('!H', packet[start:end])[0])
        is_short_mode = (pqc_pub_len == 0)
        obu_pqc_pub = ca_pqc_cert = None
        if not is_short_mode:
            start = end
            end += pqc_pub_len
            obu_pqc_pub = packet[start:end]
            ca_cert_len = int(struct.unpack('!H', packet[end:end + 2])[0])
            ca_pqc_cert = packet[end + 2 : end + 2 + ca_cert_len]
            end += 2 + ca_cert_len

        # 提取 OBU 的 PQC 簽章
        start = end
        end += 2
        obu_pqc_sig_len = int(struct.unpack('!H', packet[start:end])[0])
        start = end
        end += obu_pqc_sig_len
        obu_pqc_sig = packet[start:end]

        # 1. 驗證 OBU 的 ECC 簽章 (涵蓋 payload ‖ H(sig_PQC)) 與憑證角色
        vk, cache_key = _get_vk(obu_id_raw, role, P_U_bytes, pqc_pub_hash, rsu_id)
        if not vk.verify(obu_ecc_sig, pki.obu_ecc_tbs(payload_bytes, pqc_sig_hash), hashfunc=hashlib.sha256):
            LAST_PARSE_STATUS = "ECC_SIG_FAIL"
            print(f"OBU ECC 簽章驗證失敗(車輛: {obu_id_str})")
            return None
        payload = json.loads(payload_bytes.decode('utf-8'))
        if not role_authorized(role, payload):
            LAST_PARSE_STATUS = "ROLE_DENIED"
            print(f"車輛 {obu_id_str} 憑證角色 {role} 無緊急優先權或與 SRM 不符")
            return None
        if not srm_targets_rsu(payload, rsu_id):
            LAST_PARSE_STATUS = "WRONG_INTERSECTION"
            print(f"車輛 {obu_id_str} 的 SRM 目標路口不是本路口 {rsu_id} (F-8)")
            return None

        # 2. 【安全修正 F-1】收到的 PQC 簽章必須是車輛 ECC 簽章所承諾的那一個；
        # 不符代表傳輸途中遭竄改 (無法歸責於車輛)，只丟棄、不封鎖。
        if hashlib.sha256(obu_pqc_sig).digest() != pqc_sig_hash:
            LAST_PARSE_STATUS = "PQC_SIG_HASH_MISMATCH"
            print(f"PQC 簽章與 ECC 簽章承諾的 H(sig_PQC) 不符，疑似傳輸途中遭竄改 (車輛: {obu_id_str})")
            return None

        if is_short_mode:
            # 二次通訊 (Short 模式)：從記憶體快取還原 PQC 公鑰
            obu_pqc_pub = query_pqc_pub_cache(obu_id_raw, rsu_id=rsu_id)
            # 【安全修正 F-7】快取公鑰必須吻合本次 ECQV 憑證的 pqc_pub_hash，否則視同快取未命中
            # (例如車輛重新註冊換了 PQC 金鑰)，要求補送 Full。
            if obu_pqc_pub is None or hashlib.sha256(obu_pqc_pub).digest() != pqc_pub_hash:
                LAST_PARSE_STATUS = "NEED_CERT"
                print(f"收到 Short 封包但路口 {rsu_id} 記憶體查無相符的快取公鑰 (車輛: {obu_id_str})，需退回 Full 模式補憑證")
                return None
        else:
            # 首次通訊 (Full 模式)：接收完整 1312B 公鑰
            # 3. 雜湊綁定檢查 (防 DoS 注入攻擊)：檢查完整公鑰是否吻合 F1 裡的 pqc_pub_hash
            if hashlib.sha256(obu_pqc_pub).digest() != pqc_pub_hash:
                LAST_PARSE_STATUS = "PQC_PUB_HASH_MISMATCH"
                print(f"PQC 公鑰雜湊不符，疑似偽造公鑰攻擊！(車輛: {obu_id_str})")
                return None

            # 4. 【安全修正 F-5】驗證 CA 的 ML-DSA-44 後量子憑證 (ID ‖ role ‖ P_U ‖ H(pk_PQC))。
            # ECQV 只靠 ECC，量子攻擊者破解 CA ECC 根金鑰即可綁定任意 PQC 公鑰；
            # 此憑證讓 PQC 公鑰的信任錨回到後量子簽章。
            with oqs.Signature(pki.pqc_alg()) as verifier:
                tbs = pki.ca_pqc_cert_tbs(obu_id_raw, role, P_U_bytes, pqc_pub_hash)
                if not verifier.verify(tbs, ca_pqc_cert, _ca_pqc_pub()):
                    LAST_PARSE_STATUS = "CA_CERT_FAIL"
                    print(f"CA 後量子憑證驗證失敗 (車輛: {obu_id_str})")
                    return None

            # 【修正】此處僅完成綁定檢查，尚未驗證 ML-DSA 簽章，
            # 因此不在這裡寫入快取；改到所有簽章驗證通過後才寫入 (真正的 Verify-then-Cache)。

        # 5. 驗證 OBU 的 PQC 簽章 (ML-DSA-44 抗量子安全)
        with oqs.Signature(pki.pqc_alg()) as verifier:
            if not verifier.verify(payload_bytes, obu_pqc_sig, obu_pqc_pub):
                if is_short_mode:
                    # Short 模式公鑰來自本地快取，快取若不同步或損毀可能導致失敗，不可斷定為惡意
                    LAST_PARSE_STATUS = "SHORT_SIG_FAIL"
                    print(f"OBU Short 模式後量子簽章驗證失敗 (可能是快取過期/不同步)！(車輛: {obu_id_str})")
                else:
                    # Full 模式：ECC 簽章已承諾此 PQC 簽章、公鑰經 CA 後量子憑證綁定，
                    # 簽章仍失敗只可能是金鑰持有者自己簽出無效簽章 (古典攻擊者下的強證據)
                    LAST_PARSE_STATUS = "FULL_SIG_FAIL"
                    print(f"OBU Full 模式後量子簽章驗證失敗！(車輛: {obu_id_str})")
                return None

        update_key_cache(cache_key, vk, rsu_id=rsu_id)
        # Full 模式：所有簽章皆已通過，此時才將 PQC 公鑰寫入快取 (Verify-then-Cache)
        if not is_short_mode:
            update_pqc_pub_cache(obu_id_raw, obu_pqc_pub, rsu_id=rsu_id)

        # 記錄已驗證認證資料供骨幹預熱使用
        LAST_VERIFIED_AUTH = {
            "obu_id_raw": obu_id_raw,
            "obu_id_str": obu_id_str,
            "role": role,
            "P_U_bytes": P_U_bytes,
            "vk": vk,
            "pqc_pub": obu_pqc_pub
        }
        LAST_PARSE_STATUS = "OK"

        print(f"ECQV + {pki.pqc_alg()} 驗證全部通過")
        return payload

    except Exception as e:
        LAST_PARSE_STATUS = "PARSE_ERROR"
        print(f"封包解析失敗：{e}")
        return None
