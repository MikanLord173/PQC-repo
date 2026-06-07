import struct, oqs, json, time
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

PQC_SIG_NAME = "ML-DSA-44"
# 新增全域變數暫存 CA 公鑰
GLOBAL_CA_ECC_PUB = None
GLOBAL_CA_PQC_PUB = None

def preload_ca_keys():
    """在 RSU 啟動時呼叫一次，把 CA 公鑰載入記憶體"""
    global GLOBAL_CA_ECC_PUB, GLOBAL_CA_PQC_PUB
    print("正在載入 CA 信任根到記憶體...")
    
    # 載入 ECC
    with open("RSU/keys/ca_ecc_pub.key", "rb") as f:
        ca_ecc_pub_data = f.read()
    GLOBAL_CA_ECC_PUB = serialization.load_der_public_key(ca_ecc_pub_data)
    
    # 載入 PQC
    with open("RSU/keys/ca_pqc_pub.key", "rb") as f:
        GLOBAL_CA_PQC_PUB = f.read()

# Header 格式：序列號(1) | 總分片數(1) | 訊息ID(2)
def parse_header(header_bytes):
    try:
        seq_num, total_frags, msg_id = struct.unpack('!BBH', header_bytes)
    except struct.error as e:
        print(f"Header 解析失敗：{e}")
        return None, None, None
    return seq_num, total_frags, msg_id

# 封包格式：Payload長度(2) | Payload | 憑證 | ECC簽章長度(1) | PQC簽章長度(2) | OBU_ECC簽章 | OBU_PQC簽章
# 憑證格式：| ID (8 bytes) | Expiry (8 bytes) | ECC公鑰長度 (1 byte) | PQC公鑰長度 (2 bytes) | ECC公鑰 (variable) | PQC公鑰 (variable) | 
# CA_ECC簽章長度 (1 byte) | CA_PQC簽章長度 (2 bytes) | CA_ECC簽章 (variable) | CA_PQC簽章 (variable) |
def parse_packet(packet, logger):
    # 提取 Payload 長度
    end = 2
    msg_len = int(struct.unpack('!H', packet[:end])[0])

    # 提取 Payload 內容 (bytes)
    start = end
    end += msg_len
    payload_bytes = packet[start:end]

    # 提取 ID 和過期時間
    start = end
    end += 16
    ID_expiry_bytes = packet[start:end]
    obu_id, expiry = struct.unpack('!8sQ', ID_expiry_bytes)

    if time.time() > expiry:
        logger.warning(
                    "封包已過期，停止解析",
                    extra={"extra_data": {
                        "event": "EXPIRED_PACKET",
                        "obu_id": obu_id,
                        "drop_reason": "Packet expired"
                    }}
                )
        return None

    # 提取ECC公鑰長度 + PQC公鑰長度
    start = end
    end += 3
    ecc_pub_len, pqc_pub_len = struct.unpack('!BH', packet[start:end])

    # 提取OBU ECC公鑰
    start = end
    end += ecc_pub_len
    obu_ecc_pub = packet[start:end]

    # 提取OBU PQC公鑰
    start = end
    end += pqc_pub_len
    obu_pqc_pub = packet[start:end]

    # TBSC內容：ID_expiry + obu_ecc_pub + obu_pqc_pub
    tbs_content = ID_expiry_bytes + obu_ecc_pub + obu_pqc_pub

    # 提取CA兩簽章長度
    start = end
    end += 3
    ca_ecc_sig_len, ca_pqc_sig_len = struct.unpack('!BH', packet[start:end])

    # 提取CA ECC簽章
    start = end
    end += ca_ecc_sig_len
    ca_ecc_sig = packet[start:end]

    # 提取CA PQC簽章
    start = end
    end += ca_pqc_sig_len
    ca_pqc_sig = packet[start:end]

    # 驗證憑證有效性
    ca_ecc_ok, ca_pqc_ok = verify_cert(ca_ecc_sig, ca_pqc_sig, tbs_content)

    if not ca_ecc_ok:
        logger.warning(
            "CA ECC簽章驗證失敗，停止解析",
            extra={"extra_data": {
                "event": "CA_ECC_FAILED",
                "obu_id": obu_id,
                "drop_reason": "CA ECC signature verification failed"
            }}
        )
        return None

    if not ca_pqc_ok:
        logger.warning(
            "CA PQC簽章驗證失敗，停止解析",
            extra={"extra_data": {
                "event": "CA_PQC_FAILED",
                "obu_id": obu_id,
                "drop_reason": "CA PQC signature verification failed"
            }}
        )
        return None

    logger.info(
        "CA 混合簽章驗證成功",
        extra={"extra_data": {
            "event": "CA_SIG_PASSED",
            "obu_id": obu_id
        }}
    )

    # 提取OBU兩簽章長度
    start = end
    end += 3
    obu_ecc_sig_len, obu_pqc_sig_len = struct.unpack('!BH', packet[start:end])

    # 提取OBU ECC簽章
    start = end
    end += obu_ecc_sig_len
    obu_ecc_sig = packet[start:end]

    # 提取OBU PQC簽章
    start = end
    end += obu_pqc_sig_len
    obu_pqc_sig = packet[start:end]  

    obu_ecc_pub_obj = serialization.load_der_public_key(obu_ecc_pub)  # 解析 ECC 公鑰

    obu_ecc_ok, obu_pqc_ok = verify_obu_sig(obu_ecc_pub_obj, obu_pqc_pub, obu_ecc_sig, obu_pqc_sig, payload_bytes)  # 呼叫驗證函式

    if not obu_ecc_ok:
        logger.warning(
            "OBU ECC簽章驗證失敗，停止解析",
            extra={"extra_data": {
                "event": "OBU_ECC_FAILED",
                "obu_id": obu_id,
                "drop_reason": "OBU ECC signature verification failed"
            }}
        )
        return None

    if not obu_pqc_ok:
        logger.warning(
            "OBU PQC簽章驗證失敗，停止解析",
            extra={"extra_data": {
                "event": "OBU_PQC_FAILED",
                "obu_id": obu_id,
                "drop_reason": "OBU PQC signature verification failed"
            }}
        )
        return None

    logger.info(
        "OBU 混合簽章驗證成功",
        extra={"extra_data": {
            "event": "OBU_SIG_PASSED",
            "obu_id": obu_id
        }}
    )

    return json.loads(payload_bytes) # 驗證成功，回傳訊息內容

def verify_cert(ca_ecc_sig, ca_pqc_sig, tbs_content):
    ecc_ok, pqc_ok = False, False

    # 驗證ECC
    try:
        GLOBAL_CA_ECC_PUB.verify(ca_ecc_sig, tbs_content, ec.ECDSA(hashes.SHA256()))  # 使用 ECC 公鑰驗證 ECC 簽章
        ecc_ok = True
    except:
        pass

    # 驗證PQC
    with oqs.Signature(PQC_SIG_NAME) as verifier:
        pqc_ok = verifier.verify(tbs_content, ca_pqc_sig, GLOBAL_CA_PQC_PUB)  # 使用 PQC 公鑰驗證 PQC 簽章

    return ecc_ok, pqc_ok

def verify_obu_sig(ecc_pub, pqc_pub, ecc_sig, pqc_sig, payload_bytes):
    ecc_ok, pqc_ok = False, False
    # 驗證ECC
    try:
        ecc_pub.verify(ecc_sig, payload_bytes, ec.ECDSA(hashes.SHA256()))  # 使用 ECC 公鑰驗證 ECC 簽章
        ecc_ok = True
    except Exception as e:
        pass

    # 驗證PQC
    with oqs.Signature(PQC_SIG_NAME) as verifier:
        pqc_ok = verifier.verify(payload_bytes, pqc_sig, pqc_pub)  # 使用 PQC 公鑰驗證 PQC 簽章

    return ecc_ok, pqc_ok
