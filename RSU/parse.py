import struct, oqs, json, time
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

PQC_SIG_NAME = "ML-DSA-44"

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
def parse_packet(packet):
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
    ID, expiry = struct.unpack('!8sQ', ID_expiry_bytes)

    if time.time() > expiry:
        print(f"憑證已過期 (ID: {ID.decode('utf-8')}, Expiry: {time.ctime(expiry)})")
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
    if not verify_cert(ca_ecc_sig, ca_pqc_sig, tbs_content):
        print("憑證驗證失敗，拒絕通行。")
        return None

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

    passed = verify_obu_sig(obu_ecc_pub_obj, obu_pqc_pub, obu_ecc_sig, obu_pqc_sig, payload_bytes)  # 呼叫驗證函式

    if passed:
        return json.loads(payload_bytes) # 驗證成功，回傳訊息內容
    else:
        return None  # 驗證失敗，回傳 None

def verify_cert(ca_ecc_sig, ca_pqc_sig, tbs_content):
    ecc_ok, pqc_ok = False, False

    # 驗證ECC
    try:
        ca_ecc_pub = serialization.load_pem_public_key(open("RSU/keys/ca_ecc_pub.key", "rb").read())
        ca_ecc_pub.verify(ca_ecc_sig, tbs_content, ec.ECDSA(hashes.SHA256()))  # 使用 ECC 公鑰驗證 ECC 簽章
        print("ECC 簽章驗證成功")
        ecc_ok = True
    except Exception as e:
        print(f"ECC 簽章驗證失敗：{e}")
        print("混合簽章驗證失敗")
        return False

    # 驗證PQC
    with oqs.Signature(PQC_SIG_NAME) as verifier:
        ca_pqc_pub = verifier.import_public_key(open("RSU/keys/ca_pqc_pub.key", "rb").read())
        pqc_ok = verifier.verify(tbs_content, ca_pqc_sig, ca_pqc_pub)  # 使用 PQC 公鑰驗證 PQC 簽章
        if pqc_ok:
            print("PQC 簽章驗證成功")
        else:
            print("PQC 簽章驗證失敗")

    if ecc_ok and pqc_ok:
        print("混合簽章驗證成功")
        return True
    else:
        print("混合簽章驗證失敗")
        return False

def verify_obu_sig(ecc_pub, pqc_pub, ecc_sig, pqc_sig, payload_bytes):
    # 驗證ECC
    try:
        ecc_pub.verify(ecc_sig, payload_bytes, ec.ECDSA(hashes.SHA256()))  # 使用 ECC 公鑰驗證 ECC 簽章
        print("ECC 簽章驗證成功")
        ecc_ok = True
    except Exception as e:
        print(f"ECC 簽章驗證失敗：{e}")
        ecc_ok = False

    # 驗證PQC
    with oqs.Signature(PQC_SIG_NAME) as verifier:
        pqc_ok = verifier.verify(payload_bytes, pqc_sig, pqc_pub)  # 使用 PQC 公鑰驗證 PQC 簽章
        if pqc_ok:
            print("PQC 簽章驗證成功")
        else:
            print("PQC 簽章驗證失敗")

    if ecc_ok and pqc_ok:
        print("混合簽章驗證成功")
        return True
    else:
        print("混合簽章驗證失敗")
        return False