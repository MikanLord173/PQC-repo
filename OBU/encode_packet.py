import struct, oqs, json, hashlib
from ecdsa import SigningKey, NIST256p
from OBU.gen_payload import generate_srm_payload
from ctypes import create_string_buffer
import pki

def load_cert(obu_id):
    """
    讀取憑證檔：P_U (33B) | role (1B) | pqc_pub_len (2B) | pqc_pub (1312B) | ca_cert_len (2B) | ca_pqc_cert (2420B)
    回傳 (P_U_bytes, role, obu_pqc_pub, ca_pqc_cert)
    """
    with open(f"OBU/cert/{obu_id}_cert.bin", "rb") as f:
        cert_data = f.read()
    P_U_bytes = cert_data[:33]
    role = cert_data[33]
    pqc_pub_len = struct.unpack('!H', cert_data[34:36])[0]
    obu_pqc_pub = cert_data[36 : 36 + pqc_pub_len]
    end = 36 + pqc_pub_len
    ca_cert_len = struct.unpack('!H', cert_data[end:end + 2])[0]
    ca_pqc_cert = cert_data[end + 2 : end + 2 + ca_cert_len]
    return P_U_bytes, role, obu_pqc_pub, ca_pqc_cert

def gen_packet(obu_id, intersection_id=1, known_RSU=False):
    # 1. 生成符合 SAE J2735 SEP2024 的最小化 SRM (Signal Request Message) Payload
    payload = generate_srm_payload(obu_id, intersection_id=intersection_id)
    message = json.dumps(payload, separators=(',', ':')).encode('utf-8')

    # 2. 讀取 PQC 私鑰並進行 ML-DSA-44 簽章
    with open(f"OBU/keys/{obu_id}_pqc_priv.key", "rb") as f:
        pqc_priv = f.read()
    with oqs.Signature("ML-DSA-44") as signer:
        signer.secret_key = create_string_buffer(pqc_priv, len(pqc_priv))
        pqc_sig = signer.sign(message)

    # 3. 讀取 ECC 推導私鑰並進行簽章
    # 【安全修正 F-1】ECC 簽章改為涵蓋 payload ‖ H(sig_PQC)。原本 ECC 只簽 payload，
    # 中間人可轉送合法 F1、竄改後續分片中的 ML-DSA 簽章並重算 F1 分片雜湊承諾，
    # RSU 會判定 FULL_SIG_FAIL 而把合法救護車硬封鎖 30 秒。
    # H(sig_PQC) 以 32B 明文放在 F1，F1 輕量驗證即可確認後量子簽章出自本車。
    pqc_sig_hash = hashlib.sha256(pqc_sig).digest()
    with open(f"OBU/keys/{obu_id}_ecc_priv.key", "rb") as f:
        ecc_sk = SigningKey.from_der(f.read())
    ecc_sig = ecc_sk.sign(pki.obu_ecc_tbs(message, pqc_sig_hash), hashfunc=hashlib.sha256)

    # 4. 讀取憑證
    P_U_bytes, role, obu_pqc_pub, ca_pqc_cert = load_cert(obu_id)

    # 計算 PQC 公鑰雜湊 (32 Bytes)，供 F1 輕量驗證與防 DoS 注入
    pqc_pub_hash = hashlib.sha256(obu_pqc_pub).digest()

    # 5. 組裝封包
    #   msg_len (2B) | msg | ecc_sig_len (1B) | ecc_sig |
    #   ID (8B) | role (1B) | P_U (33B) | pqc_pub_hash (32B) | pqc_sig_hash (32B) |      ← 以上位於 F1
    #   pqc_pub_len (2B) | [pqc_pub | ca_cert_len (2B) | ca_pqc_cert] | pqc_sig_len (2B) | pqc_sig
    obu_id_raw = struct.pack('!8s', obu_id.encode('utf-8'))
    header_part = struct.pack('!H', len(message)) + message
    ecc_part = struct.pack('!B', len(ecc_sig)) + ecc_sig
    ecqv_id_part = obu_id_raw + struct.pack('!B', role) + P_U_bytes + pqc_pub_hash + pqc_sig_hash

    # 若為已知 RSU (known_RSU=True)，省略 1312 Bytes 的 PQC 公鑰本體與 2420 Bytes 的 CA 後量子憑證！
    if known_RSU:
        pqc_pub_part = struct.pack('!H', 0) # 長度標頭為 0，不帶公鑰本體
        mode_str = "Short 二次極速模式 (省略 1.3KB 公鑰 + 2.4KB CA 憑證)"
    else:
        pqc_pub_part = (struct.pack('!H', len(obu_pqc_pub)) + obu_pqc_pub
                        + struct.pack('!H', len(ca_pqc_cert)) + ca_pqc_cert)
        mode_str = "Full 首次建聯模式 (帶完整公鑰 + CA 後量子憑證)"

    pqc_sig_part = struct.pack('!H', len(pqc_sig)) + pqc_sig
    packet = header_part + ecc_part + ecqv_id_part + pqc_pub_part + pqc_sig_part

    print(f"生成 ECQV 混合簽章封包 [{mode_str}]: \nPayload長度 = {len(message)} bytes\nECC簽章長度 = {len(ecc_sig)} bytes\nP_U重構點 = {len(P_U_bytes)} bytes\nPQC公鑰長度 = {0 if known_RSU else len(obu_pqc_pub)} bytes\nCA憑證長度 = {0 if known_RSU else len(ca_pqc_cert)} bytes\nPQC簽章長度 = {len(pqc_sig)} bytes\n總封包長度 = {len(packet)} bytes\n")
    return packet
