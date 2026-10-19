import struct, oqs, json, hashlib
from ecdsa import SigningKey, NIST256p
from OBU.gen_payload import generate_srm_payload
from ctypes import create_string_buffer

def gen_packet(obu_id, intersection_id=1, known_RSU=False):
    # 1. 生成符合 SAE J2735 SEP2024 的最小化 SRM (Signal Request Message) Payload
    payload = generate_srm_payload(obu_id, intersection_id=intersection_id)
    message = json.dumps(payload, separators=(',', ':')).encode('utf-8')

    # 2. 讀取 ECC 推導私鑰並進行簽章
    with open(f"OBU/keys/{obu_id}_ecc_priv.key", "rb") as f:
        ecc_sk = SigningKey.from_der(f.read())
    ecc_sig = ecc_sk.sign(message, hashfunc=hashlib.sha256)

    # 3. 讀取 PQC 私鑰並進行 ML-DSA-44 簽章
    with open(f"OBU/keys/{obu_id}_pqc_priv.key", "rb") as f:
        pqc_priv = f.read()
    with oqs.Signature("ML-DSA-44") as signer:
        signer.secret_key = create_string_buffer(pqc_priv, len(pqc_priv))
        pqc_sig = signer.sign(message)

    # 4. 讀取精簡 ECQV 憑證：P_U (33B) | pqc_pub_len (2B) | pqc_pub (1312B)
    with open(f"OBU/cert/{obu_id}_cert.bin", "rb") as f:
        cert_data = f.read()

    P_U_bytes = cert_data[:33]
    pqc_pub_len = struct.unpack('!H', cert_data[33:35])[0]
    obu_pqc_pub = cert_data[35 : 35 + pqc_pub_len]

    # 計算 PQC 公鑰雜湊 (32 Bytes)，供 F1 輕量驗證與防 DoS 注入
    pqc_pub_hash = hashlib.sha256(obu_pqc_pub).digest()

    # 5. 組裝完整輕量封包
    obu_id_raw = struct.pack('!8s', obu_id.encode('utf-8'))
    header_part = struct.pack('!H', len(message)) + message
    ecc_part = struct.pack('!B', len(ecc_sig)) + ecc_sig
    ecqv_id_part = obu_id_raw + P_U_bytes + pqc_pub_hash
    
    # 若為已知 RSU (known_RSU=True)，省略 1312 Bytes 的 PQC 公鑰本體！
    if known_RSU:
        pqc_pub_part = struct.pack('!H', 0) # 長度標頭為 0，不帶公鑰本體
        mode_str = "Short 二次極速模式 (省略 1.3KB 公鑰)"
    else:
        pqc_pub_part = struct.pack('!H', len(obu_pqc_pub)) + obu_pqc_pub
        mode_str = "Full 首次建聯模式 (帶完整公鑰)"

    pqc_sig_part = struct.pack('!H', len(pqc_sig)) + pqc_sig
    packet = header_part + ecc_part + ecqv_id_part + pqc_pub_part + pqc_sig_part

    print(f"生成純粹 ECQV 輕量封包 [{mode_str}]: \nPayload長度 = {len(message)} bytes\nECC簽章長度 = {len(ecc_sig)} bytes\nP_U重構點 = {len(P_U_bytes)} bytes\nPQC公鑰長度 = {0 if known_RSU else len(obu_pqc_pub)} bytes\nPQC簽章長度 = {len(pqc_sig)} bytes\n總封包長度 = {len(packet)} bytes\n")
    return packet