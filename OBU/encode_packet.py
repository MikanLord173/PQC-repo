import struct, oqs, json
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from OBU.gen_payload import generate_bsm_payload
from ctypes import create_string_buffer

# 封包格式：Payload長度(2) | Payload | 憑證 | ECC簽章長度(1) | PQC簽章長度(2) | ECC簽章 | PQC簽章
def gen_packet(obu_id):
    # 生成 Payload
    payload = generate_bsm_payload(obu_id)
    message = json.dumps(payload).encode('utf-8') # 將資料轉換為位元組格式

    # 讀取 ECC 和 PQC 私鑰
    with open(f"OBU/keys/{obu_id}_ecc_priv.key", "rb") as f:
        ecc_priv_bytes = f.read()
    ecc_priv = serialization.load_der_private_key(ecc_priv_bytes, password=None)
    
    with open(f"OBU/keys/{obu_id}_pqc_priv.key", "rb") as f:
        pqc_priv = f.read()

    # 進行雙重簽章
    ecc_sig = ecc_priv.sign(message, ec.ECDSA(hashes.SHA256()))  # ECC 簽章

    sig_name = "ML-DSA-44" 
    with oqs.Signature(sig_name) as signer:
        
        # 將讀出來的 bytes 導入引擎
        signer.secret_key = create_string_buffer(pqc_priv, len(pqc_priv))
        
        # 現在可以開始簽名了
        pqc_sig = signer.sign(message)

    # 讀取憑證
    with open(f"OBU/cert/{obu_id}_full_cert.bin", "rb") as f:
        cert = f.read()

    msg_len = struct.pack('!H', len(message))   # 訊息長度 (2 bytes)
    sig_len = struct.pack('!BH', len(ecc_sig), len(pqc_sig))  # 簽章長度 (ECC 1 byte + PQC 2 bytes)
    packet = msg_len + message + cert + sig_len + ecc_sig + pqc_sig    # 組合成完整封包
    print(f"生成封包: \nPayload長度 = {len(message)} bytes\n憑證長度 = {len(cert)} bytes\nECC簽章長度 = {len(ecc_sig)} bytes\nPQC簽章長度 = {len(pqc_sig)} bytes\n")

    return packet