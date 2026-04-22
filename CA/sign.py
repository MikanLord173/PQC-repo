import struct
import time
import oqs
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from ctypes import create_string_buffer

# 憑證格式：
# | ID (8 bytes) | Expiry (8 bytes) | ECC公鑰長度 (1 byte) | PQC公鑰長度 (2 bytes) | ECC公鑰 (variable) | PQC公鑰 (variable) | ECC簽章長度 (1 byte) | PQC簽章長度 (2 bytes) | ECC簽章 (variable) | PQC簽章 (variable) |
def issue_obu_certificate(obu_id, obu_ecc_pub, obu_pqc_pub):
    try:
        # 1. 準備待簽署的內容 (TBSC: To Be Signed Certificate)
        # 包含 ID, 有效期限(365天後), 兩把公鑰
        expiry = int(time.time() + 31536000)
        
        # 組合簽署資料：| ID (8 bytes) | Expiry (8 bytes) | ECC公鑰 | PQC公鑰 |
        ID_expiry = struct.pack('!8sQ', obu_id.encode('utf-8'), expiry)
        tbs_content = ID_expiry + obu_ecc_pub + obu_pqc_pub
        
        # 2. CA 進行雙重簽署
        # A. ECC 簽署
        with open("CA/keys/ca_ecc_priv.key", "rb") as f:
            ca_ecc_priv = serialization.load_pem_private_key(f.read(), password=None)
        ca_ecc_sig = ca_ecc_priv.sign(tbs_content, ec.ECDSA(hashes.SHA256()))
        
        # B. PQC 簽署
        with oqs.Signature("ML-DSA-44") as signer:
            with open("CA/keys/ca_pqc_priv.key", "rb") as f:
                ca_pqc_priv = f.read()  # PQC 私鑰直接讀取 bytes

            signer.secret_key = create_string_buffer(ca_pqc_priv, len(ca_pqc_priv))  # 導入私鑰到簽署引擎
            ca_pqc_sig = signer.sign(tbs_content)
            
        # 3. 打包成最終憑證檔案 (.bin)
        # 為了讓 RSU 好拆，建議在每個變動長度欄位前加長度標頭
        pub_header = struct.pack('!BH', len(obu_ecc_pub), len(obu_pqc_pub)) # ECC公鑰長度 + PQC公鑰長度
        sig_header = struct.pack('!BH', len(ca_ecc_sig), len(ca_pqc_sig)) # ECC簽章長度 + PQC簽章長度
        
        final_cert = ID_expiry + pub_header + obu_ecc_pub + obu_pqc_pub + sig_header + ca_ecc_sig + ca_pqc_sig
        
        with open(f"CA/cert/{obu_id}_cert.bin", "wb") as f:
            f.write(final_cert)
        
        print(f"已成功核發 {obu_id} 的後量子憑證！")
        return final_cert
    except Exception as e:
        print(f"核發憑證失敗：{e}")
        return None