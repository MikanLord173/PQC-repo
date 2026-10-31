import struct
import time
import os
import oqs
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from ctypes import create_string_buffer
import pki

# | ID (8 bytes) | Expiry (8 bytes) | ECC公鑰長度 (1 byte) | PQC公鑰長度 (2 bytes) | ECC公鑰 (variable) | PQC公鑰 (variable) | ECC簽章長度 (1 byte) | PQC簽章長度 (2 bytes) | ECC簽章 (variable) | PQC簽章 (variable) |
def issue_obu_certificate(obu_id, obu_ecc_pub, obu_pqc_pub):
    try:
        # TBSC，有效期限 365天
        expiry = int(time.time() + 31536000)
        
        # ID (8 bytes) | Expiry (8 bytes) | ECC公鑰 | PQC公鑰 |
        ID_expiry = struct.pack('!8sQ', obu_id.encode('utf-8'), expiry)
        tbs_content = ID_expiry + obu_ecc_pub + obu_pqc_pub
        
        # CA 進行雙重簽署
        with open("CA/keys/ca_ecc_priv.key", "rb") as f:
            ca_ecc_priv = serialization.load_der_private_key(f.read(), password=None)
        ca_ecc_sig = ca_ecc_priv.sign(tbs_content, ec.ECDSA(hashes.SHA256()))
        with oqs.Signature(pki.pqc_alg()) as signer:
            with open("CA/keys/ca_pqc_priv.key", "rb") as f:
                ca_pqc_priv = f.read() 
            signer.secret_key = create_string_buffer(ca_pqc_priv, len(ca_pqc_priv))  # 導入私鑰
            ca_pqc_sig = signer.sign(tbs_content)
            
        # 打包憑證 .bin 
        pub_header = struct.pack('!BH', len(obu_ecc_pub), len(obu_pqc_pub)) 
        sig_header = struct.pack('!BH', len(ca_ecc_sig), len(ca_pqc_sig)) 
        full_cert = ID_expiry + pub_header + obu_ecc_pub + obu_pqc_pub + sig_header + ca_ecc_sig + ca_pqc_sig
        short_pub_header = struct.pack('!BH', 0, 0) #short
        short_cert = ID_expiry + short_pub_header + sig_header + ca_ecc_sig + ca_pqc_sig

        os.makedirs("CA/cert", exist_ok=True)
        with open(f"CA/cert/{obu_id}_cert.bin", "wb") as f:
            f.write(full_cert)
        with open(f"CA/cert/{obu_id}_full_cert.bin", "wb") as f:
            f.write(full_cert)
        with open(f"CA/cert/{obu_id}_short_cert.bin", "wb") as f:
            f.write(short_cert)
        
        print(f"已成功核發 {obu_id} 的後量子憑證")
        return full_cert
    except Exception as e:
        print(f"核發憑證失敗：{e}")
        return None