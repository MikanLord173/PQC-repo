from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

import oqs, struct

# 生成PQC簽章
def gen_dilithium(message):
    sig_name = "ML-DSA-44" # 選擇 Dilithium 模組，這裡使用 ML-DSA-44

    if type(message) != bytes:
        message = message.encode()  # 確保輸入是 bytes 類型，因為簽章函數需要 bytes 格式的訊息

    with oqs.Signature(sig_name) as signer:

        # 生成金鑰對 (Keypair)
        # 公鑰 (Public Key) 用於驗證，私鑰 (Secret Key) 用於簽署
        public_key = signer.generate_keypair()
        secret_key = signer.export_secret_key()

        # 生成簽章 (Sign)
        signature = signer.sign(message)
        return signature, public_key

# 生成ECC簽章
def gen_ecc(message):
    
    if type(message) != bytes:
        message = message.encode()

    # 生成 ECC 金鑰對 (使用 NIST P-256 曲線，也稱為 SECP256R1)
    # 這是車聯網標準中規定的曲線
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    # 將公鑰物件轉換為 bytes
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,            # 二進制格式，體積最小
        format=serialization.PublicFormat.SubjectPublicKeyInfo # 標準公鑰格式
    )

    # 生成簽章 (ECDSA + SHA256)
    signature = private_key.sign(
        message,
        ec.ECDSA(hashes.SHA256())
    )
    return signature, public_key_bytes

def gen_hybrid(sig_ecc, sig_pqc):
    # 混合簽章格式：| ECC 簽章長度 (1) | PQC 簽章長度 (2) | ECC 簽章 (72) | PQC 簽章 (2420) |
    # !: Big Endian, B: unsigned char (1 byte), H: unsigned short (2 bytes)
    header = struct.pack('!BH', len(sig_ecc), len(sig_pqc)) # header = ECC 簽章長度 + PQC 簽章長度

    return header + sig_ecc + sig_pqc

def merge_pub(ecc_pub, pqc_pub):
    # 混合公鑰格式：| ECC 公鑰長度 (1) | PQC 公鑰長度 (2) | ECC 公鑰 | PQC 公鑰 |
    header = struct.pack('!BH', len(ecc_pub), len(pqc_pub)) # header = ECC 公鑰長度 + PQC 公鑰長度

    return header + ecc_pub + pqc_pub