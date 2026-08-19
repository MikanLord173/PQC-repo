import struct
import time
import oqs
import hashlib
from ecdsa import NIST256p
from ecdsa.util import randrange
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from ctypes import create_string_buffer
import ecdsa.ellipticcurve as ellipticcurve

def ca_process_enrollment(obu_id: bytes, obu_R_U_bytes: bytes, obu_pqc_pub: bytes):
    curve = NIST256p
    n = curve.order
    G = curve.generator
    
    # 1. 載入 OBU 的請求點 R_U
    R_U = ellipticcurve.PointJacobi.from_bytes(curve.curve, obu_R_U_bytes)
    
    # 2. CA 產生隨機貢獻值 k_CA，計算重構值 P_U
    k_CA = randrange(n)
    P_U = R_U + (k_CA * G)
    P_U_bytes = P_U.to_bytes("compressed") # 壓縮為 33 Bytes
    
    # 3. 雜湊糾纏 (Hash Entanglement)
    # 將身分、重構值與 PQC 公鑰全部綁定在一起進行 SHA-256
    entanglement_data = obu_id + P_U_bytes + obu_pqc_pub
    e_hex = hashlib.sha256(entanglement_data).hexdigest()
    e = int(e_hex, 16) % n
    
    # 4. 計算私鑰重構因子 r
    # 先讀取 ECC 私鑰並轉為 int
    with open("CA/keys/ca_ecc_priv.key", "rb") as f:
        ca_ecc_priv_obj = serialization.load_der_private_key(f.read(), password=None)

    ca_ecc_priv_int = ca_ecc_priv_obj.private_numbers().private_value
    r = (e * k_CA + ca_ecc_priv_int) % n
    
    # 5. CA 使用自己的 PQC 私鑰對憑證資料進行簽章 (保護 PQC 公鑰與 P_U)
    with oqs.Signature("ML-DSA-44") as signer:
        with open("CA/keys/ca_pqc_priv.key", "rb") as f:
            ca_pqc_priv = f.read()  # PQC 私鑰直接讀取 bytes

        signer.secret_key = create_string_buffer(ca_pqc_priv, len(ca_pqc_priv))  # 導入私鑰到簽署引擎
        ca_pqc_sig = signer.sign(entanglement_data)
    
    # 回傳：對外公開的憑證資料 (P_U_bytes, ca_pqc_sig)，以及不可公開的私鑰重構因子 (r)
    # 1. 數字轉位元組：將大整數 r 轉換為 32 bytes (強制使用 big-endian)
    r_bytes = r.to_bytes(32, byteorder='big')
    # 2. 取得 PQC 簽章的實際長度
    sig_len = len(ca_pqc_sig)
    # 3. 定義 struct 格式字串：
    # !   : Network byte order (大端序，確保跨平台一致性)
    # 33s : 33 Bytes 的字串 (P_U_bytes)
    # 32s : 32 Bytes 的字串 (r_bytes)
    # H   : 2 Bytes 的無號整數 unsigned short (用來儲存 PQC 簽章長度)
    # {sig_len}s : 動態長度的 PQC 簽章本體
    # 4. 執行打包
    packed_data = struct.pack(f"!33s 32s H {sig_len}s", P_U_bytes, r_bytes, sig_len, ca_pqc_sig)
    return packed_data