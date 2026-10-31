import struct
import oqs
import hashlib
import hmac
from ecdsa import NIST256p
from ecdsa.util import randrange
from cryptography.hazmat.primitives import serialization
from ctypes import create_string_buffer
import ecdsa.ellipticcurve as ellipticcurve

import pki
from CA.registry import load_registry

def authenticate_enrollment(obu_id: bytes, obu_R_U_bytes: bytes, obu_pqc_pub: bytes, tag: bytes, registry=None):
    """
    【安全修正 F-3】驗證註冊請求：ID 必須已登記於 CA 名冊，且 HMAC 吻合其註冊金鑰。
    回傳名冊登記的角色；驗證失敗回傳 None。
    """
    registry = load_registry() if registry is None else registry
    entry = registry.get(obu_id.rstrip(b'\x00').decode('utf-8', errors='replace'))
    if entry is None:
        return None
    expected = pki.enroll_mac(bytes.fromhex(entry["enroll_key"]), obu_id, obu_R_U_bytes, obu_pqc_pub)
    if not hmac.compare_digest(expected, tag):
        return None
    return int(entry["role"])

def ca_process_enrollment(obu_id: bytes, obu_R_U_bytes: bytes, obu_pqc_pub: bytes, role: int):
    """
    輸入：obu_id、 obu_R_U_bytes、 obu_pqc_pub、role (由 CA 名冊決定，非車輛自報)
    輸出：[P_U (33B) | r (32B) | role (1B) | ca_pqc_sig_len (2B) | ca_pqc_sig]
    """
    curve = NIST256p
    n = curve.order
    G = curve.generator

    # 載入R_U
    R_U = ellipticcurve.PointJacobi.from_bytes(curve.curve, obu_R_U_bytes)
    # CA 產生 k_CA，計算 P_U = R_U + k_CA * G
    k_CA = randrange(n)
    P_U = R_U + (k_CA * G)
    P_U_bytes = P_U.to_bytes("compressed") # 壓縮



    # Hash Entanglement
    # 【安全修正 F-2】角色納入糾纏值：e = H(ID ‖ role ‖ P_U ‖ H(pk_PQC))，
    # 一般車輛的 d_U 只能對應 role=一般車 的 Q_U，無法冒稱救護車。
    pqc_pub_hash = hashlib.sha256(obu_pqc_pub).digest()
    e = pki.ecqv_e(obu_id, role, P_U_bytes, pqc_pub_hash)
    # 4. 計算私鑰重構因子 r = (e * k_CA + d_CA) mod n
    with open("CA/keys/ca_ecc_priv.key", "rb") as f:
        ca_ecc_priv_obj = serialization.load_der_private_key(f.read(), password=None)

    ca_ecc_priv_int = ca_ecc_priv_obj.private_numbers().private_value
    r = (e * k_CA + ca_ecc_priv_int) % n

    # 5. 【安全修正 F-5】CA 以 ML-DSA-44 根金鑰簽署後量子憑證 (ID ‖ role ‖ P_U ‖ H(pk_PQC))。
    # 原設計認為「能簽出有效 ECC 簽章即證明擁有 CA 授權」，此推論只對古典攻擊者成立：
    # 量子攻擊者以 Shor 求得 d_CA 後可自行簽發綁定任意 PQC 公鑰的 ECQV 憑證，兩層簽章都會通過。
    # 此憑證只在 Full 封包夾帶 (+2420B)，RSU 驗證後快取 PQC 公鑰，Short 封包大小不變。
    with oqs.Signature(pki.pqc_alg()) as signer:
        with open("CA/keys/ca_pqc_priv.key", "rb") as f:
            ca_pqc_priv = f.read()
        signer.secret_key = create_string_buffer(ca_pqc_priv, len(ca_pqc_priv))
        ca_pqc_sig = signer.sign(pki.ca_pqc_cert_tbs(obu_id, role, P_U_bytes, pqc_pub_hash))

    r_bytes = r.to_bytes(32, byteorder='big')
    packed_data = struct.pack(f"!33s 32s B H {len(ca_pqc_sig)}s", P_U_bytes, r_bytes, role, len(ca_pqc_sig), ca_pqc_sig)
    return packed_data

def issue_rsu_certificate(rsu_id: int, rsu_pub_bytes: bytes) -> bytes:
    """【安全修正 F-6】以 CA ECC 根金鑰簽發 RSU 憑證，供 OBU 驗證下行 SSM。回傳 64B ECDSA 簽章 (r‖s)。"""
    from ecdsa import SigningKey
    with open("CA/keys/ca_ecc_priv.key", "rb") as f:
        ca_ecc_priv_obj = serialization.load_der_private_key(f.read(), password=None)
    ca_sk = SigningKey.from_secret_exponent(ca_ecc_priv_obj.private_numbers().private_value, curve=NIST256p)
    return ca_sk.sign(pki.rsu_cert_tbs(rsu_id, rsu_pub_bytes), hashfunc=hashlib.sha256)
