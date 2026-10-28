"""
PKI 共用定義：CA / OBU / RSU 三方必須逐位元組一致的欄位與簽署內容。

【安全修正】集中定義以下項目 (見 security/THREAT_MODEL.md)：
  F-2  角色 (role) 綁進 ECQV 糾纏值 e 與 CA 後量子憑證，RSU 不再信任 SRM 自稱的角色
  F-3  CA 註冊請求以預先發放的註冊金鑰 (HMAC-SHA256) 驗證申請者
  F-5  CA 以 ML-DSA-44 根金鑰簽署 (ID ‖ role ‖ P_U ‖ H(pk_PQC))，PQC 公鑰不再只靠 ECC 綁定
  F-6  RSU 以 CA 核發的 ECDSA 金鑰簽署下行 SSM
"""
import base64, hashlib, hmac, json, struct

from ecdsa import NIST256p, VerifyingKey

# ─── 角色 (SAE J2735 DE_BasicVehicleRole) ───────────────────────────────────
ROLE_BASIC_VEHICLE = 0
ROLE_EMERGENCY     = 6
ROLE_POLICE        = 12
ROLE_FIRE          = 13
ROLE_AMBULANCE     = 14
# 可觸發緊急號誌優先的角色
EMERGENCY_ROLES = {ROLE_EMERGENCY, ROLE_POLICE, ROLE_FIRE, ROLE_AMBULANCE}


def ecqv_entangled_data(obu_id_raw: bytes, role: int, P_U_bytes: bytes, pqc_pub_hash: bytes) -> bytes:
    """ECQV 糾纏值 e = SHA256(ID ‖ role ‖ P_U ‖ H(pk_PQC)) 的輸入。"""
    return obu_id_raw + struct.pack('!B', role) + P_U_bytes + pqc_pub_hash


def ecqv_e(obu_id_raw: bytes, role: int, P_U_bytes: bytes, pqc_pub_hash: bytes) -> int:
    data = ecqv_entangled_data(obu_id_raw, role, P_U_bytes, pqc_pub_hash)
    return int(hashlib.sha256(data).hexdigest(), 16) % NIST256p.order


def ca_pqc_cert_tbs(obu_id_raw: bytes, role: int, P_U_bytes: bytes, pqc_pub_hash: bytes) -> bytes:
    """CA ML-DSA-44 後量子憑證的簽署內容 (加上網域分隔字串，避免與其他簽章混用)。"""
    return b"PQC-EV-CERT-v1" + ecqv_entangled_data(obu_id_raw, role, P_U_bytes, pqc_pub_hash)


def obu_ecc_tbs(payload_bytes: bytes, pqc_sig_hash: bytes) -> bytes:
    """OBU ECC 簽章內容：payload ‖ H(sig_PQC)，讓 ECC 簽章同時保護後量子簽章 (F-1)。"""
    return payload_bytes + pqc_sig_hash


# ─── CA 註冊驗證 (F-3) ──────────────────────────────────────────────────────
def enroll_mac(enroll_key: bytes, obu_id_raw: bytes, R_U_bytes: bytes, obu_pqc_pub: bytes) -> bytes:
    """註冊請求驗證碼：HMAC-SHA256(註冊金鑰, ID ‖ R_U ‖ pk_PQC)。"""
    return hmac.new(enroll_key, obu_id_raw + R_U_bytes + obu_pqc_pub, hashlib.sha256).digest()


# ─── RSU 憑證與 SSM 簽章 (F-6) ──────────────────────────────────────────────
def rsu_cert_tbs(rsu_id: int, rsu_pub_bytes: bytes) -> bytes:
    return b"RSU-CERT-v1" + struct.pack('!H', rsu_id) + rsu_pub_bytes


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode('ascii')


def _canonical(ssm: dict) -> bytes:
    """SSM 簽署內容：去除 sig 欄位後的正規化 JSON。"""
    return json.dumps({k: v for k, v in ssm.items() if k != "sig"}, sort_keys=True, separators=(',', ':')).encode()


def sign_ssm(ssm: dict, rsu_sk, rsu_cert: dict) -> dict:
    """附上 RSU 憑證與 ECDSA 簽章 (sig 欄位)。rsu_cert = {"rsu_id", "pub", "ca_sig"} (base64)。"""
    ssm = dict(ssm, rsu_cert=rsu_cert)
    ssm["sig"] = _b64(rsu_sk.sign(_canonical(ssm), hashfunc=hashlib.sha256))
    return ssm


def verify_ssm(ssm: dict, ca_ecc_vk) -> bool:
    """
    OBU 驗證 SSM：
      1. RSU 憑證由 CA ECC 根金鑰簽發
      2. SSM 簽章由該 RSU 金鑰簽出
      3. SSM 宣稱的路口編號 = 憑證上的 RSU 編號 (防止 A 路口的 RSU 冒充 B 路口)
    """
    try:
        cert = ssm["rsu_cert"]
        rsu_id = int(cert["rsu_id"])
        rsu_pub = base64.b64decode(cert["pub"])
        ca_ecc_vk.verify(base64.b64decode(cert["ca_sig"]), rsu_cert_tbs(rsu_id, rsu_pub), hashfunc=hashlib.sha256)
        rsu_vk = VerifyingKey.from_string(rsu_pub, curve=NIST256p)
        rsu_vk.verify(base64.b64decode(ssm["sig"]), _canonical(ssm), hashfunc=hashlib.sha256)
        return all(entry.get("id", {}).get("id") == rsu_id for entry in ssm.get("status", []))
    except Exception:   # 欄位缺漏、格式錯誤、BadSignatureError、MalformedPointError 一律視為驗證失敗
        return False
