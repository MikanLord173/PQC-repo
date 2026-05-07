import oqs
import json
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from CA.sign import issue_obu_certificate
from OBU.main import OBU_ID

def setup(obu_id):
    # 清空原有內容
    with open("OBU/json/saved_RSU.json", "w") as f:
        empty_data = {}
        json.dump(empty_data, f, indent=4)

    # 準備 ECC 金鑰
    obu_ecc_priv = ec.generate_private_key(ec.SECP256R1())
    obu_ecc_pub_bytes = obu_ecc_priv.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    # 準備 PQC 金鑰 (ML-DSA-44)
    obu_pqc = oqs.Signature("ML-DSA-44")
    obu_pqc_pub = obu_pqc.generate_keypair()
    obu_pqc_priv = obu_pqc.export_secret_key()

    with open(f"OBU/keys/{obu_id}_ecc_pub.key", "wb") as f:
        f.write(obu_ecc_pub_bytes)

    with open(f"OBU/keys/{obu_id}_ecc_priv.key", "wb") as f:
        f.write(obu_ecc_priv.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption() # 專題演示建議先不加密
        ))

    with open(f"OBU/keys/{obu_id}_pqc_pub.key", "wb") as f:
        f.write(obu_pqc_pub)
    
    with open(f"OBU/keys/{obu_id}_pqc_priv.key", "wb") as f:
        f.write(obu_pqc_priv)

    short_cert, full_cert = issue_obu_certificate(obu_id, obu_ecc_pub_bytes, obu_pqc_pub)
    if short_cert is not None:
        with open(f"OBU/cert/{obu_id}_short_cert.bin", "wb") as f:
            f.write(short_cert)
    if full_cert is not None:
        with open(f"OBU/cert/{obu_id}_full_cert.bin", "wb") as f:
            f.write(full_cert)

    return short_cert, full_cert
if __name__ == "__main__":
    if setup(OBU_ID):
        print(f"{OBU_ID} 的金鑰和憑證已成功生成！")
    else:
        print(f"{OBU_ID} 的金鑰和憑證生成失敗！")