from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
import oqs
import pki

def generate_ca_root_keys():
    # 1. 產生 CA 的 ECC 金鑰 (Root)
    ca_ecc_priv = ec.generate_private_key(ec.SECP256R1())
    ca_ecc_pub = ca_ecc_priv.public_key()
    
    # 2. 產生 CA 的 PQC 金鑰 (Root)
    ca_pqc = oqs.Signature(pki.pqc_alg())
    ca_pqc_pub = ca_pqc.generate_keypair()
    ca_pqc_priv = ca_pqc.export_secret_key()
    
    return ca_ecc_pub, ca_ecc_priv, ca_pqc_pub, ca_pqc_priv

def write_ca_root_keys():
    """產生 CA 根金鑰並寫入 CA/keys/ (相對於目前工作目錄)。"""
    import os
    os.makedirs("CA/keys", exist_ok=True)
    ca_ecc_pub, ca_ecc_priv, ca_pqc_pub, ca_pqc_priv = generate_ca_root_keys()

    with open("CA/keys/ca_ecc_pub.key", "wb") as f:
        f.write(ca_ecc_pub.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    with open("CA/keys/ca_ecc_priv.key", "wb") as f:
        f.write(ca_ecc_priv.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption() # 專題演示建議先不加密
        ))

    with open("CA/keys/ca_pqc_pub.key", "wb") as f:
        f.write(ca_pqc_pub)
    
    with open("CA/keys/ca_pqc_priv.key", "wb") as f:
        f.write(ca_pqc_priv)

    print(f"已成功生成 CA 的 ECC 和 PQC ({pki.pqc_alg()}) 金鑰對！")


if __name__ == "__main__":
    write_ca_root_keys()