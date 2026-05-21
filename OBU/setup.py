import oqs, struct, os, argparse
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from socket import *
from dotenv import load_dotenv

load_dotenv()

CA_IP = os.getenv("CA_IP", "127.0.0.1")
CA_PORT = int(os.getenv("CA_PORT", 57217))
BUF_SIZE = 4096 

def recv_all(sock, count):
    """循環使用 4096 buffer size 讀取，讀取到 count bytes"""
    buffer = b''
    while(len(buffer) < count):
        to_read = min(count-len(buffer), BUF_SIZE)
        chunk = sock.recv(to_read)
        if not chunk:
            return None
        buffer += chunk
    return buffer

# 向CA傳送OBU ID, ECC公鑰及PQC公鑰，請求憑證
def request_cert(ca_ip, ca_port, obu_id, obu_ecc_pub, obu_pqc_pub):
    # Create TCP socket for CA
    clientSocket = socket(AF_INET, SOCK_STREAM)
    # Connect the socket to CA's IP and port
    clientSocket.connect((ca_ip, ca_port))
    try:
        # 打包header：OBU識別碼 0x57 | OBU ID (8 bytes) | ECC公鑰長度 (1 byte) | PQC公鑰長度 (2 bytes)
        req_header = struct.pack('!B8sBH', 0x57, obu_id.encode(), len(obu_ecc_pub), len(obu_pqc_pub))
        message = req_header + obu_ecc_pub + obu_pqc_pub

        # Attach CA IP and port to message, send into socket
        clientSocket.sendto(message, (CA_IP, CA_PORT))

        recv_header = recv_all(clientSocket, 4)
        cert_len = struct.unpack('!I', recv_header)[0]

        cert = recv_all(clientSocket, cert_len)
    except Exception as e:
        print(e)
        cert = None

    clientSocket.close()
    return cert

def setup(obu_id):

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

    cert = request_cert(CA_IP, CA_PORT, obu_id, obu_ecc_pub_bytes, obu_pqc_pub)
    if cert is not None:
        with open(f"OBU/cert/{obu_id}_cert.bin", "wb") as f:
            f.write(cert)

    return cert
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("obu_id", type=str, help="緊急車輛的編號")
    args = parser.parse_args()

    if setup(args.obu_id):
        print(f"{args.obu_id} 的金鑰和憑證已成功生成！")
    else:
        print(f"{args.obu_id} 的金鑰和憑證生成失敗！")