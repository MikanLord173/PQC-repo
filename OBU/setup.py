import oqs, struct, os, argparse, hashlib
from ecdsa import SigningKey, NIST256p
from ecdsa.util import randrange
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

def generate_enrollment_request():
    curve = NIST256p
    G = curve.generator
    n = curve.order
    
    # 1. 產生 OBU 的隨機貢獻值 k_U (必須保存在 OBU 記憶體中，等 CA 回傳後要用)
    k_U = randrange(n)
    
    # 2. 計算請求點 R_U
    R_U = k_U * G
    R_U_bytes = R_U.to_bytes("compressed") # 壓成 33 bytes
    
    return k_U, R_U_bytes

def obu_derive_key(obu_id: str, P_U_bytes: bytes, obu_pqc_pub: bytes, r: int, k_U: int):
    curve = NIST256p
    n = curve.order
    
    # 1. OBU 重算相同的雜湊糾纏值 e
    entangled_data = obu_id.encode() + P_U_bytes + obu_pqc_pub
    e = int(hashlib.sha256(entangled_data).hexdigest(), 16) % n
    
    # 2. 推導真正的 ECC 私鑰 d_U
    d_U = (e * k_U + r) % n
    return d_U

# 向CA傳送OBU ID, ECC公鑰及PQC公鑰，請求憑證
def request(ca_ip, ca_port, obu_id, R_U_bytes, obu_pqc_pub):
    # Create TCP socket for CA
    clientSocket = socket(AF_INET, SOCK_STREAM)
    # Connect the socket to CA's IP and port
    clientSocket.connect((ca_ip, ca_port))
    try:
        # 打包header：OBU識別碼 0x57 | OBU ID (8 bytes) | PQC公鑰長度 (2 bytes)
        req_header = struct.pack('!B8sBH', 0x57, obu_id.encode(), len(obu_pqc_pub))
        message = req_header + R_U_bytes + obu_pqc_pub

        # Attach CA IP and port to message, send into socket
        clientSocket.sendto(message, (CA_IP, CA_PORT))

        recv_header = recv_all(clientSocket, 4)
        response_len = struct.unpack('!I', recv_header)[0]

        response = recv_all(clientSocket, response_len)
    except Exception as e:
        print(e)
        response = None

    clientSocket.close()
    return response

def setup(obu_id):

    # 準備 ECC 金鑰
    '''
    print("正在準備ECC/PQC金鑰對...")
    obu_ecc_priv = ec.generate_private_key(ec.SECP256R1())
    obu_ecc_pub_bytes = obu_ecc_priv.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    with open(f"OBU/keys/{obu_id}_ecc_pub.key", "wb") as f:
        f.write(obu_ecc_pub_bytes)

    with open(f"OBU/keys/{obu_id}_ecc_priv.key", "wb") as f:
        f.write(obu_ecc_priv.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption() # 專題演示建議先不加密
        ))
    '''

    # 產生一次性密碼學隨機數 k_U
    # 並利用 k_U算出請求點 R_U (R_U = k_U * G)，壓縮為 33 byte
    k_U, R_U_bytes = generate_enrollment_request()

    # 準備 PQC 金鑰 (ML-DSA-44)
    obu_pqc = oqs.Signature("ML-DSA-44")
    obu_pqc_pub = obu_pqc.generate_keypair()
    obu_pqc_priv = obu_pqc.export_secret_key()

    with open(f"OBU/keys/{obu_id}_pqc_pub.key", "wb") as f:
        f.write(obu_pqc_pub)
    
    with open(f"OBU/keys/{obu_id}_pqc_priv.key", "wb") as f:
        f.write(obu_pqc_priv)
    print("金鑰對建立成功！")

    # 將 [車輛 ID, 33-byte 的 RU, 巨大的 PQC 公鑰 pk_U] 傳給 CA。
    print("正在向CA請求憑證...")
    response = request(CA_IP, CA_PORT, obu_id, R_U_bytes, obu_pqc_pub)

    # 接收 P_U, CA_PQC_SIG, r
    if response is not None:
        P_U_bytes, r_bytes, sig_len = struct.unpack("!33s 32s H", response[:67])
        ca_pqc_sig = struct.unpack(f"!{sig_len}s", response[67 : 67 + sig_len])[0]
        # 位元組轉數字：將 r_bytes 轉回 Python 大整數
        r_int = int.from_bytes(r_bytes, byteorder='big')
        with open(f"OBU/cert/{obu_id}_cert.bin", "wb") as f:
            f.write(response)
    else:
        print("憑證請求失敗！")

    # 重新計算雜湊糾纏值 e
    # 利用算出的 e、收到的 r 與自己記憶體裡的 k_U，推導出真正的 ECC 私鑰 d_U = (e * k_U + r) % n
    d_U = obu_derive_key(obu_id, P_U_bytes, obu_pqc_pub, r_int, k_U)

    # 將 d_U, P_U 和 ca_pqc_sig 存在本地
    obu_ecc_sk = SigningKey.from_secret_exponent(d_U, curve=NIST256p)
    with open(f"OBU/keys/{obu_id}_ecc_priv.key", "wb") as f:
        f.write(obu_ecc_sk.to_pem())
    with open(f"OBU/bin/{obu_id}_ca_pqc_sig.bin", "wb") as f:
        f.write(ca_pqc_sig)
    with open(f"OBU/bin/{obu_id}_P_U.bin", "wb") as f:
        f.write(P_U_bytes)
    # 從記憶體中銷毀 k_U 與 r


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("obu_id", type=str, help="緊急車輛的編號")
    args = parser.parse_args()

    if setup(args.obu_id):
        print(f"{args.obu_id} 的金鑰和憑證已成功生成！")
    else:
        print(f"{args.obu_id} 的金鑰和憑證生成失敗！")