import os, struct
from socket import *
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    if os.path.exists(".env"):
        with open(".env", "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))

CA_IP = os.getenv("CA_IP", "127.0.0.1")
CA_PORT = int(os.getenv("CA_PORT", 57217))
BUF_SIZE = 4096

def recv_all(sock, count):
    """循環讀取至指定 count bytes"""
    buffer = b''
    while len(buffer) < count:
        to_read = min(count - len(buffer), BUF_SIZE)
        chunk = sock.recv(to_read)
        if not chunk:
            return None
        buffer += chunk
    return buffer

# 向 CA 請求 ECC 與 PQC 根公鑰
def fetch_ca_keys(ca_ip=CA_IP, ca_port=CA_PORT):
    os.makedirs("RSU/keys", exist_ok=True)
    try:
        print(f"向 CA 伺服器 ({ca_ip}:{ca_port}) 取得公鑰 (TCP 0x67)...")
        clientSocket = socket(AF_INET, SOCK_STREAM)
        clientSocket.settimeout(5)
        clientSocket.connect((ca_ip, ca_port))
        # 發送 RSU 識別碼 0x67
        clientSocket.sendall(struct.pack('!B', 0x67))
        # 接收標頭：ECC公鑰長度 (1 byte) | PQC公鑰長度 (2 bytes)
        reply_header = recv_all(clientSocket, 3)
        if not reply_header:
            clientSocket.close()
            raise Exception("未收到 CA 回應標頭")

        ecc_pub_len, pqc_pub_len = struct.unpack('!BH', reply_header)
        ca_ecc_pub = recv_all(clientSocket, ecc_pub_len)
        ca_pqc_pub = recv_all(clientSocket, pqc_pub_len)
        clientSocket.close()

        with open("RSU/keys/ca_ecc_pub.key", "wb") as f:
            f.write(ca_ecc_pub)
        with open("RSU/keys/ca_pqc_pub.key", "wb") as f:
            f.write(ca_pqc_pub)

        print("成功配置 CA 公鑰！")
        return True

    except Exception as e:
        print(f"遠端 CA 未連線 ({e})，改從本地 CA/keys/ 複製...")
        if os.path.exists("CA/keys/ca_ecc_pub.key") and os.path.exists("CA/keys/ca_pqc_pub.key"):
            with open("CA/keys/ca_ecc_pub.key", "rb") as f_in, open("RSU/keys/ca_ecc_pub.key", "wb") as f_out:
                f_out.write(f_in.read())
            with open("CA/keys/ca_pqc_pub.key", "rb") as f_in, open("RSU/keys/ca_pqc_pub.key", "wb") as f_out:
                f_out.write(f_in.read())
            print("已從本地 CA/keys 成功複製公鑰！")
            return True
        else:
            print("找不到本地公鑰，請先在 CA 端執行 CA.gen_keys！")
            return False

def provision_rsu_keys(rsu_ids=(1, 2, 3, 4)):
    """
    【安全修正 F-6】為每個路口 RSU 產生 ECDSA 金鑰，並由 CA 簽發 RSU 憑證，用於簽署下行 SSM。
    RSU 由道路主管機關佈建，視同在受控環境配發 (直接呼叫本地 CA 簽發，不經公開網路)。
    輸出：RSU/keys/rsu_<id>_ecc_priv.key、RSU/keys/rsu_<id>_cert.json
    """
    import base64, json
    from ecdsa import SigningKey, NIST256p
    from CA.enroll import issue_rsu_certificate
    if not os.path.exists("CA/keys/ca_ecc_priv.key"):
        print("找不到 CA/keys/ca_ecc_priv.key，無法簽發 RSU 憑證 (需在 CA 端執行)")
        return False
    os.makedirs("RSU/keys", exist_ok=True)
    for rsu_id in rsu_ids:
        sk = SigningKey.generate(curve=NIST256p)
        pub = sk.get_verifying_key().to_string()          # 64B 未壓縮 (x‖y)
        cert = {"rsu_id": rsu_id,
                "pub": base64.b64encode(pub).decode("ascii"),
                "ca_sig": base64.b64encode(issue_rsu_certificate(rsu_id, pub)).decode("ascii")}
        with open(f"RSU/keys/rsu_{rsu_id}_ecc_priv.key", "wb") as f:
            f.write(sk.to_der())
        with open(f"RSU/keys/rsu_{rsu_id}_cert.json", "w", encoding="utf-8") as f:
            json.dump(cert, f)
    print(f"已為 RSU {list(rsu_ids)} 配發 SSM 簽章金鑰與 CA 憑證")
    return True

if __name__ == "__main__":
    if fetch_ca_keys():
        provision_rsu_keys()
