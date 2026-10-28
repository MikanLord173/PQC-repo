import struct, os
from socket import *
from CA.sign import issue_obu_certificate
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    # 若環境未安裝 python-dotenv，純 Python 自行解析 .env
    if os.path.exists(".env"):
        with open(".env", "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))

CA_PORT = int(os.getenv("CA_PORT", 57217))
BUF_SIZE = 4096 

def get_local_ip():
    s = socket(AF_INET, SOCK_DGRAM)
    try:
        # 這裡的 IP 是 Google Public DNS，不需要真的連通
        # 只是藉由測試連線來逼作業系統吐出目前作用中的區域網路 IP
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    except Exception:
        # 如果完全沒網路（例如單機離線），就退回 localhost
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip

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

def handle_enrollment(obu_id_raw, obu_R_U_bytes, obu_pqc_pub, tag, registry=None):
    """
    【安全修正 F-3】原本對任何 0x57 請求都直接發憑證 (可冒名註冊 AMB-217)。
    現在先以 CA 名冊驗證申請者，角色取自名冊。
    回傳：[P_U | r | role | ca_pqc_sig_len | ca_pqc_sig | ca_ecc_pub_len (1B) | ca_ecc_pub]，拒絕時回傳 None。
    附上 CA ECC 根公鑰，供 OBU 驗證 RSU 下行 SSM 的憑證 (F-6)。
    """
    from CA.enroll import authenticate_enrollment, ca_process_enrollment
    role = authenticate_enrollment(obu_id_raw, obu_R_U_bytes, obu_pqc_pub, tag or b'', registry=registry)
    if role is None:
        return None
    with open('CA/keys/ca_ecc_pub.key', 'rb') as f:
        ca_ecc_pub = f.read()
    cert_data = ca_process_enrollment(obu_id_raw, obu_R_U_bytes, obu_pqc_pub, role)
    return cert_data + struct.pack('!B', len(ca_ecc_pub)) + ca_ecc_pub

def main():
    # Create TCP socket
    serverSocket = socket(AF_INET, SOCK_STREAM)
    # If this address is in use, reuse it instead of throwing an error
    serverSocket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    # Bind socket to local port num 57217
    serverSocket.bind(('0.0.0.0', CA_PORT))

    # Listen for incoming connections, with a queue of 1 connection
    serverSocket.listen(5)
    print(f"The server is ready to receive, IP: {get_local_ip()}")

    while True:
        # Accept a connection, getting a new socket to send data on, and the client's address
        # Code will block here until a client connects
        connectionSocket, addr = serverSocket.accept()
        print(f"Connection from {addr} has been established.")

        id_code = struct.unpack('!B', recv_all(connectionSocket, 1))[0]
        if id_code == 0x57:     # OBU ECQV 註冊請求
            # Header: OBU ID (8 bytes) | PQC公鑰長度 (2 bytes) -> 共 10 bytes
            req_header = recv_all(connectionSocket, 10)
            obu_id_raw, obu_pqc_pub_len = struct.unpack('!8sH', req_header)
            obu_id_str = obu_id_raw.rstrip(b'\x00').decode('utf-8')
            print(f"已接收到 OBU {obu_id_str} 的 ECQV 註冊請求")

            # 接收 33 bytes 的 R_U 請求點、PQC 公鑰本體與 32 bytes 註冊驗證碼 (HMAC)
            obu_R_U_bytes = recv_all(connectionSocket, 33)
            obu_pqc_pub = recv_all(connectionSocket, obu_pqc_pub_len)
            tag = recv_all(connectionSocket, 32)

            cert_data = handle_enrollment(obu_id_raw, obu_R_U_bytes, obu_pqc_pub, tag)
            if cert_data is None:
                print(f"[拒絕] {obu_id_str} 未登記於 CA 名冊或註冊驗證碼錯誤，不發憑證")
                cert_data = b''   # 長度 0 = 拒絕

            reply_header = struct.pack('!I', len(cert_data))
            reply = cert_data
        elif id_code == 0x67:   # RSU，只傳識別碼
            print(f"已接收到 RSU 的請求")
            with open('CA/keys/ca_ecc_pub.key', 'rb') as f:
                ca_ecc_pub = f.read()
            with open('CA/keys/ca_pqc_pub.key', 'rb') as f:
                ca_pqc_pub = f.read()

            reply_header = struct.pack('!BH', len(ca_ecc_pub), len(ca_pqc_pub))
            reply = ca_ecc_pub + ca_pqc_pub
        else:
            print("Not OBU nor RSU, skipped.")
            connectionSocket.close()
            continue

        # Send certificate / pub keys back to OBU / RSU
        connectionSocket.sendall(reply_header + reply)
        print("Message sent")
        connectionSocket.close()

    serverSocket.close()

if __name__ == "__main__":
    main()