import oqs, struct
from socket import *

CA_IP = '127.0.0.1'
CA_PORT = 57217
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

# 向CA傳送識別碼，請求公鑰
def request_ca_pub(ca_ip, ca_port):
    # Create TCP socket for CA
    clientSocket = socket(AF_INET, SOCK_STREAM)
    # Connect the socket to CA's IP and port
    clientSocket.connect((ca_ip, ca_port))
    try:
        # 打包訊息：只有RSU識別碼 0x67
        message = struct.pack('!B', 0x67)
        # Attach CA IP and port to message, send into socket
        clientSocket.sendto(message, (CA_IP, CA_PORT))

        # header: | CA ECC公鑰長度 (1 byte) | CA PQ公鑰長度 (2 bytes) |
        recv_header = recv_all(clientSocket, 3)
        ecc_len, pqc_len = struct.unpack('!BH', recv_header)
        ecc_pub = recv_all(clientSocket, ecc_len)
        pqc_pub = recv_all(clientSocket, pqc_len)
    except Exception as e:
        print(e)
        ecc_pub, pqc_pub = None, None

    clientSocket.close()
    return ecc_pub, pqc_pub

if __name__ == "__main__":
    ca_ecc_pub, ca_pqc_pub = request_ca_pub(CA_IP, CA_PORT)
    if ca_ecc_pub is not None:
        with open(f"RSU/keys/ca_ecc_pub.key", "wb") as f:
            f.write(ca_ecc_pub)
    if ca_pqc_pub is not None:
        with open(f"RSU/keys/ca_pqc_pub.key", "wb") as f:
            f.write(ca_pqc_pub)

    if ca_ecc_pub and ca_pqc_pub:
        print(f"已成功請求CA公鑰！")
    else:
        print(f"CA公鑰請求失敗！")