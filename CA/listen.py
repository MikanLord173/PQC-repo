import struct, os
from socket import *
from CA.sign import issue_obu_certificate
from dotenv import load_dotenv

load_dotenv()

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
        if id_code == 0x57:     # OBU
            # | 識別碼 (1 byte) | OBU ID (8 bytes) | ECC公鑰長度 (1 byte) | PQC公鑰長度 (2 bytes) | -> 不含識別碼 11 bytes
            req_header = recv_all(connectionSocket, 11)
            obu_id, obu_ecc_pub_len, obu_pqc_pub_len = struct.unpack('!8sBH', req_header)
            obu_id = obu_id.decode('utf-8')
            print(f"已接收到 OBU {obu_id} 的請求")

            obu_ecc_pub = recv_all(connectionSocket, obu_ecc_pub_len)
            obu_pqc_pub = recv_all(connectionSocket, obu_pqc_pub_len)

            cert = issue_obu_certificate(obu_id, obu_ecc_pub, obu_pqc_pub)
            reply_header = struct.pack('!I', len(cert))
            reply = cert
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
            reply_header = None
            reply = None

        # Send certificate / pub keys back to OBU / RSU
        connectionSocket.sendall(reply_header + reply)
        print("Message sent")

    serverSocket.close()

if __name__ == "__main__":
    main()