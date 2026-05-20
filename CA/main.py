import struct
from socket import *
from CA.sign import issue_obu_certificate

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

def main():
    # Create TCP socket
    serverSocket = socket(AF_INET, SOCK_STREAM)
    # If this address is in use, reuse it instead of throwing an error
    serverSocket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    # Bind socket to local port num 57217
    serverSocket.bind(('', CA_PORT))

    # Listen for incoming connections, with a queue of 1 connection
    serverSocket.listen(1)
    print("The server is ready to receive")

    # Accept a connection, getting a new socket to send data on, and the OBU's address
    # Code will block here until a OBU connects
    connectionSocket, addr = serverSocket.accept()
    print(f"Connection from {addr} has been established.")

    # OBU ID (8 bytes) | ECC公鑰長度 (1 byte) | PQC公鑰長度 (2 bytes) -> 11 bytes
    req_header = recv_all(connectionSocket, 11)
    obu_id, obu_ecc_pub_len, obu_pqc_pub_len = struct.unpack('8sBH', req_header)

    obu_ecc_pub = recv_all(connectionSocket, obu_ecc_pub_len)
    obu_pqc_pub = recv_all(connectionSocket, obu_pqc_pub_len)

    cert = issue_obu_certificate(obu_id, obu_ecc_pub, obu_pqc_pub)
    reply_header = struct.pack('!I', len(cert))

    # Send certificate back to this OBU
    connectionSocket.sendall(reply_header + cert)
    print("Message sent")

    serverSocket.close()

if __name__ == "__main__":
    main()