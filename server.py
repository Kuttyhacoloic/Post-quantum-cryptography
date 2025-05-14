# secure_file_transfer/server.py (Production Version)

import socket
import struct
import os
import logging
from datetime import datetime
from encryption_utils import derive_shared_key, decrypt_file
from simulated_kyber import generate_shared_secret

HOST = '0.0.0.0'
PORT = 5001
SAVE_DIR = 'received_files'
BUFFER_SIZE = 4096

# Setup logging
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(message)s', datefmt='%H:%M:%S')
os.makedirs(SAVE_DIR, exist_ok=True)

def recv_data(sock):
    raw_len = sock.recv(4)
    if not raw_len:
        return None
    length = struct.unpack('!I', raw_len)[0]
    data = b''
    while len(data) < length:
        chunk = sock.recv(min(BUFFER_SIZE, length - len(data)))
        if not chunk:
            raise ConnectionError("Connection lost during recv_data.")
        data += chunk
    return data

def run_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen(5)
        logging.info(f"Server listening on {HOST}:{PORT}")

        while True:
            conn, addr = server.accept()
            with conn:
                logging.info(f"Connection established from {addr}")

                try:
                    shared_secret = recv_data(conn)
                    aes_key = derive_shared_key(shared_secret)
                    file_name = recv_data(conn).decode()
                    encrypted_data = recv_data(conn)

                    decrypted_data = decrypt_file(encrypted_data, aes_key)
                    file_path = os.path.join(SAVE_DIR, f"received_{file_name}")

                    with open(file_path, 'wb') as f:
                        f.write(decrypted_data)

                    logging.info(f"File '{file_name}' received and saved to '{file_path}'")
                except Exception as e:
                    logging.error(f"Failed to process file: {e}")

if __name__ == '__main__':
    run_server()

