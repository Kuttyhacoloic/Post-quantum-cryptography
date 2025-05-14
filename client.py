# secure_file_transfer/client.py (Production Version)

import socket
import struct
import os
import logging
from encryption_utils import derive_shared_key, encrypt_file
from simulated_kyber import generate_shared_secret

HOST = '127.0.0.1'
PORT = 5001
BUFFER_SIZE = 4096

# Setup logging
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(message)s', datefmt='%H:%M:%S')


def send_data(sock, data):
    sock.sendall(struct.pack('!I', len(data)) + data)

def run_client(file_path):
    if not os.path.exists(file_path):
        logging.error(f"File '{file_path}' does not exist.")
        return

    file_name = os.path.basename(file_path)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        client.connect((HOST, PORT))
        logging.info(f"Connected to server at {HOST}:{PORT}")

        shared_secret = generate_shared_secret()
        aes_key = derive_shared_key(shared_secret)

        with open(file_path, 'rb') as f:
            file_data = f.read()

        encrypted_data = encrypt_file(file_data, aes_key)

        send_data(client, shared_secret)             # Send key
        send_data(client, file_name.encode())        # Send file name
        send_data(client, encrypted_data)            # Send encrypted file

        logging.info(f"File '{file_name}' sent successfully.")

if __name__ == '__main__':
    filepath = input("Enter the path of the file to send: ").strip()
    run_client(filepath)
