
# secure_file_transfer/gui_client.py

import sys
import os
import socket
import struct
import logging
from PyQt6.QtWidgets import QApplication, QWidget, QLabel, QVBoxLayout, QPushButton, QFileDialog, QMessageBox
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
        return False, "File does not exist."

    file_name = os.path.basename(file_path)

    try:
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
            return True, "File sent successfully."

    except Exception as e:
        logging.error(f"Error sending file: {e}")
        return False, str(e)

class FileTransferApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Secure File Transfer Client")
        self.setGeometry(100, 100, 400, 200)
        self.layout = QVBoxLayout()

        self.label = QLabel("Select a file to send to the server.")
        self.button = QPushButton("Choose File and Send")
        self.button.clicked.connect(self.choose_file)

        self.layout.addWidget(self.label)
        self.layout.addWidget(self.button)
        self.setLayout(self.layout)

    def choose_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if file_path:
            success, message = run_client(file_path)
            QMessageBox.information(self, "Result", message if success else f"Failed: {message}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = FileTransferApp()
    window.show()
    sys.exit(app.exec())
