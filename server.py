import socket
import threading
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import pickle
import base64

HOST = '127.0.0.1'
PORT = 5555

key = Fernet.generate_key()
cipher = Fernet(key)

clients = {}

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen()
print(f"Server avviato su {HOST}:{PORT}")

def derive_key(password: str, salt: bytes = None):
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt

def handle_client(client_socket, address):
    client_socket.send(pickle.dumps(key))
    encrypted_username = client_socket.recv(1024)
    username = cipher.decrypt(encrypted_username).decode('utf-8')
    clients[client_socket] = username
    broadcast(f"{username} si è connesso alla chat!".encode('utf-8'))
    print(f"Connessione da {address} - Username: {username}")
    while True:
        try:
            encrypted_message = client_socket.recv(1024)
            if not encrypted_message:
                break
            message = cipher.decrypt(encrypted_message).decode('utf-8')
            broadcast(f"{username}: {message}".encode('utf-8'))
        except:
            break
    client_socket.close()
    del clients[client_socket]
    broadcast(f"{username} ha lasciato la chat!".encode('utf-8'))

def broadcast(message):
    encrypted_message = cipher.encrypt(message)
    for client in clients:
        try:
            client.send(encrypted_message)
        except:
            continue

def start_server():
    while True:
        client_socket, address = server.accept()
        thread = threading.Thread(target=handle_client, args=(client_socket, address))
        thread.start()
        print(f"Client attivi: {threading.active_count() - 1}")

if __name__ == "__main__":
    start_server()