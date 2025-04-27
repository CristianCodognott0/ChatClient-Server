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

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((HOST, PORT))

key = pickle.loads(client.recv(1024))
cipher = Fernet(key)

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

username = input("Inserisci il tuo username: ")
encrypted_username = cipher.encrypt(username.encode('utf-8'))
client.send(encrypted_username)

def receive_messages():
    while True:
        try:
            encrypted_message = client.recv(1024)
            message = cipher.decrypt(encrypted_message).decode('utf-8')
            print(message)
        except:
            print("Errore nella connessione al server.")
            client.close()
            break

def send_messages():
    while True:
        message = input("")
        encrypted_message = cipher.encrypt(message.encode('utf-8'))
        client.send(encrypted_message)

receive_thread = threading.Thread(target=receive_messages)
receive_thread.start()

send_thread = threading.Thread(target=send_messages)
send_thread.start()