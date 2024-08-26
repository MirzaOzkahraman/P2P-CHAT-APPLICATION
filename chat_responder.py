import secrets
import socket
import json
import threading
from datetime import datetime
from peer_utils import load_peers, update_peers, cleanup_peers, save_peers
import hashlib
from pyDes import des, ECB, PAD_PKCS5

PEERS = load_peers()

LOG_FILE = "chat_history.log"

p = 23
g = 5

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('', 6001))
    server.listen(5)
    print("Server is listening on port 6001...")
    
    try:
        while True:
            client, addr = server.accept()
            print(f"Connection from {addr}")
            threading.Thread(target=handle_client, args=(client, addr)).start()
    except Exception as e:
        print(f"Server error: {str(e)}")
    finally:
        server.close()

def get_username_from_ip(ip):
    for key, value in PEERS.items():
        if value['ip'] == ip:
            return value['username']
    return "Friend"

def handle_client(client, addr):
    username = get_username_from_ip(addr[0])
    shared_key = None
    try:
        while True:
            message = client.recv(1024).decode()
            if not message:
                break
            data = json.loads(message)
            if 'key' in data:
                shared_key = perform_dh_key_exchange(client, data['key'])
            elif 'encrypted_message' in data and shared_key:
                decrypted_message = decrypt_message(data['encrypted_message'], shared_key)
                print(f"Decrypted message from {username}: {decrypted_message}")
                response_message = input("Enter your response: ")
                send_response(client, response_message, shared_key)
            elif 'unencrypted_message' in data:
                print(f"Message from {username}: {data['unencrypted_message']}")
                response_message = input("Enter your response: ")
                send_response(client, response_message, None)
            else:
                print(f"Unknown message format from {username}")
    finally:
        client.close()

def perform_dh_key_exchange(client, peer_public_key):
    private_key = secrets.randbelow(p)
    public_key = pow(g, private_key, p)
    client.sendall(json.dumps({"key": public_key}).encode())
    shared_secret = pow(int(peer_public_key), private_key, p)
    shared_key = hashlib.sha256(str(shared_secret).encode()).digest()[:8]
    return shared_key

def encrypt_message(message, shared_key):
    des_cipher = des(shared_key, ECB, padmode=PAD_PKCS5)
    encrypted_message = des_cipher.encrypt(message)
    return encrypted_message.hex()

def decrypt_message(encrypted_message, shared_key):
    des_cipher = des(shared_key, ECB, padmode=PAD_PKCS5)
    decrypted_message = des_cipher.decrypt(bytes.fromhex(encrypted_message))
    return decrypted_message.decode()

def send_response(client, response_message, shared_key):
    if shared_key:
        encrypted_response = encrypt_message(response_message, shared_key)
        json_response = json.dumps({"encrypted_message": encrypted_response})
    else:
        json_response = json.dumps({"unencrypted_message": response_message})
    client.sendall(json_response.encode())

if __name__ == "__main__":
    start_server()
