import socket
import json
import time
from datetime import datetime, timedelta
from peer_utils import load_peers, save_peers, update_peers, cleanup_peers
import threading
import secrets
import hashlib
from pyDes import des, ECB, PAD_PKCS5

PEERS = {}
LOG_FILE = "chat_history.log"

p = 23
g = 5

user_name = ""
target_username = ""
exit_event = threading.Event()

def main_menu():
    global user_name
    user_name = input("Please enter your username: ")
    while True:
        global PEERS
        PEERS = load_peers()
        print(f"\nMain Menu for {user_name}:")
        print("1. View Users")
        print("2. Start Chat")
        print("3. View History")
        choice = input("Enter your choice (1/2/3): ").lower()
        if choice in ['1', 'users']:
            display_users()
        elif choice in ['2', 'chat']:
            exit_event.clear()
            initiate_chat(user_name)
        elif choice in ['3', 'history']:
            view_history()
        else:
            print("Invalid choice. Please try again.")

def display_users():
    global PEERS
    PEERS = load_peers()
    print("\nCurrent Users:")
    current_time = datetime.now()
    if not PEERS:
        print("No users found.")
        return
    for key, info in PEERS.items():
        username = info['username']
        last_seen = datetime.strptime(info['last_seen'], '%Y-%m-%d %H:%M:%S')
        if (current_time - last_seen) <= timedelta(seconds=10):
            status = "Online"
        else:
            status = "Away"
        print(f"{username} - {status}")

def initiate_chat(user_name):
    display_users()
    global target_username
    target_username = input("Enter the username to chat with: ")
    if target_username not in [info['username'] for info in PEERS.values()]:
        print("User not found.")
        return
    secure = input("Do you want to chat securely? (yes/no): ").lower()
    initiate_tcp_session(user_name, target_username, secure == 'yes')

def receive_messages(sock, shared_key=None):
    global target_username
    while not exit_event.is_set():
        try:
            incoming_message = sock.recv(1024).decode()
            if not incoming_message:
                print("Server closed the connection.")
                break
            data = json.loads(incoming_message)
            if 'encrypted_message' in data and shared_key:
                decrypted_message = decrypt_message(data['encrypted_message'], shared_key)
                print(f"\nReceived from {target_username}: {decrypted_message}")
                log_message(target_username, decrypted_message, "RECEIVED")
            elif 'unencrypted_message' in data:
                print(f"\nReceived from {target_username}: {data['unencrypted_message']}")
                log_message(target_username, data['unencrypted_message'], "RECEIVED")
            print(f"{user_name} (type 'exit' to quit): ", end='', flush=True)
        except Exception as e:
            if not exit_event.is_set():
                print(f"Error receiving message: {e}")
            break

def initiate_tcp_session(user_name, target_username, secure):
    try:
        # For demonstration purposes, replace with the actual peer IP
        target_info = next((info for info in PEERS.values() if info['username'] == target_username), None)
        if not target_info:
            print(f"IP address for {target_username} not found.")
            return
        
        target_ip = target_info['ip']

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            print(f"Attempting to connect to {target_username} at {target_ip}...")
            sock.connect((target_ip, 6002))
            print(f"Connected to {target_username} at {target_ip}")

            shared_key = None
            if secure:
                shared_key = perform_key_exchange(sock)
                print("Key exchange completed")

            threading.Thread(target=receive_messages, args=(sock, shared_key), daemon=True).start()
            prompt_user_message(sock, user_name, target_username, shared_key, secure)
            print("Closing connection.")
    except socket.error as e:
        print(f"Network error: {e}")
    except KeyError:
        print(f"User '{target_username}' not found in PEERS list.")
    except Exception as e:
        print(f"Failed to establish connection: {str(e)}")

def prompt_user_message(sock, user_name, target_username, shared_key, secure):
    while not exit_event.is_set():
        message = input(f"{user_name} (type 'exit' to quit): ")
        if message.lower() == 'exit':
            exit_event.set()
            break
        if sock:
            try:
                if secure and shared_key:
                    encrypted_message = encrypt_message(message, shared_key)
                    json_msg = json.dumps({"username": user_name, "encrypted_message": encrypted_message})
                else:
                    json_msg = json.dumps({"username": user_name, "unencrypted_message": message})
                sock.sendall(json_msg.encode())
                log_message(target_username, message, "SENT")
            except Exception as e:
                print(f"Error sending message: {e}")

def perform_key_exchange(sock):
    try:
        private_key = secrets.randbelow(p)
        public_key = pow(g, private_key, p)
        sock.sendall(json.dumps({"key": public_key}).encode())
        peer_key_data = json.loads(sock.recv(1024).decode())
        peer_public_key = peer_key_data["key"]
        shared_secret = pow(int(peer_public_key), private_key, p)
        shared_key = hashlib.sha256(str(shared_secret).encode()).digest()[:8]
        return shared_key
    except Exception as e:
        print(f"Key exchange failed: {e}")
        raise

def encrypt_message(message, shared_key):
    try:
        des_cipher = des(shared_key, ECB, padmode=PAD_PKCS5)
        encrypted_message = des_cipher.encrypt(message)
        return encrypted_message.hex()
    except Exception as e:
        print(f"Encryption failed: {e}")
        raise

def decrypt_message(encrypted_message, shared_key):
    try:
        des_cipher = des(shared_key, ECB, padmode=PAD_PKCS5)
        decrypted_message = des_cipher.decrypt(bytes.fromhex(encrypted_message))
        return decrypted_message.decode()
    except Exception as e:
        print(f"Decryption failed: {e}")
        raise

def log_message(other_user, message, status):
    if status in ["SENT", "RECEIVED"]:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        direction = "to" if status == "SENT" else "from"
        with open(LOG_FILE, 'a') as f:
            f.write(f"{timestamp} - {status} {direction} {other_user}: {message}\n")

def view_history():
    try:
        with open(LOG_FILE, 'r') as f:
            print("\nChat History:")
            for line in f:
                print(line.strip())
    except FileNotFoundError:
        print("No history available.")

if __name__ == "__main__":
    main_menu()
