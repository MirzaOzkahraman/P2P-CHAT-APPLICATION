import socket
import json
import time
import threading
import secrets
import hashlib
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from peer_utils import load_peers, save_peers, update_peers, cleanup_peers

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    print("Warning: pycryptodome not installed. Using fallback encryption.")

# Peer storage
PEERS: Dict[str, Any] = {}
LOG_FILE = "chat_history.log"

# Diffie-Hellman parameters (RFC 3526 - 2048-bit MODP Group)
# For educational purposes, using smaller but still reasonable parameters
DH_PRIME = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16
)
DH_GENERATOR = 2

# Connection settings
CHAT_PORT = 6001  # Fixed: matches responder port
SOCKET_TIMEOUT = 30  # seconds

user_name: str = ""
target_username: str = ""
exit_event = threading.Event()


def main_menu() -> None:
    """Main menu for the chat application."""
    global user_name
    user_name = input("Please enter your username: ").strip()
    
    if not user_name:
        print("Username cannot be empty.")
        return
    
    while True:
        global PEERS
        PEERS = load_peers()
        print(f"\n{'='*40}")
        print(f"  Main Menu - {user_name}")
        print(f"{'='*40}")
        print("1. 👥 View Online Users")
        print("2. 💬 Start Chat")
        print("3. 📜 View Chat History")
        print("4. 🚪 Exit")
        print(f"{'='*40}")
        
        choice = input("Enter your choice (1-4): ").strip().lower()
        
        if choice in ['1', 'users']:
            display_users()
        elif choice in ['2', 'chat']:
            exit_event.clear()
            initiate_chat(user_name)
        elif choice in ['3', 'history']:
            view_history()
        elif choice in ['4', 'exit', 'quit']:
            print("Goodbye!")
            break
        else:
            print("Invalid choice. Please try again.")


def display_users() -> None:
    """Display all discovered peers with their online status."""
    global PEERS
    PEERS = load_peers()
    print("\n" + "="*40)
    print("  Online Users")
    print("="*40)
    
    current_time = datetime.now()
    
    if not PEERS:
        print("No users found on the network.")
        return
    
    for key, info in PEERS.items():
        username = info['username']
        last_seen = datetime.strptime(info['last_seen'], '%Y-%m-%d %H:%M:%S')
        time_diff = (current_time - last_seen).total_seconds()
        
        if time_diff <= 10:
            status = "🟢 Online"
        elif time_diff <= 60:
            status = "🟡 Away"
        else:
            status = "🔴 Offline"
        
        print(f"  {username} - {status}")
    
    print("="*40)


def initiate_chat(user_name: str) -> None:
    """Start a chat session with another user."""
    display_users()
    
    global target_username
    target_username = input("\nEnter the username to chat with: ").strip()
    
    # Check if user exists
    available_users = [info['username'] for info in PEERS.values()]
    if target_username not in available_users:
        print(f"User '{target_username}' not found.")
        return
    
    if target_username == user_name:
        print("You cannot chat with yourself.")
        return
    
    secure = input("Do you want to chat securely? (yes/no): ").strip().lower()
    initiate_tcp_session(user_name, target_username, secure in ['yes', 'y'])


def receive_messages(sock: socket.socket, shared_key: Optional[bytes] = None) -> None:
    """Receive and display incoming messages."""
    global target_username
    
    while not exit_event.is_set():
        try:
            sock.settimeout(1.0)  # Allow checking exit_event periodically
            incoming_message = sock.recv(4096).decode('utf-8')
            
            if not incoming_message:
                print("\nConnection closed by peer.")
                exit_event.set()
                break
            
            data = json.loads(incoming_message)
            
            if 'encrypted_message' in data and shared_key:
                decrypted_message = decrypt_message(data['encrypted_message'], shared_key)
                print(f"\n🔒 Received from {target_username}: {decrypted_message}")
                log_message(target_username, decrypted_message, "RECEIVED")
            elif 'unencrypted_message' in data:
                print(f"\nReceived from {target_username}: {data['unencrypted_message']}")
                log_message(target_username, data['unencrypted_message'], "RECEIVED")
            
            print(f"{user_name} (type 'exit' to quit): ", end='', flush=True)
            
        except socket.timeout:
            continue
        except json.JSONDecodeError as e:
            print(f"\nError parsing message: {e}")
        except Exception as e:
            if not exit_event.is_set():
                print(f"\nError receiving message: {e}")
            break


def initiate_tcp_session(user_name: str, target_username: str, secure: bool) -> None:
    """Establish a TCP connection and start chatting."""
    try:
        # Find target peer info
        target_info = next(
            (info for info in PEERS.values() if info['username'] == target_username), 
            None
        )
        
        if not target_info:
            print(f"IP address for {target_username} not found.")
            return
        
        target_ip = target_info['ip']
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(SOCKET_TIMEOUT)
            print(f"Connecting to {target_username} at {target_ip}:{CHAT_PORT}...")
            sock.connect((target_ip, CHAT_PORT))
            print(f"✓ Connected to {target_username}")
            
            shared_key: Optional[bytes] = None
            if secure:
                print("🔐 Performing secure key exchange...")
                shared_key = perform_key_exchange(sock)
                print("✓ Secure connection established")
            
            # Start receiving thread
            recv_thread = threading.Thread(
                target=receive_messages, 
                args=(sock, shared_key), 
                daemon=True
            )
            recv_thread.start()
            
            # Send messages
            prompt_user_message(sock, user_name, target_username, shared_key, secure)
            
            print("Connection closed.")
            
    except socket.timeout:
        print(f"Connection timed out. {target_username} might be offline.")
    except ConnectionRefusedError:
        print(f"Connection refused. {target_username} is not accepting connections.")
    except socket.error as e:
        print(f"Network error: {e}")
    except Exception as e:
        print(f"Failed to establish connection: {e}")


def prompt_user_message(
    sock: socket.socket, 
    user_name: str, 
    target_username: str, 
    shared_key: Optional[bytes], 
    secure: bool
) -> None:
    """Prompt user for messages and send them."""
    print("\n" + "="*40)
    print("  Chat started. Type 'exit' to quit.")
    print("="*40 + "\n")
    
    while not exit_event.is_set():
        try:
            message = input(f"{user_name} (type 'exit' to quit): ")
            
            if message.lower() == 'exit':
                exit_event.set()
                break
            
            if not message.strip():
                continue
            
            if sock:
                if secure and shared_key:
                    encrypted_message = encrypt_message(message, shared_key)
                    json_msg = json.dumps({
                        "username": user_name, 
                        "encrypted_message": encrypted_message
                    })
                else:
                    json_msg = json.dumps({
                        "username": user_name, 
                        "unencrypted_message": message
                    })
                
                sock.sendall(json_msg.encode('utf-8'))
                log_message(target_username, message, "SENT")
                
        except Exception as e:
            print(f"Error sending message: {e}")
            break


def perform_key_exchange(sock: socket.socket) -> bytes:
    """Perform Diffie-Hellman key exchange."""
    try:
        # Generate private key (256 bits for security)
        private_key = secrets.randbelow(DH_PRIME - 2) + 1
        public_key = pow(DH_GENERATOR, private_key, DH_PRIME)
        
        # Send our public key
        sock.sendall(json.dumps({"key": str(public_key)}).encode('utf-8'))
        
        # Receive peer's public key
        peer_data = sock.recv(4096).decode('utf-8')
        peer_key_data = json.loads(peer_data)
        peer_public_key = int(peer_key_data["key"])
        
        # Compute shared secret
        shared_secret = pow(peer_public_key, private_key, DH_PRIME)
        
        # Derive 32-byte key using SHA-256 (for AES-256)
        shared_key = hashlib.sha256(str(shared_secret).encode()).digest()
        
        return shared_key
        
    except Exception as e:
        print(f"Key exchange failed: {e}")
        raise


def encrypt_message(message: str, shared_key: bytes) -> str:
    """Encrypt message using AES-256-CBC."""
    try:
        if CRYPTO_AVAILABLE:
            # Generate random IV
            iv = secrets.token_bytes(16)
            cipher = AES.new(shared_key, AES.MODE_CBC, iv)
            padded_message = pad(message.encode('utf-8'), AES.block_size)
            encrypted = cipher.encrypt(padded_message)
            # Return IV + encrypted message as hex
            return (iv + encrypted).hex()
        else:
            # Fallback: XOR with key (NOT SECURE - for compatibility only)
            key_bytes = shared_key[:len(message.encode())]
            encrypted = bytes(a ^ b for a, b in zip(message.encode(), key_bytes * (len(message) // len(key_bytes) + 1)))
            return encrypted.hex()
    except Exception as e:
        print(f"Encryption failed: {e}")
        raise


def decrypt_message(encrypted_hex: str, shared_key: bytes) -> str:
    """Decrypt message using AES-256-CBC."""
    try:
        if CRYPTO_AVAILABLE:
            encrypted_data = bytes.fromhex(encrypted_hex)
            iv = encrypted_data[:16]
            encrypted = encrypted_data[16:]
            cipher = AES.new(shared_key, AES.MODE_CBC, iv)
            decrypted = unpad(cipher.decrypt(encrypted), AES.block_size)
            return decrypted.decode('utf-8')
        else:
            # Fallback: XOR with key
            encrypted = bytes.fromhex(encrypted_hex)
            key_bytes = shared_key[:len(encrypted)]
            decrypted = bytes(a ^ b for a, b in zip(encrypted, key_bytes * (len(encrypted) // len(key_bytes) + 1)))
            return decrypted.decode('utf-8')
    except Exception as e:
        print(f"Decryption failed: {e}")
        raise


def log_message(other_user: str, message: str, status: str) -> None:
    """Log chat messages to file."""
    if status in ["SENT", "RECEIVED"]:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        direction = "to" if status == "SENT" else "from"
        try:
            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(f"{timestamp} - {status} {direction} {other_user}: {message}\n")
        except IOError as e:
            print(f"Warning: Could not write to log file: {e}")


def view_history() -> None:
    """Display chat history."""
    try:
        with open(LOG_FILE, 'r', encoding='utf-8') as f:
            print("\n" + "="*40)
            print("  Chat History")
            print("="*40)
            lines = f.readlines()
            if not lines:
                print("No chat history available.")
            else:
                for line in lines[-50:]:  # Show last 50 messages
                    print(line.strip())
            print("="*40)
    except FileNotFoundError:
        print("No chat history available.")
    except IOError as e:
        print(f"Error reading history: {e}")


if __name__ == "__main__":
    main_menu()
