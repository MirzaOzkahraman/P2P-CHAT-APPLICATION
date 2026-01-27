import socket
import json
import threading
import secrets
import hashlib
import signal
import sys
from datetime import datetime
from typing import Optional, Dict, Any
from peer_utils import load_peers, update_peers, cleanup_peers, save_peers

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    print("Warning: pycryptodome not installed. Using fallback encryption.")

# Load peers
PEERS: Dict[str, Any] = load_peers()
LOG_FILE = "chat_history.log"

# Diffie-Hellman parameters (RFC 3526 - 2048-bit MODP Group)
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

# Server settings
CHAT_PORT = 6001
server_running = True


def signal_handler(sig, frame):
    """Handle graceful shutdown."""
    global server_running
    print("\nShutting down server...")
    server_running = False
    sys.exit(0)


def start_server() -> None:
    """Start the chat responder server."""
    global server_running
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server.bind(('', CHAT_PORT))
        server.listen(5)
        server.settimeout(1.0)  # Allow checking server_running periodically
        
        print(f"{'='*40}")
        print(f"  Chat Responder Server")
        print(f"  Listening on port {CHAT_PORT}")
        print(f"  Press Ctrl+C to stop")
        print(f"{'='*40}")
        
        while server_running:
            try:
                client, addr = server.accept()
                print(f"\n📥 Connection from {addr[0]}:{addr[1]}")
                thread = threading.Thread(
                    target=handle_client, 
                    args=(client, addr),
                    daemon=True
                )
                thread.start()
            except socket.timeout:
                continue
            except Exception as e:
                if server_running:
                    print(f"Accept error: {e}")
                    
    except OSError as e:
        print(f"Server error: {e}")
        print(f"Port {CHAT_PORT} might already be in use.")
    finally:
        server.close()
        print("Server stopped.")


def get_username_from_ip(ip: str) -> str:
    """Get username from IP address."""
    global PEERS
    PEERS = load_peers()  # Refresh peers list
    
    for key, value in PEERS.items():
        if value['ip'] == ip:
            return value['username']
    return "Unknown"


def handle_client(client: socket.socket, addr: tuple) -> None:
    """Handle incoming client connection."""
    username = get_username_from_ip(addr[0])
    shared_key: Optional[bytes] = None
    
    print(f"👤 Client identified as: {username}")
    
    try:
        client.settimeout(300)  # 5 minute timeout for idle connections
        
        while True:
            try:
                message = client.recv(4096).decode('utf-8')
                
                if not message:
                    print(f"📤 {username} disconnected")
                    break
                
                data = json.loads(message)
                
                if 'key' in data:
                    # Diffie-Hellman key exchange
                    print(f"🔐 Performing key exchange with {username}...")
                    shared_key = perform_dh_key_exchange(client, data['key'])
                    print(f"✓ Secure connection established with {username}")
                    
                elif 'encrypted_message' in data and shared_key:
                    # Decrypt and display message
                    decrypted_message = decrypt_message(data['encrypted_message'], shared_key)
                    print(f"\n🔒 Message from {username}: {decrypted_message}")
                    log_message(username, decrypted_message, "RECEIVED")
                    
                    # Get response
                    response_message = input("Your response (or 'skip' to ignore): ")
                    if response_message.lower() != 'skip':
                        send_response(client, response_message, shared_key)
                        log_message(username, response_message, "SENT")
                        
                elif 'unencrypted_message' in data:
                    # Display unencrypted message
                    print(f"\n💬 Message from {username}: {data['unencrypted_message']}")
                    log_message(username, data['unencrypted_message'], "RECEIVED")
                    
                    # Get response
                    response_message = input("Your response (or 'skip' to ignore): ")
                    if response_message.lower() != 'skip':
                        send_response(client, response_message, None)
                        log_message(username, response_message, "SENT")
                else:
                    print(f"⚠️ Unknown message format from {username}")
                    
            except socket.timeout:
                print(f"⏰ Connection with {username} timed out")
                break
            except json.JSONDecodeError as e:
                print(f"⚠️ Invalid message format: {e}")
                
    except ConnectionResetError:
        print(f"📤 {username} disconnected unexpectedly")
    except Exception as e:
        print(f"❌ Error handling client {username}: {e}")
    finally:
        client.close()


def perform_dh_key_exchange(client: socket.socket, peer_public_key: str) -> bytes:
    """Perform Diffie-Hellman key exchange."""
    # Generate our private and public keys
    private_key = secrets.randbelow(DH_PRIME - 2) + 1
    public_key = pow(DH_GENERATOR, private_key, DH_PRIME)
    
    # Send our public key
    client.sendall(json.dumps({"key": str(public_key)}).encode('utf-8'))
    
    # Compute shared secret
    shared_secret = pow(int(peer_public_key), private_key, DH_PRIME)
    
    # Derive 32-byte key using SHA-256 (for AES-256)
    shared_key = hashlib.sha256(str(shared_secret).encode()).digest()
    
    return shared_key


def encrypt_message(message: str, shared_key: bytes) -> str:
    """Encrypt message using AES-256-CBC."""
    try:
        if CRYPTO_AVAILABLE:
            iv = secrets.token_bytes(16)
            cipher = AES.new(shared_key, AES.MODE_CBC, iv)
            padded_message = pad(message.encode('utf-8'), AES.block_size)
            encrypted = cipher.encrypt(padded_message)
            return (iv + encrypted).hex()
        else:
            # Fallback XOR (NOT SECURE)
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
            # Fallback XOR
            encrypted = bytes.fromhex(encrypted_hex)
            key_bytes = shared_key[:len(encrypted)]
            decrypted = bytes(a ^ b for a, b in zip(encrypted, key_bytes * (len(encrypted) // len(key_bytes) + 1)))
            return decrypted.decode('utf-8')
    except Exception as e:
        print(f"Decryption failed: {e}")
        raise


def send_response(client: socket.socket, response_message: str, shared_key: Optional[bytes]) -> None:
    """Send response to client."""
    try:
        if shared_key:
            encrypted_response = encrypt_message(response_message, shared_key)
            json_response = json.dumps({"encrypted_message": encrypted_response})
        else:
            json_response = json.dumps({"unencrypted_message": response_message})
        
        client.sendall(json_response.encode('utf-8'))
    except Exception as e:
        print(f"Error sending response: {e}")


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


if __name__ == "__main__":
    start_server()
