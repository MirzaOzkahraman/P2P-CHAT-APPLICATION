import socket
import json
from datetime import datetime, timedelta
from peer_utils import save_peers, load_peers, update_peers

def listen_for_peers():
    listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listener.bind(('', 6000))
    peers = load_peers()  # `load_peers` fonksiyonunu kullanarak mevcut peers'i yükleyin

    while True:
        try:
            message, addr = listener.recvfrom(1024)
            data = json.loads(message.decode())
            ip = addr[0]
            username = data['username']
            update_peers(peers, ip, username)
            cleanup_peers(peers)
            save_peers(peers)
        except KeyboardInterrupt:
            print("Shutting down peer discovery.")
            break
        except Exception as e:
            print(f"Error receiving data: {e}")

def cleanup_peers(peers, timeout=900):
    current_time = datetime.now()
    to_remove = [key for key, value in peers.items()
                 if (current_time - datetime.strptime(value['last_seen'], '%Y-%m-%d %H:%M:%S')) > timedelta(seconds=timeout)]
    for key in to_remove:
        print(f"Removing inactive peer: {peers[key]['username']} at {peers[key]['ip']}")
        del peers[key]

def main():
    print("Starting peer discovery...")
    listen_for_peers()

if __name__ == "__main__":
    main()
