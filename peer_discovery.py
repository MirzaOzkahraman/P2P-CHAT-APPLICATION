import socket
import json
import signal
import sys
from datetime import datetime, timedelta
from typing import Dict, Any
from peer_utils import save_peers, load_peers, update_peers, cleanup_peers

# Discovery settings
DISCOVERY_PORT = 6000
running = True


def signal_handler(sig, frame):
    """Handle graceful shutdown."""
    global running
    print("\nShutting down peer discovery...")
    running = False
    sys.exit(0)


def listen_for_peers() -> None:
    """Listen for peer announcements on the network."""
    global running
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        listener.bind(('', DISCOVERY_PORT))
        listener.settimeout(1.0)  # Allow periodic cleanup
        
        peers: Dict[str, Any] = load_peers()
        
        print(f"{'='*40}")
        print(f"  Peer Discovery Service")
        print(f"  Listening on port {DISCOVERY_PORT}")
        print(f"  Press Ctrl+C to stop")
        print(f"{'='*40}")
        
        last_cleanup = datetime.now()
        
        while running:
            try:
                message, addr = listener.recvfrom(1024)
                data = json.loads(message.decode('utf-8'))
                ip = addr[0]
                username = data.get('username', 'Unknown')
                
                update_peers(peers, ip, username)
                save_peers(peers)
                
                # Periodic cleanup every 5 minutes
                if (datetime.now() - last_cleanup).total_seconds() > 300:
                    cleanup_peers(peers)
                    save_peers(peers)
                    last_cleanup = datetime.now()
                    
            except socket.timeout:
                continue
            except json.JSONDecodeError as e:
                print(f"Invalid peer announcement: {e}")
            except Exception as e:
                if running:
                    print(f"Error receiving data: {e}")
                    
    except OSError as e:
        print(f"Failed to bind to port {DISCOVERY_PORT}: {e}")
    finally:
        listener.close()
        print("Peer discovery stopped.")


def main() -> None:
    """Main entry point."""
    print("Starting peer discovery...")
    listen_for_peers()


if __name__ == "__main__":
    main()
