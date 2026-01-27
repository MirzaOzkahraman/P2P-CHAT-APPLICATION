import socket
import json
import time
import signal
import sys
from typing import Optional

# Broadcast settings
BROADCAST_PORT = 6000
BROADCAST_INTERVAL = 8  # seconds

running = True


def signal_handler(sig, frame):
    """Handle graceful shutdown."""
    global running
    print("\nStopping broadcast...")
    running = False
    sys.exit(0)


def get_local_ip() -> str:
    """
    Get the local IP address of this machine.
    
    Returns:
        Local IP address string
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Connect to a public IP (doesn't need to be reachable)
        s.connect(('10.255.255.255', 1))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip


def broadcast_presence(username: str, interval: int = BROADCAST_INTERVAL) -> None:
    """
    Broadcast user presence on the network.
    
    Args:
        username: Username to broadcast
        interval: Seconds between broadcasts
    """
    global running
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    local_ip = get_local_ip()
    
    broadcaster = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    broadcaster.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    
    print(f"{'='*40}")
    print(f"  Service Announcer")
    print(f"  Username: {username}")
    print(f"  IP: {local_ip}")
    print(f"  Broadcasting every {interval} seconds")
    print(f"  Press Ctrl+C to stop")
    print(f"{'='*40}")
    
    try:
        while running:
            message = json.dumps({
                "username": username,
                "ip": local_ip,
                "timestamp": time.strftime('%Y-%m-%d %H:%M:%S')
            })
            
            try:
                broadcaster.sendto(message.encode('utf-8'), ('<broadcast>', BROADCAST_PORT))
                print(f"📡 Broadcasting: {username} @ {local_ip}")
            except socket.error as e:
                print(f"Broadcast error: {e}")
            
            time.sleep(interval)
            
    except Exception as e:
        print(f"Error: {e}")
    finally:
        broadcaster.close()
        print("Broadcast stopped.")


def main() -> None:
    """Main entry point."""
    print("\n" + "="*40)
    print("  P2P Chat - Service Announcer")
    print("="*40 + "\n")
    
    username = input("Please enter your username: ").strip()
    
    if not username:
        print("Username cannot be empty.")
        return
    
    broadcast_presence(username)


if __name__ == "__main__":
    main()
