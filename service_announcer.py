import socket
import json
import time

def get_local_ip():
    """Utility function to get the local IP address of the machine."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # doesn't even have to be reachable
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

def broadcast_presence(username, interval=8):
    """Broadcasts the user's presence on the network every 8 seconds."""
    local_ip = get_local_ip()
    broadcaster = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    broadcaster.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    while True:
        # Creating JSON message with username and IP address
        message = json.dumps({"username": username, "ip": local_ip})
        # Broadcasting the message
        broadcaster.sendto(message.encode(), ('<broadcast>', 6000))
        print(f"Broadcasting: {message}")
        time.sleep(interval)

def main():
    username = input("Please enter your username: ")
    # Start broadcasting
    broadcast_presence(username)

if __name__ == "__main__":
    main()
