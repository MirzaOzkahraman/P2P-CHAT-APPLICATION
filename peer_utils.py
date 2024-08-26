import json
from datetime import datetime, timedelta

def save_peers(peers, filename='peers.json'):
    with open(filename, 'w') as f:
        json.dump(peers, f, indent=4)

def load_peers(filename='peers.json'):
    try:
        with open(filename, 'r') as f:
            peers = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        peers = {}
    return peers

def update_peers(peers, ip, username):
    """Updates the peers dictionary with unique identifier as a combination of IP and username."""
    key = f"{ip}_{username}"  # Create a unique key by combining IP and username
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    if key in peers:
        peers[key]['last_seen'] = timestamp
        print(f"Updated {username} at {ip}, last seen at {timestamp}")
    else:
        peers[key] = {'username': username, 'ip': ip, 'last_seen': timestamp}
        print(f"New peer discovered: {username} at {ip}, added at {timestamp}")

def cleanup_peers(peers, timeout=900):
    """Removes peers that have not been seen for more than a specified timeout in seconds."""
    current_time = datetime.now()
    to_remove = [key for key, value in peers.items()
                 if (current_time - datetime.strptime(value['last_seen'], '%Y-%m-%d %H:%M:%S')) > timedelta(seconds=timeout)]
    for key in to_remove:
        print(f"Removing inactive peer: {peers[key]['username']} at {peers[key]['ip']}")
        del peers[key]
