import json
import threading
from datetime import datetime, timedelta
from typing import Dict, Any, Optional

# Thread lock for file operations
_file_lock = threading.Lock()

# Default settings
DEFAULT_PEERS_FILE = 'peers.json'
DEFAULT_TIMEOUT = 900  # 15 minutes


def save_peers(peers: Dict[str, Any], filename: str = DEFAULT_PEERS_FILE) -> bool:
    """
    Save peers dictionary to JSON file.
    Thread-safe implementation.
    
    Args:
        peers: Dictionary of peer information
        filename: Path to the peers file
        
    Returns:
        True if successful, False otherwise
    """
    with _file_lock:
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(peers, f, indent=4, ensure_ascii=False)
            return True
        except IOError as e:
            print(f"Error saving peers: {e}")
            return False


def load_peers(filename: str = DEFAULT_PEERS_FILE) -> Dict[str, Any]:
    """
    Load peers dictionary from JSON file.
    Thread-safe implementation.
    
    Args:
        filename: Path to the peers file
        
    Returns:
        Dictionary of peer information
    """
    with _file_lock:
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                peers = json.load(f)
                return peers if isinstance(peers, dict) else {}
        except FileNotFoundError:
            return {}
        except json.JSONDecodeError as e:
            print(f"Warning: Invalid peers file, starting fresh: {e}")
            return {}
        except IOError as e:
            print(f"Error loading peers: {e}")
            return {}


def update_peers(peers: Dict[str, Any], ip: str, username: str) -> None:
    """
    Update the peers dictionary with a new or existing peer.
    Uses IP_username as unique identifier.
    
    Args:
        peers: Dictionary of peer information
        ip: IP address of the peer
        username: Username of the peer
    """
    key = f"{ip}_{username}"
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    if key in peers:
        peers[key]['last_seen'] = timestamp
        # Silent update for existing peers
    else:
        peers[key] = {
            'username': username,
            'ip': ip,
            'last_seen': timestamp
        }
        print(f"🆕 New peer discovered: {username} at {ip}")


def cleanup_peers(peers: Dict[str, Any], timeout: int = DEFAULT_TIMEOUT) -> int:
    """
    Remove peers that haven't been seen within the timeout period.
    
    Args:
        peers: Dictionary of peer information
        timeout: Seconds of inactivity before removing peer
        
    Returns:
        Number of peers removed
    """
    current_time = datetime.now()
    to_remove = []
    
    for key, value in peers.items():
        try:
            last_seen = datetime.strptime(value['last_seen'], '%Y-%m-%d %H:%M:%S')
            if (current_time - last_seen) > timedelta(seconds=timeout):
                to_remove.append(key)
        except (KeyError, ValueError):
            # Invalid entry, mark for removal
            to_remove.append(key)
    
    for key in to_remove:
        username = peers[key].get('username', 'Unknown')
        ip = peers[key].get('ip', 'Unknown')
        print(f"🗑️ Removing inactive peer: {username} at {ip}")
        del peers[key]
    
    return len(to_remove)


def get_peer_by_username(peers: Dict[str, Any], username: str) -> Optional[Dict[str, Any]]:
    """
    Find a peer by username.
    
    Args:
        peers: Dictionary of peer information
        username: Username to search for
        
    Returns:
        Peer info dictionary or None if not found
    """
    for key, value in peers.items():
        if value.get('username') == username:
            return value
    return None


def get_online_peers(peers: Dict[str, Any], online_threshold: int = 10) -> Dict[str, Any]:
    """
    Get only online peers (seen within threshold seconds).
    
    Args:
        peers: Dictionary of peer information
        online_threshold: Seconds to consider a peer online
        
    Returns:
        Dictionary of online peers
    """
    current_time = datetime.now()
    online = {}
    
    for key, value in peers.items():
        try:
            last_seen = datetime.strptime(value['last_seen'], '%Y-%m-%d %H:%M:%S')
            if (current_time - last_seen) <= timedelta(seconds=online_threshold):
                online[key] = value
        except (KeyError, ValueError):
            pass
    
    return online
