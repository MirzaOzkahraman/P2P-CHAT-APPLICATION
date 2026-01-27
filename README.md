# 🔐 P2P Chat Application

<div align="center">

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Platform](https://img.shields.io/badge/Platform-Cross--Platform-lightgrey.svg)

**A secure peer-to-peer chat application with end-to-end encryption**

</div>

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔍 **Peer Discovery** | Automatic discovery of users on the same network |
| 💬 **Real-time Chat** | Direct peer-to-peer messaging without a central server |
| 🔒 **Secure Mode** | AES-256-CBC encryption with Diffie-Hellman key exchange |
| 📜 **Chat History** | Local message logging with timestamps |
| 🌐 **Cross-Platform** | Works on Windows, macOS, and Linux |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    P2P Chat Network                         │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────┐         UDP/6000          ┌─────────────┐  │
│  │   Peer A    │◄─────────────────────────►│   Peer B    │  │
│  │             │      (Discovery)          │             │  │
│  │  Announcer  │                           │  Discovery  │  │
│  └─────────────┘                           └─────────────┘  │
│                                                             │
│  ┌─────────────┐         TCP/6001          ┌─────────────┐  │
│  │  Initiator  │◄─────────────────────────►│  Responder  │  │
│  │             │    (Encrypted Chat)       │             │  │
│  └─────────────┘                           └─────────────┘  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 📦 Installation

### Prerequisites

- Python 3.8 or higher
- Same Wi-Fi network for all participants

### Quick Start

```bash
# Clone the repository
git clone https://github.com/yourusername/P2P-CHAT-APPLICATION.git
cd P2P-CHAT-APPLICATION

# Install dependencies (optional, for enhanced security)
pip install -r requirements.txt
```

> **Note**: The application works without `pycryptodome`, but secure chat will use a less secure fallback encryption.

---

## 🚀 Usage

### Step 1: Start Service Announcer
```bash
python service_announcer.py
# Enter your username when prompted
```

### Step 2: Start Peer Discovery (on each device)
```bash
python peer_discovery.py
```

### Step 3: Start Chat Responder (to receive messages)
```bash
python chat_responder.py
```

### Step 4: Start Chat Initiator (to send messages)
```bash
python chat_initiator.py
# Enter your username
# Choose from menu:
#   1. View Online Users
#   2. Start Chat
#   3. View Chat History
#   4. Exit
```

---

## 🔒 Security

### Encryption Details

| Component | Algorithm | Key Size |
|-----------|-----------|----------|
| Key Exchange | Diffie-Hellman | 2048-bit (RFC 3526) |
| Message Encryption | AES-256-CBC | 256-bit |
| Key Derivation | SHA-256 | 256-bit |

### Secure Chat Flow

```
1. Initiator generates DH key pair
2. Initiator sends public key → Responder
3. Responder generates DH key pair
4. Responder sends public key → Initiator
5. Both compute shared secret using DH
6. Shared secret → SHA-256 → AES-256 key
7. All messages encrypted with AES-256-CBC
```

---

## 📁 Project Structure

```
P2P-CHAT-APPLICATION/
├── chat_initiator.py     # Start chat sessions
├── chat_responder.py     # Accept incoming chats
├── peer_discovery.py     # Discover network peers
├── peer_utils.py         # Shared utilities
├── service_announcer.py  # Broadcast presence
├── requirements.txt      # Python dependencies
├── peers.json           # Discovered peers (auto-generated)
└── chat_history.log     # Message log (auto-generated)
```

---

## 🔧 Configuration

### Ports Used

| Port | Protocol | Purpose |
|------|----------|---------|
| 6000 | UDP | Peer discovery broadcasts |
| 6001 | TCP | Chat connections |

### Timeouts

| Setting | Value | Description |
|---------|-------|-------------|
| Peer timeout | 15 min | Inactive peers removed |
| Connection timeout | 30 sec | TCP connection timeout |
| Online threshold | 10 sec | Peer shown as "Online" |

---

## 🐛 Troubleshooting

### Common Issues

| Problem | Solution |
|---------|----------|
| "Port already in use" | Stop other instances or wait 60 seconds |
| "No users found" | Ensure `service_announcer.py` is running |
| "Connection refused" | Start `chat_responder.py` on target device |
| "Encryption failed" | Install `pycryptodome`: `pip install pycryptodome` |

### Firewall Settings

Ensure these ports are allowed:
- UDP 6000 (inbound/outbound)
- TCP 6001 (inbound/outbound)

---

## 📋 Requirements

```
Python >= 3.8
pycryptodome >= 3.20.0  (optional, for AES encryption)
```

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 👤 Author

**Mirza Özkahraman**

---

<div align="center">

Made with ❤️ for secure peer-to-peer communication

</div>
