Peer-to-Peer Chat Application
This project is a Python-based peer-to-peer chat application that operates over the same Wi-Fi network across different computers. 
The application offers various features such as viewing online users, chat history, and the ability to initiate both secure and insecure chats.

Features
View Online Users: Easily see who is currently online.
Chat History: Access past conversations.
Secure & Insecure Chats: Start a chat session that can be secure or insecure based on your preference. 
Secure chats use the Diffie-Hellman algorithm to encrypt messages, ensuring that only the intended recipient can decrypt them.

Getting Started
To run the project, follow these steps:

Run service_announcer.py
Enter your username(s) when prompted.

Run peer_discovery.py
This script helps in discovering other peers on the network.

Run chat_responder.py
This script listens for incoming chat requests.

Run chat_initiator.py
Enter your username to start. From this interface, you can:

  View online users.
  Choose who to chat with.
  Initiate either a secure or insecure chat.
  View chat history.

Usage
Initiate a Chat: Use chat_initiator.py to see active users and select the user you want to chat with.
Secure Communication: If you choose to initiate a secure chat, the application will use the Diffie-Hellman key exchange method to encrypt your messages.
Chat History: You can view the chat history at any time during your session.
Security
The secure chat feature ensures that your conversations are protected through encryption. 
The Diffie-Hellman algorithm is employed to generate a shared secret key between you and the other participant, which is then used to encrypt and decrypt the messages.
