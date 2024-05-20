# End-to-End Encryption with Python Socket Communication

This Python project demonstrates end-to-end encryption (E2EE) using the x25519 key exchange protocol and AES encryption for secure communication between a client (Alice) and a server (Bob) over a socket connection.

## Key Features

- **Secure Key Exchange**: Utilizes the x25519 algorithm for secure key exchange between Alice and Bob.
- **Symmetric Encryption**: Employs AES encryption in CBC mode for symmetric encryption of messages.
- **Message Integrity**: Verifies message integrity using HMAC to detect any tampering during transmission.
- **Client-Server Interaction**: Implements client-server interaction with threading to handle concurrent connections securely.

## Setup Instructions

1. **Clone the Repository:**
   
   ```bash
   git clone https://github.com/anishvedant/End-to-End-Encryption.git
   ```

2. **Install Dependencies:**
   ```bash
      pip install cryptography
      pip install sockets
   ```
## Usage
1. **Run the key_gen and generate a shared key:**
   ```bash
   python3 key_gen.py
   ```
   
1. **Run the Server:**
   ```bash
   python3 Server.py
   ```
   
2. **Run Alice's Client:**
    ```bash
   python3 Alice.py
   ```
   
4. **Run Bob's Server:**
   ```bash
   python3 Bob.py
   ```
5. **Input the shared key generated from the key_gen.py**
   
6. **Follow the Prompts:**

Enter messages as prompted to observe the encrypted communication between Alice and Bob.

## File Descriptions 

- **key_gen.py:** Generates public and private keys for Alice and Bob, performs key exchange, and encrypts/decrypts messages.
- **Server.py:** Initializes the server, handles client connections, and relays encrypted messages to other clients.
- **Alice.py:** Simulates Alice's client-side interaction. Encrypts messages and sends them to Bob, verifies message integrity.
- **Bob.py:**  Simulates Bob's server-side interaction. Receives messages from Alice, decrypts them, and responds securely.

# **How it Works**
### *Key Generation and Exchange*

The key_gen.py script generates public and private keys for Alice and Bob using the x25519 key exchange protocol.
Key exchange is performed between Alice and Bob to derive a shared secret key for symmetric encryption.

### *Server Setup and Client Connections*

The Server.py script initializes a server that listens for incoming client connections. Each client connection is handled in a separate thread.

### *End-to-End Encryption*

Alice encrypts messages using AES encryption with a shared key derived from the key exchange. Messages are padded and encrypted using CBC mode with randomly generated Initialization Vectors (IVs).
HMAC (Hash-based Message Authentication Code) is generated for each message to ensure message integrity. 
Bob decrypts received messages using the shared key and verifies the HMAC for integrity.

### *Client Interaction*

Alice and Bob scripts simulate client-server interactions.
They establish connections, send encrypted messages, receive and decrypt messages, and maintain message integrity through HMAC verification.


# **Contributing**
Contributions are welcome! Fork the repository and submit a pull request with your changes.

##  :bulb:Note:
Ensure both Alice and Bob have the same shared key for successful communication.
This project is for educational purposes and may require adjustments for production use.

# **License**
This project is licensed under the MIT License. See the LICENSE file for details.

# **Disclaimer**

End-to-end encryption enhances communication security but does not guarantee absolute protection against all forms of attacks. Users are advised to understand the limitations and potential risks associated with the implementation. Use this project responsibly and in compliance with applicable laws and regulations.






