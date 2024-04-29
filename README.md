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
   git clone https://github.com/your-username/e2ee-python-socket.git
   ```

2. **Install Dependencies:**
   ```bash
      pip install cryptography
   ```
## Usage

1. **Run the Server:**
   ```bash
   python Server.py
   ```
   
2. **Run Alice's Client:**
    ```bash
   python Alice.py
   ```
   
4. **Run Bob's Server:**
   ``bash
   python Bob.py
   ```
5. **Follow the Prompts:**

Enter messages as prompted to observe the encrypted communication between Alice and Bob.

## File Descriptions

- **key_gen.py:** Generates public and private keys for Alice and Bob, performs key exchange, and encrypts/decrypts messages.
- **Server.py:** Initializes the server, handles client connections, and relays encrypted messages to other clients.
- **Alice.py:** Simulates Alice's client-side interaction. Encrypts messages and sends them to Bob, verifies message integrity.
- **Bob.py:**  Simulates Bob's server-side interaction. Receives messages from Alice, decrypts them, and responds securely.

## Dependencies
cryptography: Cryptographic library for secure communication.

# Contributing
Contributions are welcome! Fork the repository and submit a pull request with your changes.

# License
This project is licensed under the MIT License. See the LICENSE file for details.

# Disclaimer: End-to-end encryption enhances communication security but does not guarantee absolute protection against all forms of attacks. Users are advised to understand the limitations and potential risks associated with the implementation. Use this project responsibly and in compliance with applicable laws and regulations.
