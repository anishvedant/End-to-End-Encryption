import socket
import binascii, os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hmac, hashes

def encrypt_message(message, shared_key, iv):
    cipher = Cipher(algorithms.AES(shared_key), modes.CBC(iv), backend=default_backend())

    # Pad the message to ensure its length is a multiple of the block size
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_message = padder.update(message.encode()) + padder.finalize()

    # Encrypt the padded message
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_message) + encryptor.finalize()

    return ciphertext

def generate_hmac(message, shared_key):
    h = hmac.HMAC(shared_key, hashes.SHA256(), backend=default_backend())
    h.update(message)
    return h.finalize()

def decrypt_message(encrypted_message, shared_key, iv):
    cipher = Cipher(algorithms.AES(shared_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt the ciphertext
    decrypted_padded_message = decryptor.update(encrypted_message) + decryptor.finalize()

    # Unpad the decrypted message
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_message = unpadder.update(decrypted_padded_message) + unpadder.finalize()

    return decrypted_message.decode()

def bob(shared_key):
    host = 'localhost'
    port = 12345

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    print("Bob: Connected to server")

    while True:
        # Receive encrypted message and HMAC from the server
        data = s.recv(1024)
        if not data:
            print("Connection closed by the server")
            break

        iv_alice = data[:16]
        encrypted_message = data[16:-32]
        received_hmac = data[-32:]

        print("Bob: Received Hash:", binascii.hexlify(received_hmac))  # Print the received HMAC

        # Decrypt message
        decrypted_message = decrypt_message(encrypted_message, shared_key, iv_alice)
        print("Bob: Decrypted message from Alice:", decrypted_message)

        # Generate HMAC from the decrypted message
        computed_hmac = generate_hmac(decrypted_message.encode(), shared_key)

        # Compare computed HMAC with received HMAC
        if computed_hmac == received_hmac:
            print("Bob: Hash verification successful.")
        else:
            print("Bob: Hash verification failed. Message integrity compromised.")

        response = input("Bob: Enter the message to send to Alice (type 'exit' to quit): ")
        if response == 'exit':
            break

        iv = os.urandom(16)  # Generate random IV (Initialization Vector)
        encrypted_response = encrypt_message(response, shared_key, iv)
        print("Bob: IV:", binascii.hexlify(iv))
        print("Bob: Encrypted response:", binascii.hexlify(encrypted_response))

        # Generate HMAC for the response
        hmac_digest = generate_hmac(response.encode(), shared_key)

        print("Bob: Hash:", binascii.hexlify(hmac_digest))
        
        # Send IV, encrypted message, and HMAC to the server
        s.sendall(iv + encrypted_response + hmac_digest)  
        print("Bob: Encrypted response and Hash sent to the server.")
        
    s.close()

# Take shared key from user input
shared_key_hex = input("Enter the shared key in hexadecimal format: ")
shared_key = binascii.unhexlify(shared_key_hex)

# Start Bob
bob(shared_key)
