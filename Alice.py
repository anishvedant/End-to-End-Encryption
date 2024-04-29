import socket
import binascii
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hmac, hashes
import os

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
    h.update(message.encode())
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

def alice(shared_key):
    host = 'localhost'
    port = 12345

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    print("Alice: Connected to server")

    while True:
        message = input("Alice: Enter the message to send to Bob (type 'exit' to quit): ")
        if message == 'exit':
            break

        iv = os.urandom(16) 
        
        # Encrypt message
        encrypted_message = encrypt_message(message, shared_key, iv)
        
        # Generate HMAC
        hmac_digest = generate_hmac(message, shared_key)
        
        print("Alice: IV:", binascii.hexlify(iv))
        print("Alice: Encrypted message:", binascii.hexlify(encrypted_message))
        print("Alice: Hash:", binascii.hexlify(hmac_digest))
        
        # Send encrypted message and HMAC to Bob
        s.sendall(iv + encrypted_message + hmac_digest)
        print("Alice: Encrypted message and Hash sent to Bob")

        # Receive encrypted response from Bob
        iv_bob = s.recv(16)
        encrypted_response = s.recv(1024)
        
        # Extract HMAC from received data
        received_hmac = encrypted_response[-32:]
        encrypted_response = encrypted_response[:-32]
        
        # Generate HMAC from the decrypted message
        computed_hmac = generate_hmac(decrypt_message(encrypted_response, shared_key, iv_bob), shared_key)

        # Compare computed HMAC with received HMAC
        if computed_hmac == received_hmac:
            print("Alice: Hash verified.")
            print("Alice: Decrypted response from Bob:", decrypt_message(encrypted_response, shared_key, iv_bob))
        else:
            print("Alice: Hash verification failed. Message integrity compromised.")

    s.close()

# Take shared key from user input
shared_key_hex = input("Enter the shared key in hexadecimal format: ")
shared_key = binascii.unhexlify(shared_key_hex)

# Start Alice
alice(shared_key)
