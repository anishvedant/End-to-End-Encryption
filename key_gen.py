from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import binascii, os

def bytes_to_int(byte_str):
    return int.from_bytes(byte_str, byteorder='big')

def int_to_bytes(integer):
    return integer.to_bytes((integer.bit_length() + 7) // 8, byteorder='big')

# Generate private keys for Bob and Alice
private_key_bob = x25519.X25519PrivateKey.generate()
private_key_alice = x25519.X25519PrivateKey.generate()

# Generate public keys for Bob and Alice
public_key_bob = private_key_bob.public_key()
public_key_alice = private_key_alice.public_key()

# Perform key exchange
shared_key_bob = private_key_bob.exchange(public_key_alice)
shared_key_alice = private_key_alice.exchange(public_key_bob)

# Print private and public keys for Alice
print("Alice's private key:", binascii.hexlify(private_key_alice.private_bytes(encoding=serialization.Encoding.Raw, format=serialization.PrivateFormat.Raw, encryption_algorithm=serialization.NoEncryption())))
print("Alice's public key:", binascii.hexlify(public_key_alice.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)))

# Print private and public keys for Bob
print("Bob's private key:", binascii.hexlify(private_key_bob.private_bytes(encoding=serialization.Encoding.Raw, format=serialization.PrivateFormat.Raw, encryption_algorithm=serialization.NoEncryption())))
print("Bob's public key:", binascii.hexlify(public_key_bob.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)))

# Print shared keys
print("Shared key (Bob):", binascii.hexlify(shared_key_bob))    
print("Shared key (Alice):", binascii.hexlify(shared_key_alice))

# Take input from the user
message = input("Enter the message to encrypt: ")

# Encrypt the message using Alice's private key and Bob's public key
encryption_key = shared_key_alice[:16]  # Use first 128 bits (16 bytes) of shared key for AES encryption
iv = os.urandom(16)  # Generate random IV (Initialization Vector)
cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv), backend=default_backend())

# Pad the message to ensure its length is a multiple of the block size
padder = padding.PKCS7(algorithms.AES.block_size).padder()
padded_message = padder.update(message.encode()) + padder.finalize()

# Encrypt the padded message
encryptor = cipher.encryptor()
ciphertext = encryptor.update(padded_message) + encryptor.finalize()

# Decrypt the message using Bob's private key and Alice's public key
decryption_key = shared_key_bob[:16]  # Use first 128 bits (16 bytes) of shared key for AES decryption
cipher = Cipher(algorithms.AES(decryption_key), modes.CBC(iv), backend=default_backend())
decryptor = cipher.decryptor()

# Decrypt the ciphertext
decrypted_padded_message = decryptor.update(ciphertext) + decryptor.finalize()

# Unpad the decrypted message
unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
decrypted_message = unpadder.update(decrypted_padded_message) + unpadder.finalize()

# Print original message, encrypted message, and decrypted message
print("\nOriginal Message:", message)
print("Encrypted Message:", binascii.hexlify(ciphertext))
print("Decrypted Message:", decrypted_message.decode())