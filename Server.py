import socket
import binascii
import threading
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend

clients = []

def handle_client(client_socket, address):
    global clients

    print(f"Connected to {address}")

    while True:
        # Receive data from client
        data = client_socket.recv(1024)
        if not data:
            print(f"Connection closed by {address}")
            break

        iv = data[:16]
        encrypted_response = data[16:]  # Extract encrypted response
        received_hmac = encrypted_response[-32:]  # Extract received HMAC
        encrypted_response = encrypted_response[:-32]  # Remove HMAC from the encrypted response

        print(f"Received encrypted response from {address}:")
        print(f"IV: {binascii.hexlify(iv)}")
        print(f"Encrypted response: {binascii.hexlify(encrypted_response)}")
        print(f"Received Hash: {binascii.hexlify(received_hmac)}")

        # Echo back the complete data (IV + encrypted_response + received_hmac) to all clients except the sender
        for client in clients:
            if client != client_socket:
                echo_data = iv + encrypted_response + received_hmac
                client.sendall(echo_data)
                print(f"Sent message to {client.getpeername()}")

    # Close the connection
    client_socket.close()

def server():
    global clients

    host = 'localhost'
    port = 12345
    max_connections = 5

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((host, port))
        server_socket.listen()

        print("Server is listening for connections...")
        while True:
            client_socket, address = server_socket.accept()
            clients.append(client_socket)

            client_handler = threading.Thread(target=handle_client, args=(client_socket, address))
            client_handler.start()

# Start the server
server()


