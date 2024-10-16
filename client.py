import socket
import json
import os
import sys
from cryptography.hazmat.primitives import serialization
# Import other necessary cryptographic modules as needed
# from cryptography.hazmat.primitives import hashes, padding as asym_padding
# from cryptography.hazmat.primitives.asymmetric import rsa
# from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
# from cryptography.exceptions import InvalidSignature
# from cryptography.hazmat.backends import default_backend


class Client:
    def __init__(self, username, server_host="localhost", server_port=12345):
        self.username = username
        self.server_host = server_host
        self.server_port = server_port
        self.private_key = None
        self.public_key = None
        self.server_socket = None
        self.contacts = {}
        self.messages = []

    def generate_keys(self):
        """Generate RSA public and private keys."""
        print("[Client] Generating RSA keys...")
        # TODO: Generate a 2048-bit RSA key pair and assign to self.private_key
        # Set self.public_key to the public key part of the key pair
        print("[Client] Keys generated.")

    def load_keys(self, private_key_path):
        """Load private key from a file."""
        print(f"[Client] Loading private key from '{private_key_path}'...")
        with open(private_key_path, "rb") as key_file:
            # TODO: Load the private key from the file and assign to self.private_key
            # Set self.public_key to the public key part of the key pair
            pass
        print("[Client] Private key loaded.")

    def save_private_key(self, private_key_path):
        """Save the private key to a file."""
        print(f"[Client] Saving private key to '{private_key_path}'...")
        # TODO: Serialize the private key and save it to the specified file
        print("[Client] Private key saved.")

    def connect_to_server(self):
        """Establish a connection to the server."""
        print(
            f"[Client] Connecting to server at {self.server_host}:{self.server_port}..."
        )
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.connect((self.server_host, self.server_port))
        print("[Client] Connected to server.")

    def disconnect_from_server(self):
        """Close the connection to the server."""
        if self.server_socket:
            self.server_socket.close()
            print("[Client] Disconnected from server.")

    def register(self):
        """Register the client with the server by sending the public key."""
        print("[Client] Registering with the server...")
        # TODO: Serialize the public key to PEM format and decode to a string
        public_key_pem = None  # Replace with actual serialized public key string
        data = {
            "command": "register",
            "username": self.username,
            "public_key": public_key_pem,
        }
        self.send_data(data)
        response = self.receive_data()
        print(f"[Server Response] {response['message']}")

    def send_message(self, recipient_username, plaintext_message):
        """Encrypt and send a message to another user."""
        print(f"[Client] Sending message to '{recipient_username}'...")
        # Get recipient's public key
        recipient_public_key_pem = self.get_public_key(recipient_username)
        recipient_public_key = serialization.load_pem_public_key(
            recipient_public_key_pem.encode(),
            # backend=default_backend()
        )

        # TODO: Generate a random symmetric key (AES-256) and IV (16 bytes)
        symmetric_key = None  # Students implement this
        iv = None  # Students implement this

        # TODO: Encrypt the plaintext_message using AES encryption with the symmetric key and IV
        ciphertext = None  # Students implement this

        # TODO: Encrypt the symmetric key using the recipient's public RSA key
        encrypted_symmetric_key = None  # Students implement this

        # TODO: Sign the ciphertext using your private RSA key
        signature = None  # Students implement this

        # Package the message
        message_package = {
            "command": "send_message",
            "from": self.username,
            "to": recipient_username,
            "message": {
                "encrypted_symmetric_key": encrypted_symmetric_key.hex()
                if encrypted_symmetric_key
                else "",
                "iv": iv.hex() if iv else "",
                "ciphertext": ciphertext.hex() if ciphertext else "",
                "signature": signature.hex() if signature else "",
            },
        }

        # Send the message to the server
        self.send_data(message_package)
        response = self.receive_data()
        print(f"[Server Response] {response['message']}")

    def get_public_key(self, username):
        """Retrieve the public key of a user."""
        print(f"[Client] Retrieving public key for '{username}'...")
        if username in self.contacts:
            return self.contacts[username]
        else:
            # Fetch contacts from server
            self.request_contacts()
            if username in self.contacts:
                return self.contacts[username]
            else:
                raise ValueError(f"User '{username}' not found.")

    def request_contacts(self):
        """Request the list of contacts from the server."""
        print("[Client] Requesting contacts from server...")
        data = {"command": "get_contacts"}
        self.send_data(data)
        response = self.receive_data()
        if response["status"] == "success":
            self.contacts = response["contacts"]
            print("[Client] Contacts updated.")
        else:
            print(f"[Client] Error retrieving contacts: {response['message']}")

    def retrieve_messages(self):
        """Retrieve messages from the server."""
        print("[Client] Retrieving messages from server...")
        data = {"command": "get_messages"}
        self.send_data(data)
        response = self.receive_data()
        if response["status"] == "success":
            messages = response["messages"]
            print(f"[Client] Received {len(messages)} messages.")
            for message in messages:
                if message["to"] == self.username:
                    self.process_message(message)
        else:
            print(f"[Client] Error retrieving messages: {response['message']}")

    def process_message(self, message):
        """Decrypt and verify a received message."""
        print(f"\n[Client] Processing message from '{message['from']}'...")
        sender_username = message["from"]
        sender_public_key_pem = self.get_public_key(sender_username)
        sender_public_key = serialization.load_pem_public_key(
            sender_public_key_pem.encode(),
            # backend=default_backend()
        )

        message_content = message["message"]
        encrypted_symmetric_key_hex = message_content.get("encrypted_symmetric_key")
        iv_hex = message_content.get("iv")
        ciphertext_hex = message_content.get("ciphertext")
        signature_hex = message_content.get("signature")

        if not all(
            [encrypted_symmetric_key_hex, iv_hex, ciphertext_hex, signature_hex]
        ):
            print("[Client] Incomplete message data.")
            return

        encrypted_symmetric_key = bytes.fromhex(encrypted_symmetric_key_hex)
        iv = bytes.fromhex(iv_hex)
        ciphertext = bytes.fromhex(ciphertext_hex)
        signature = bytes.fromhex(signature_hex)

        # TODO: Decrypt the symmetric key using your private RSA key
        symmetric_key = None  # Students implement this

        # TODO: Decrypt the ciphertext using AES decryption with the symmetric key and IV
        plaintext = None  # Students implement this

        # TODO: Verify the signature using the sender's public RSA key
        signature_valid = False  # Students implement this

        if signature_valid:
            print(
                f"[Client] Signature verified. Message from '{sender_username}': {plaintext.decode()}"
            )
        else:
            print("[Client] Invalid signature. Message may have been tampered with.")

    def send_data(self, data):
        """Send JSON data to the server."""
        self.server_socket.sendall(json.dumps(data).encode())

    def receive_data(self):
        """Receive JSON data from the server."""
        data = self.server_socket.recv(8192)
        if not data:
            return None
        return json.loads(data.decode())

    def run(self):
        """Main method to run the client operations."""
        try:
            self.connect_to_server()
            self.register()
            self.request_contacts()
            self.cli_loop()
        except Exception as e:
            print(f"[Client] Error: {e}")
        finally:
            self.disconnect_from_server()

    def cli_loop(self):
        """Command-line interface loop."""
        while True:
            print("\nAvailable commands:")
            print("1. Send message")
            print("2. Retrieve messages")
            print("3. View contacts")
            print("4. Exit")
            choice = input("Enter your choice: ").strip()
            if choice == "1":
                recipient = input("Enter recipient's username: ").strip()
                message = input("Enter your message: ").strip()
                self.send_message(recipient, message)
            elif choice == "2":
                self.retrieve_messages()
            elif choice == "3":
                self.display_contacts()
            elif choice == "4":
                print("[Client] Exiting.")
                break
            else:
                print("[Client] Invalid choice. Please try again.")

    def display_contacts(self):
        """Display the list of contacts."""
        print("\n[Client] Contacts:")
        for username in self.contacts.keys():
            print(f"- {username}")


if __name__ == "__main__":
    # Check if username is provided
    if len(sys.argv) < 2:
        print("Usage: python client.py <username>")
        sys.exit(1)

    username = sys.argv[1]
    client = Client(username=username)
    private_key_file = f"{username}_private_key.pem"

    # Check if private key exists
    if os.path.exists(private_key_file):
        client.load_keys(private_key_file)
    else:
        client.generate_keys()
        client.save_private_key(private_key_file)

    client.run()
