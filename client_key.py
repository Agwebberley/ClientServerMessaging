import socket
import json
import os
import sys
import datetime  # Added for timestamp handling
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend


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
        self.conversations = {}  # Store conversations with contacts
        self.processed_message_ids = set()

    def generate_keys(self):
        """Generate RSA public and private keys."""
        print("[Client] Generating RSA keys...")
        self.private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        print("[Client] Keys generated.")

    def load_keys(self, private_key_path):
        """Load private key from a file."""
        print(f"[Client] Loading private key from '{private_key_path}'...")
        with open(private_key_path, "rb") as key_file:
            self.private_key = serialization.load_pem_private_key(
                key_file.read(), password=None, backend=default_backend()
            )
        self.public_key = self.private_key.public_key()
        print("[Client] Private key loaded.")

    def save_private_key(self, private_key_path):
        """Save the private key to a file."""
        print(f"[Client] Saving private key to '{private_key_path}'...")
        pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        with open(private_key_path, "wb") as key_file:
            key_file.write(pem)
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
        public_key_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
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
            recipient_public_key_pem.encode(), backend=default_backend()
        )

        # Generate symmetric key and IV
        symmetric_key = os.urandom(32)  # AES-256 key
        iv = os.urandom(16)  # AES block size for CFB mode

        # Encrypt the message with symmetric key
        cipher = Cipher(
            algorithms.AES(symmetric_key), modes.CFB(iv), backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext_message.encode()) + encryptor.finalize()

        # Encrypt the symmetric key with recipient's public key
        encrypted_symmetric_key = recipient_public_key.encrypt(
            symmetric_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        # Sign the ciphertext with sender's private key
        signature = self.private_key.sign(
            ciphertext,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

        # Add DateTime to the message
        timestamp = datetime.datetime.now().isoformat()

        # Package the message
        message_package = {
            "command": "send_message",
            "from": self.username,
            "to": recipient_username,
            "message": {
                "encrypted_symmetric_key": encrypted_symmetric_key.hex(),
                "iv": iv.hex(),
                "ciphertext": ciphertext.hex(),
                "signature": signature.hex(),
                "timestamp": timestamp,
            },
        }

        # Store the sent message persistently
        self.store_message(
            recipient_username, self.username, plaintext_message, timestamp
        )

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
                message_id = message.get("message_id")
                if message_id in self.processed_message_ids:
                    print(
                        f"[Client] Skipping already processed message ID {message_id}"
                    )
                    continue  # Skip already processed messages
                if message["to"] == self.username:
                    plaintext = self.process_message(message)
                    if plaintext:
                        self.processed_message_ids.add(message_id)
        else:
            print(f"[Client] Error retrieving messages: {response['message']}")

    def process_message(self, message):
        """Decrypt and verify a received message."""
        print(f"\n[Client] Processing message from '{message['from']}'...")
        sender_username = message["from"]
        sender_public_key_pem = self.get_public_key(sender_username)
        sender_public_key = serialization.load_pem_public_key(
            sender_public_key_pem.encode(), backend=default_backend()
        )

        message_content = message["message"]
        encrypted_symmetric_key = bytes.fromhex(
            message_content["encrypted_symmetric_key"]
        )
        iv = bytes.fromhex(message_content["iv"])
        ciphertext = bytes.fromhex(message_content["ciphertext"])
        signature = bytes.fromhex(message_content["signature"])
        timestamp = message_content.get(
            "timestamp", datetime.datetime.now().isoformat()
        )

        # Decrypt the symmetric key with recipient's private key
        try:
            symmetric_key = self.private_key.decrypt(
                encrypted_symmetric_key,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
        except Exception as e:
            print(f"[Client] Failed to decrypt symmetric key: {e}")
            return

        # Decrypt the message with symmetric key
        cipher = Cipher(
            algorithms.AES(symmetric_key), modes.CFB(iv), backend=default_backend()
        )
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        # Verify the signature
        try:
            sender_public_key.verify(
                signature,
                ciphertext,
                asym_padding.PSS(
                    mgf=asym_padding.MGF1(hashes.SHA256()),
                    salt_length=asym_padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            plaintext_message = plaintext.decode()
            print(
                f"[Client] Signature verified. Message from '{sender_username}': {plaintext_message}"
            )

            # Store the received message persistently
            self.store_message(
                sender_username, sender_username, plaintext_message, timestamp
            )

            return plaintext_message
        except InvalidSignature:
            print("[Client] Invalid signature. Message may have been tampered with.")
            return None

    def store_message(self, contact_username, sender, message, timestamp):
        """Store messages persistently for each conversation."""
        if contact_username not in self.conversations:
            self.conversations[contact_username] = []
        # Check if the message already exists
        for msg in self.conversations[contact_username]:
            if (
                msg["sender"] == sender
                and msg["message"] == message
                and msg["timestamp"] == timestamp
            ):
                # Message already exists, do not add it again
                return
        # Add the new message
        self.conversations[contact_username].append(
            {"sender": sender, "message": message, "timestamp": timestamp}
        )
        # Save the conversation to a JSON file
        self.save_conversation(contact_username)

    def load_conversations(self):
        """Load all conversations from files."""
        if not os.path.exists("conversations"):
            return
        for filename in os.listdir("conversations"):
            if filename.startswith(f"{self.username}_") and filename.endswith(".json"):
                contact_username = filename[len(self.username) + 1 : -5]
                with open(os.path.join("conversations", filename), "r") as f:
                    self.conversations[contact_username] = json.load(f)

    def save_conversation(self, contact_username):
        """Save a conversation to a JSON file."""
        if not os.path.exists("conversations"):
            os.makedirs("conversations")
        filename = os.path.join(
            "conversations", f"{self.username}_{contact_username}.json"
        )
        with open(filename, "w") as f:
            json.dump(self.conversations[contact_username], f)

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
            # Load existing conversations
            self.load_conversations()
            # The GUI will handle user interactions
        except Exception as e:
            print(f"[Client] Error: {e}")
            self.disconnect_from_server()
            raise e
