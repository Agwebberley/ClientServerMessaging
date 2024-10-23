import socket
import threading
import json
import sqlite3
import os
import sys
import argparse
import time


class Server:
    def __init__(
        self, host="localhost", port=12345, db_file="server.db", peers_file="peers.json"
    ):
        self.host = host
        self.port = port
        self.lock = threading.Lock()  # For thread-safe operations

        # Initialize the database
        self.db_file = db_file
        self.init_database()

        # Initialize peers
        self.peers_file = peers_file
        self.peers = self.load_peers()
        self.peer_handlers = []

    def init_database(self):
        """Initialize the SQLite database and create tables if they don't exist."""
        self.conn = sqlite3.connect(self.db_file, check_same_thread=False)
        self.cursor = self.conn.cursor()
        with self.lock:
            # Create users table
            self.cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    public_key TEXT NOT NULL
                )
            """)
            # Create messages table
            self.cursor.execute("""
                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sender TEXT NOT NULL,
                    recipient TEXT NOT NULL,
                    message_content TEXT NOT NULL,
                    FOREIGN KEY(sender) REFERENCES users(username),
                    FOREIGN KEY(recipient) REFERENCES users(username)
                )
            """)
            self.conn.commit()
            print("[Server] Database initialized.")

    def load_peers(self):
        """Load the list of peers from a JSON file."""
        if os.path.exists(self.peers_file):
            with open(self.peers_file, "r") as f:
                peers = json.load(f)
            print("[Server] Peers loaded from file.")
        else:
            peers = []
            print("[Server] No peers file found. Starting with an empty peer list.")
        return peers

    def save_peers(self):
        """Save the list of peers to a JSON file."""
        with open(self.peers_file, "w") as f:
            json.dump(self.peers, f, indent=4)
        print("[Server] Peers saved to file.")

    def add_peer(self, peer_host, peer_port):
        """Add a new peer to the list and save it."""
        peer = {"host": peer_host, "port": peer_port}
        if peer not in self.peers and (peer_host, peer_port) != (self.host, self.port):
            self.peers.append(peer)
            self.save_peers()
            print(f"[Server] New peer added: {peer_host}:{peer_port}")
        else:
            print("[Server] Peer already exists or is the current server.")

    def start(self):
        """Start the server and listen for incoming connections."""
        self.init_peers()  # Initialize peer handlers
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        print(f"[Server] Listening on {self.host}:{self.port}")

        try:
            while True:
                client_socket, client_address = self.server_socket.accept()
                print(f"[Server] Connection from {client_address}")
                client_handler = ClientHandler(client_socket, client_address, self)
                client_handler.start()
        except KeyboardInterrupt:
            print("\n[Server] Shutting down.")
        finally:
            self.server_socket.close()
            self.conn.close()
            # Close peer handlers
            for handler in self.peer_handlers:
                handler.stop()

    def init_peers(self):
        """Initialize connections to peer servers."""
        for peer in self.peers:
            peer_host = peer["host"]
            peer_port = peer["port"]
            if (peer_host, peer_port) != (self.host, self.port):
                handler = PeerServerHandler(peer_host, peer_port, self)
                self.peer_handlers.append(handler)
                handler.start()
        print("[Server] Peer servers initialized.")

    def register_user(self, username, public_key):
        """Register a new user or update the public key if the user already exists."""
        with self.lock:
            self.cursor.execute(
                """
                INSERT OR REPLACE INTO users (username, public_key) VALUES (?, ?)
            """,
                (username, public_key),
            )
            self.conn.commit()
            print(f"[Server] Registered user '{username}' with public key.")

    def store_message(self, sender, recipient, message_content):
        """Store a new message."""
        with self.lock:
            self.cursor.execute(
                """
                INSERT INTO messages (sender, recipient, message_content) VALUES (?, ?, ?)
            """,
                (sender, recipient, message_content),
            )
            self.conn.commit()
            print(f"[Server] Stored message from '{sender}' to '{recipient}'.")

    def get_messages(self):
        """Retrieve all messages."""
        with self.lock:
            self.cursor.execute(
                "SELECT id, sender, recipient, message_content FROM messages"
            )
            messages = self.cursor.fetchall()
            # Convert to list of dictionaries
            messages_list = [
                {
                    "message_id": row[0],
                    "from": row[1],
                    "to": row[2],
                    "message": json.loads(row[3]),
                }
                for row in messages
            ]
            return messages_list

    def get_contacts(self):
        """Retrieve all contacts."""
        with self.lock:
            self.cursor.execute("SELECT username, public_key FROM users")
            contacts = self.cursor.fetchall()
            # Convert to dictionary
            contacts_dict = {row[0]: row[1] for row in contacts}
            return contacts_dict

    def get_peer_list(self):
        """Retrieve the list of peers."""
        return self.peers.copy()

    def synchronize_peers(self, new_peers):
        """Synchronize the peer list with new peers."""
        updated = False
        for peer in new_peers:
            if peer not in self.peers and (peer["host"], peer["port"]) != (
                self.host,
                self.port,
            ):
                self.peers.append(peer)
                updated = True
                print(f"[Server] New peer discovered: {peer['host']}:{peer['port']}")
        if updated:
            self.save_peers()
            # Initialize handlers for new peers
            self.init_peers()

    # Additional methods for statistics (if needed)
    # ...


class ClientHandler(threading.Thread):
    def __init__(self, client_socket, client_address, server: Server):
        super().__init__()
        self.client_socket = client_socket
        self.client_address = client_address
        self.server = server
        self.username = None

    def run(self):
        """Handle client requests."""
        try:
            while True:
                data = self.receive_data()
                if not data:
                    break

                command = data.get("command")
                if command == "register":
                    self.handle_register(data)
                elif command == "send_message":
                    self.handle_send_message(data)
                elif command == "get_messages":
                    self.handle_get_messages()
                elif command == "get_contacts":
                    self.handle_get_contacts()
                elif command == "get_peers":
                    self.handle_get_peers()
                elif command == "sync_peers":
                    self.handle_sync_peers(data)
                else:
                    self.send_data({"status": "error", "message": "Invalid command."})
        except Exception as e:
            print(f"[ClientHandler] Error: {e}")
        finally:
            print(f"[ClientHandler] Closing connection with {self.client_address}")
            self.client_socket.close()

    def handle_register(self, data):
        """Handle user registration."""
        username = data.get("username")
        public_key = data.get("public_key")
        if username and public_key:
            self.server.register_user(username, public_key)
            self.username = username
            self.send_data(
                {"status": "success", "message": "User registered successfully."}
            )
        else:
            self.send_data(
                {"status": "error", "message": "Username and public key required."}
            )

    def handle_send_message(self, data):
        """Handle sending a message."""
        from_user = data.get("from")
        to_user = data.get("to")
        message_content = json.dumps(data.get("message"))  # Store as JSON string
        if from_user and to_user and message_content:
            self.server.store_message(from_user, to_user, message_content)
            self.send_data(
                {"status": "success", "message": "Message sent successfully."}
            )
        else:
            self.send_data({"status": "error", "message": "Incomplete message data."})

    def handle_get_messages(self):
        """Handle retrieving messages."""
        messages = self.server.get_messages()
        self.send_data({"status": "success", "messages": messages})

    def handle_get_contacts(self):
        """Handle retrieving contacts."""
        contacts = self.server.get_contacts()
        self.send_data({"status": "success", "contacts": contacts})

    def handle_get_peers(self):
        """Handle retrieving peer list."""
        peers = self.server.get_peer_list()
        self.send_data({"status": "success", "peers": peers})

    def handle_sync_peers(self, data):
        """Handle synchronizing peers."""
        new_peers = data.get("peers")
        if new_peers:
            self.server.synchronize_peers(new_peers)
            self.send_data({"status": "success", "message": "Peer list synchronized."})
        else:
            self.send_data(
                {"status": "error", "message": "No peers provided for synchronization."}
            )

    def receive_data(self):
        """Receive JSON data from the client."""
        try:
            data = self.client_socket.recv(8192)
            if not data:
                return None
            return json.loads(data.decode())
        except json.JSONDecodeError:
            self.send_data({"status": "error", "message": "Invalid JSON format."})
            return None

    def send_data(self, data):
        """Send JSON data to the client."""
        self.client_socket.sendall(json.dumps(data).encode())


class PeerServerHandler(threading.Thread):
    def __init__(self, peer_host, peer_port, server: Server):
        super().__init__()
        self.peer_host = peer_host
        self.peer_port = peer_port
        self.server = server
        self.socket = None
        self.connected = False
        self.running = True

    def run(self):
        """Connect to the peer server and synchronize data periodically."""
        while self.running:
            try:
                if not self.connected:
                    self.connect_to_peer()
                # Synchronize data
                self.request_user_sync()
                self.request_message_sync()
                self.request_peer_sync()
                time.sleep(10)  # Synchronize every 10 seconds
            except Exception as e:
                print(f"[PeerServerHandler] Error: {e}")
                self.connected = False
                if self.socket:
                    self.socket.close()
                time.sleep(5)  # Wait before retrying

    def stop(self):
        """Stop the peer handler thread."""
        self.running = False
        if self.socket:
            self.socket.close()

    def connect_to_peer(self):
        """Establish a connection to the peer server."""
        print(
            f"[PeerServerHandler] Connecting to peer server at {self.peer_host}:{self.peer_port}..."
        )
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.peer_host, self.peer_port))
        self.connected = True
        print("[PeerServerHandler] Connected to peer server.")

    def request_user_sync(self):
        """Request user data from the peer server."""
        data = {"command": "get_contacts"}
        self.send_data(data)
        response = self.receive_data()
        if response and response["status"] == "success":
            contacts = response["contacts"]
            with self.server.lock:
                for username, public_key in contacts.items():
                    self.server.register_user(username, public_key)
            print("[PeerServerHandler] User data synchronized.")
        else:
            print("[PeerServerHandler] Failed to synchronize user data.")

    def request_message_sync(self):
        """Request messages from the peer server."""
        data = {"command": "get_messages"}
        self.send_data(data)
        response = self.receive_data()
        if response and response["status"] == "success":
            messages = response["messages"]
            with self.server.lock:
                for message in messages:
                    sender = message["from"]
                    recipient = message["to"]
                    message_content = json.dumps(message["message"])
                    self.server.store_message(sender, recipient, message_content)
            print("[PeerServerHandler] Message data synchronized.")
        else:
            print("[PeerServerHandler] Failed to synchronize messages.")

    def request_peer_sync(self):
        """Request peer list synchronization."""
        data = {"command": "get_peers"}
        self.send_data(data)
        response = self.receive_data()
        if response and response["status"] == "success":
            peer_list = response["peers"]
            self.server.synchronize_peers(peer_list)
            # Send back our peer list to the peer server
            sync_data = {"command": "sync_peers", "peers": self.server.get_peer_list()}
            self.send_data(sync_data)
            sync_response = self.receive_data()
            if sync_response and sync_response["status"] == "success":
                print("[PeerServerHandler] Peer list synchronized.")
            else:
                print(
                    "[PeerServerHandler] Failed to synchronize peer list with peer server."
                )
        else:
            print("[PeerServerHandler] Failed to retrieve peer list from peer server.")

    def send_data(self, data):
        """Send JSON data to the peer server."""
        self.socket.sendall(json.dumps(data).encode())

    def receive_data(self):
        """Receive JSON data from the peer server."""
        data = self.socket.recv(8192)
        if not data:
            return None
        return json.loads(data.decode())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Start the messaging server.")
    parser.add_argument(
        "--host", default="localhost", help="Server host (default: localhost)"
    )
    parser.add_argument(
        "--port", type=int, default=12345, help="Server port (default: 12345)"
    )
    parser.add_argument(
        "--register-peer",
        nargs=2,
        metavar=("PEER_HOST", "PEER_PORT"),
        help="Register a new peer server",
    )
    args = parser.parse_args()

    server = Server(host=args.host, port=args.port)

    if args.register_peer:
        peer_host, peer_port = args.register_peer
        peer_port = int(peer_port)
        server.add_peer(peer_host, peer_port)
        print(f"[Server] Peer {peer_host}:{peer_port} registered.")
    else:
        server.start()
