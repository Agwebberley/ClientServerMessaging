import socket
import threading
import json


class Server:
    def __init__(self, host="localhost", port=12345):
        self.host = host
        self.port = port
        self.contacts = {}  # Format: {username: public_key}
        self.messages = []  # List of message dictionaries
        self.lock = threading.Lock()  # For thread-safe operations

    def start(self):
        """Start the server and listen for incoming connections."""
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

    def register_user(self, username, public_key):
        """Register a new user or update the public key if the user already exists."""
        with self.lock:
            self.contacts[username] = public_key
            print(f"[Server] Registered user '{username}' with public key.")

    def store_message(self, message):
        """Store a new message."""
        with self.lock:
            self.messages.append(message)
            print(
                f"[Server] Stored message from '{message['from']}' to '{message['to']}'."
            )

    def get_messages(self):
        """Retrieve all messages."""
        with self.lock:
            return self.messages.copy()

    def get_contacts(self):
        """Retrieve all contacts."""
        with self.lock:
            return self.contacts.copy()


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
        message_content = data.get("message")
        if from_user and to_user and message_content:
            message = {"from": from_user, "to": to_user, "message": message_content}
            self.server.store_message(message)
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

    def receive_data(self):
        """Receive JSON data from the client."""
        try:
            data = self.client_socket.recv(4096)
            if not data:
                return None
            return json.loads(data.decode())
        except json.JSONDecodeError:
            self.send_data({"status": "error", "message": "Invalid JSON format."})
            return None

    def send_data(self, data):
        """Send JSON data to the client."""
        self.client_socket.sendall(json.dumps(data).encode())


if __name__ == "__main__":
    server = Server(host="localhost", port=12345)
    server.start()
