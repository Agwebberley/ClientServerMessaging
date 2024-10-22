import threading
import tkinter as tk
from tkinter import messagebox, scrolledtext
from client_key import Client  # Assuming the client code is in client.py
import os


class ClientGUI:
    def __init__(self):
        self.client = None
        self.root = tk.Tk()
        self.root.title("Secure Messaging Client")
        self.username = None
        self.create_login_screen()

    def create_login_screen(self):
        """Create the login screen to enter username."""
        self.clear_window()
        tk.Label(self.root, text="Enter your username:", font=("Helvetica", 14)).pack(
            pady=10
        )
        self.username_entry = tk.Entry(self.root, font=("Helvetica", 12))
        self.username_entry.pack(pady=5)
        tk.Button(
            self.root, text="Login", command=self.login, font=("Helvetica", 12)
        ).pack(pady=10)

    def login(self):
        """Handle user login."""
        username = self.username_entry.get().strip()
        if not username:
            messagebox.showerror("Error", "Please enter a username.")
            return

        self.username = username
        self.client = Client(username=username)
        private_key_file = f"{username}_private_key.pem"

        # Check if private key exists
        if os.path.exists(private_key_file):
            self.client.load_keys(private_key_file)
        else:
            self.client.generate_keys()
            self.client.save_private_key(private_key_file)

        # Start the client connection in a separate thread
        threading.Thread(target=self.run_client, daemon=True).start()
        self.create_main_screen()

    def run_client(self):
        """Connect to the server and handle networking."""
        try:
            self.client.connect_to_server()
            self.client.register()
            self.client.request_contacts()
        except Exception as e:
            messagebox.showerror(
                "Connection Error", f"Failed to connect to server: {e}"
            )
            return

        # Start a thread to periodically check for new messages
        threading.Thread(
            target=self.retrieve_messages_periodically, daemon=True
        ).start()

    def create_main_screen(self):
        """Create the main messaging interface."""
        self.clear_window()

        # Left frame for contacts
        self.left_frame = tk.Frame(self.root)
        self.left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=10, pady=10)

        tk.Label(self.left_frame, text="Contacts", font=("Helvetica", 14)).pack(pady=5)
        self.contacts_listbox = tk.Listbox(self.left_frame, font=("Helvetica", 12))
        self.contacts_listbox.pack(fill=tk.Y, expand=True)

        tk.Button(
            self.left_frame,
            text="Refresh Contacts",
            command=self.refresh_contacts,
            font=("Helvetica", 12),
        ).pack(pady=5)

        # Right frame for messages
        self.right_frame = tk.Frame(self.root)
        self.right_frame.pack(
            side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=10, pady=10
        )

        tk.Label(self.right_frame, text="Messages", font=("Helvetica", 14)).pack(pady=5)
        self.messages_text = scrolledtext.ScrolledText(
            self.right_frame, font=("Helvetica", 12), state="disabled"
        )
        self.messages_text.pack(fill=tk.BOTH, expand=True)

        self.message_entry = tk.Entry(self.right_frame, font=("Helvetica", 12))
        self.message_entry.pack(fill=tk.X, pady=5)
        self.message_entry.bind("<Return>", self.send_message)

        tk.Button(
            self.right_frame,
            text="Send",
            command=self.send_message,
            font=("Helvetica", 12),
        ).pack(pady=5)

        # Refresh contacts initially
        self.refresh_contacts()

    def refresh_contacts(self):
        """Refresh the contacts list from the server."""
        self.client.request_contacts()
        self.contacts_listbox.delete(0, tk.END)
        for username in self.client.contacts.keys():
            if username != self.username:
                self.contacts_listbox.insert(tk.END, username)

    def send_message(self, event=None):
        """Send a message to the selected contact."""
        selected_indices = self.contacts_listbox.curselection()
        if not selected_indices:
            messagebox.showwarning(
                "No Recipient", "Please select a contact to send a message."
            )
            return
        recipient = self.contacts_listbox.get(selected_indices[0])
        message = self.message_entry.get().strip()
        if not message:
            messagebox.showwarning("Empty Message", "Please enter a message to send.")
            return
        # Send the message in a separate thread to avoid blocking the GUI
        threading.Thread(
            target=self.send_message_thread, args=(recipient, message), daemon=True
        ).start()
        self.messages_text.config(state="normal")
        self.messages_text.insert(tk.END, f"You to {recipient}: {message}\n")
        self.messages_text.config(state="disabled")
        self.message_entry.delete(0, tk.END)

    def send_message_thread(self, recipient, message):
        """Threaded function to send a message."""
        try:
            self.client.send_message(recipient, message)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to send message: {e}")

    def retrieve_messages_periodically(self):
        """Retrieve messages from the server periodically."""
        while True:
            try:
                self.client.retrieve_messages()
            except Exception as e:
                print(f"Error retrieving messages: {e}")
            self.root.after(
                5000, self.update_messages
            )  # Update messages every 5 seconds

    def update_messages(self):
        """Update the messages display with any new messages."""
        # Since process_message displays messages directly, we might not need to do anything here
        pass

    def process_message(self, message):
        """Override the client's process_message to display messages in the GUI."""
        sender_username = message["from"]
        # Decrypt and verify the message
        plaintext = self.client.process_message(message)
        if plaintext is not None:
            self.messages_text.config(state="normal")
            self.messages_text.insert(tk.END, f"{sender_username}: {plaintext}\n")
            self.messages_text.config(state="disabled")
            self.messages_text.see(tk.END)

    def clear_window(self):
        """Clear all widgets from the root window."""
        for widget in self.root.winfo_children():
            widget.destroy()

    def run(self):
        """Run the main Tkinter loop."""
        self.root.mainloop()


if __name__ == "__main__":
    app = ClientGUI()
    app.run()
