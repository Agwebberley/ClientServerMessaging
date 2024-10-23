import os
import sys
import json
import datetime
from kivy.app import App
from kivy.uix.screenmanager import ScreenManager, Screen
from kivy.core.window import Window
from kivy.clock import Clock
from kivy.lang import Builder
from client_key import Client
from kivy.uix.button import Button
from kivy.uix.label import Label


# Load the KV file
Builder.load_file("chat_app.kv")

# Include your updated Client class here or import it
# from client_backend import Client


class LoginScreen(Screen):
    def login(self):
        username = self.ids.username_input.text.strip()
        server_address = self.ids.server_address_input.text.strip()
        server_port = self.ids.server_port_input.text.strip()

        if username and server_address and server_port:
            try:
                server_port = int(server_port)
            except ValueError:
                self.ids.error_label.text = "Server port must be a number."
                return

            # Proceed to the main screen
            app = App.get_running_app()
            app.username = username
            # Initialize the client with custom server address and port
            app.client = Client(
                username=username, server_host=server_address, server_port=server_port
            )
            private_key_file = f"{username}_private_key.pem"
            if os.path.exists(private_key_file):
                app.client.load_keys(private_key_file)
            else:
                app.client.generate_keys()
                app.client.save_private_key(private_key_file)
            # Now connect to server and register
            try:
                app.client.connect_to_server()
                app.client.register()
                app.client.request_contacts()
                # Load existing conversations
                app.client.load_conversations()
                # Switch to chat screen
                app.root.current = "chat"
                app.root.get_screen("chat").load_contacts()
            except Exception as e:
                print(f"[Client] Error: {e}")
                self.ids.error_label.text = str(e)
        else:
            self.ids.error_label.text = "Please fill in all fields."


class ChatScreen(Screen):
    def __init__(self, **kwargs):
        super(ChatScreen, self).__init__(**kwargs)
        self.current_contact = None

    def load_contacts(self):
        app = App.get_running_app()
        self.ids.contacts_layout.clear_widgets()
        contacts = app.client.contacts
        print(f"[Debug] Contacts: {contacts}")
        for username in contacts.keys():
            print(f"[Debug] Adding contact: {username}")
            btn = Button(
                text=username, size_hint_y=None, height=40, on_press=self.select_contact
            )
            self.ids.contacts_layout.add_widget(btn)
        self.ids.contacts_layout.do_layout()

    def select_contact(self, instance):
        self.current_contact = instance.text
        self.ids.chat_with_label.text = f"Chat with {self.current_contact}"
        self.load_messages()

    def load_messages(self):
        self.ids.messages_layout.clear_widgets()
        app = App.get_running_app()
        if self.current_contact in app.client.conversations:
            conversation = app.client.conversations[self.current_contact]
            for msg in conversation:
                timestamp = datetime.datetime.fromisoformat(msg["timestamp"]).strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
                sender = msg["sender"]
                message_text = msg["message"]
                label = Label(
                    text=f"[{timestamp}] [b]{sender}:[/b] {message_text}",
                    markup=True,
                    size_hint_y=None,
                    height=60,
                    halign="left",
                    valign="middle",
                    text_size=(Window.width - 200, None),
                )
                label.bind(size=label.setter("text_size"))
                self.ids.messages_layout.add_widget(label)
            # Scroll to the bottom
            Clock.schedule_once(self.scroll_to_bottom, 0.1)

    def scroll_to_bottom(self, dt):
        self.ids.messages_scroll.scroll_y = 0

    def send_message(self):
        message = self.ids.message_input.text.strip()
        if self.current_contact and message:
            app = App.get_running_app()
            try:
                app.client.send_message(self.current_contact, message)
                self.ids.message_input.text = ""
                # Reload messages to display the new message
                self.load_messages()
            except Exception as e:
                print(f"Error sending message: {e}")

    def on_enter(self):
        # When the screen is entered, start checking for new messages
        self.check_messages_event = Clock.schedule_interval(
            self.check_for_new_messages, 5
        )

    def on_leave(self):
        # When leaving the screen, cancel the message checking
        if hasattr(self, "check_messages_event"):
            self.check_messages_event.cancel()

    def check_for_new_messages(self, dt):
        app = App.get_running_app()
        try:
            app.client.retrieve_messages()
            # If we are chatting with someone, reload messages
            if self.current_contact:
                self.load_messages()
        except Exception as e:
            print(f"Error retrieving messages: {e}")


class ChatApp(App):
    username = ""
    client = None

    def build(self):
        # Create the screen manager
        sm = ScreenManager()
        sm.add_widget(LoginScreen(name="login"))
        sm.add_widget(ChatScreen(name="chat"))
        return sm

    def on_stop(self):
        # Disconnect from the server when the app is closed
        if self.client:
            self.client.disconnect_from_server()


if __name__ == "__main__":
    ChatApp().run()
