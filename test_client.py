import unittest
import os
from client import Client  # Assuming the client code is in client.py
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend


class TestClientCryptography(unittest.TestCase):
    def setUp(self):
        # Setup clients for testing
        self.alice = Client(username="alice_test")
        self.bob = Client(username="bob_test")

        # Generate or load keys for Alice
        alice_key_file = "alice_test_private_key.pem"
        if os.path.exists(alice_key_file):
            self.alice.load_keys(alice_key_file)
        else:
            self.alice.generate_keys()
            self.alice.save_private_key(alice_key_file)

        # Generate or load keys for Bob
        bob_key_file = "bob_test_private_key.pem"
        if os.path.exists(bob_key_file):
            self.bob.load_keys(bob_key_file)
        else:
            self.bob.generate_keys()
            self.bob.save_private_key(bob_key_file)

    def test_key_generation(self):
        # Ensure that keys are generated and loaded correctly
        self.assertIsNotNone(self.alice.private_key)
        self.assertIsNotNone(self.alice.public_key)
        self.assertIsNotNone(self.bob.private_key)
        self.assertIsNotNone(self.bob.public_key)

    def test_symmetric_encryption(self):
        # Test AES encryption and decryption
        plaintext = b"This is a test message."
        symmetric_key = os.urandom(32)  # 256-bit key
        iv = os.urandom(16)  # 128-bit IV

        # Encrypt
        cipher = Cipher(
            algorithms.AES(symmetric_key), modes.CFB(iv), backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        # Decrypt
        cipher = Cipher(
            algorithms.AES(symmetric_key), modes.CFB(iv), backend=default_backend()
        )
        decryptor = cipher.decryptor()
        decrypted_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        self.assertEqual(plaintext, decrypted_plaintext)

    def test_asymmetric_encryption(self):
        # Test RSA encryption and decryption of symmetric key
        symmetric_key = os.urandom(32)  # 256-bit key

        # Encrypt with Bob's public key
        encrypted_symmetric_key = self.bob.public_key.encrypt(
            symmetric_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        # Decrypt with Bob's private key
        decrypted_symmetric_key = self.bob.private_key.decrypt(
            encrypted_symmetric_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        self.assertEqual(symmetric_key, decrypted_symmetric_key)

    def test_digital_signature(self):
        # Test signing and verifying a message
        message = b"This is a test message."

        # Sign with Alice's private key
        signature = self.alice.private_key.sign(
            message,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

        # Verify with Alice's public key
        try:
            self.alice.public_key.verify(
                signature,
                message,
                asym_padding.PSS(
                    mgf=asym_padding.MGF1(hashes.SHA256()),
                    salt_length=asym_padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            verification_passed = True
        except InvalidSignature:
            verification_passed = False

        self.assertTrue(verification_passed)

    def test_end_to_end_message(self):
        # Simulate sending a message from Alice to Bob
        plaintext_message = "Hello Bob, this is Alice."
        recipient_public_key_pem = self.bob.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        recipient_public_key = serialization.load_pem_public_key(
            recipient_public_key_pem.encode(), backend=default_backend()
        )

        # Alice's side
        # Generate symmetric key and IV
        symmetric_key = os.urandom(32)  # AES-256 key
        iv = os.urandom(16)  # AES block size for CFB mode

        # Encrypt the message with symmetric key
        cipher = Cipher(
            algorithms.AES(symmetric_key), modes.CFB(iv), backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext_message.encode()) + encryptor.finalize()

        # Encrypt the symmetric key with Bob's public key
        encrypted_symmetric_key = recipient_public_key.encrypt(
            symmetric_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        # Sign the ciphertext with Alice's private key
        signature = self.alice.private_key.sign(
            ciphertext,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

        # Prepare the message package
        message_package = {
            "from": self.alice.username,
            "to": self.bob.username,
            "message": {
                "encrypted_symmetric_key": encrypted_symmetric_key.hex(),
                "iv": iv.hex(),
                "ciphertext": ciphertext.hex(),
                "signature": signature.hex(),
            },
        }

        # Bob's side
        sender_public_key_pem = self.alice.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        sender_public_key = serialization.load_pem_public_key(
            sender_public_key_pem.encode(), backend=default_backend()
        )

        message_content = message_package["message"]
        encrypted_symmetric_key = bytes.fromhex(
            message_content["encrypted_symmetric_key"]
        )
        iv = bytes.fromhex(message_content["iv"])
        ciphertext = bytes.fromhex(message_content["ciphertext"])
        signature = bytes.fromhex(message_content["signature"])

        # Decrypt the symmetric key with Bob's private key
        try:
            symmetric_key = self.bob.private_key.decrypt(
                encrypted_symmetric_key,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
        except Exception as e:
            self.fail(f"Failed to decrypt symmetric key: {e}")

        # Decrypt the message with symmetric key
        cipher = Cipher(
            algorithms.AES(symmetric_key), modes.CFB(iv), backend=default_backend()
        )
        decryptor = cipher.decryptor()
        decrypted_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

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
            signature_valid = True
        except InvalidSignature:
            signature_valid = False

        self.assertTrue(signature_valid)
        self.assertEqual(plaintext_message, decrypted_plaintext.decode())

    def tearDown(self):
        # Clean up test keys if desired
        pass
        # os.remove('alice_test_private_key.pem')
        # os.remove('bob_test_private_key.pem')


if __name__ == "__main__":
    unittest.main()
