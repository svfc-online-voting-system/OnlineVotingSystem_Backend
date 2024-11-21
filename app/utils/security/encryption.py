""" This module responsibility is to encrypt voting data """

import base64
from json import dumps

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from app.config.base_config import BaseConfig

KEY = bytes.fromhex(BaseConfig.ENCRYPTION_KEY)  # type: ignore


class Encryption:
    """This class is responsible for encrypting and decrypting voting data."""

    def pad(self, data, block_size):
        """Pad the data to the block size."""
        padding_length = block_size - len(data) % block_size
        return data + bytes([padding_length] * padding_length)

    def encrypt_poll_cast_entry(self, user_id, event_uuid_bin, poll_option_id) -> str:
        """
        Encrypt a poll cast entry.

        Args:
            user_id (str): The user ID.
            event_uuid_bin (bytes): The event UUID in binary format.
            poll_option_id (str): The poll option ID.

        Returns:
            str: The encrypted poll cast entry.
        """
        # Convert binary UUID to a Base64 string for serialization
        event_uuid_base64 = base64.b64encode(event_uuid_bin).decode("utf-8")

        # Prepare data for encryption
        data = {
            "user_id": user_id,
            "event_uuid": event_uuid_base64,  # Store UUID as Base64
            "poll_option_id": poll_option_id,
        }
        data_bytes = dumps(data).encode("utf-8")

        # Generate a random IV
        iv = get_random_bytes(16)

        # Encrypt the data using AES in CBC mode
        cipher = AES.new(KEY, AES.MODE_CBC, iv)
        cipher_text = cipher.encrypt(self.pad(data_bytes, AES.block_size))

        # Encode IV and ciphertext in Base64 for storage
        iv_base64 = base64.b64encode(iv).decode("utf-8")
        cipher_text_base64 = base64.b64encode(cipher_text).decode("utf-8")

        # Return the combined IV and ciphertext
        return f"{iv_base64}${cipher_text_base64}"
