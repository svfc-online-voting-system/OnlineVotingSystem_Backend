"""This module contains the class for decrypting data."""

from base64 import b64decode

from json import loads
from Crypto.Cipher import AES

from app.config.base_config import BaseConfig


KEY = bytes.fromhex(BaseConfig.ENCRYPTION_KEY)  # type: ignore


class Decryption:
    """Class for decrypting data"""

    def unpad(self, data, block_size):  # pylint: disable=unused-argument
        """Unpad the data"""
        padding_length = data[-1]
        return data[:-padding_length]

    def decrypt_poll_cast_entry(self, poll_vote_token: str) -> dict:
        """
        Decrypt a poll cast entry.

        Args:
            encrypted_data (str): The encrypted poll cast entry.

        Returns:
            dict: The decrypted poll cast entry.
        """
        iv_base64, ciphertext_base64 = poll_vote_token.split("$")

        iv = b64decode(iv_base64)
        ciphertext = b64decode(ciphertext_base64)

        cipher = AES.new(KEY, AES.MODE_CBC, iv)
        decrypted_data = self.unpad(cipher.decrypt(ciphertext), AES.block_size)

        return loads(decrypted_data)
