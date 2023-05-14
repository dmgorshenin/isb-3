import os
import logging
from cryptography.hazmat.primitives import padding as symmetric_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

logger = logging.getLogger()
logger.setLevel('INFO')


class SymmetricSystem:
    def __init__(self, settings: dict) -> None:
        self.settings = settings
        logging.info(
            ' Settings for symmetric encryption have been successfully applied')

    def generate_symmetric_key(self, length: int) -> bytes:
        """The function generates a symmetric key for symmetric encryption algorithm.

        Args:
            length (int): Key length in bytes.

        Returns:
            bytes: Symmetric key.
        """
        symmetric_key = os.urandom(length)
        logging.info(
            f' Symmetric key successfully generated (key length: {length} bits)')
        return symmetric_key

    def save_symmetric_key(self, key: bytes, file_name: str) -> None:
        """The function saves a symmetric key to txt file.

        Args:
            key (bytes): Symmetric key.
            file_name (str): Name of txt file.
        """
        try:
            with open(file_name, 'wb') as key_file:
                key_file.write(key)
            logging.info(f' Symmetric key successfully saved to {file_name}')
        except OSError as err:
            logging.warning(f' Symmetric key not saved.\nError: {err}')
            raise

    def symmetric_encrypt(self, key: bytes, text: bytes) -> bytes:
        """The function encrypts an input text using symmetric key.


        Args:
            key (bytes): Symmetric key of symmetric encryption algorithm.
            text (bytes): Text for encryption.

        Returns:
            bytes: Encrypted text.
        """
        padder = symmetric_padding.ANSIX923(64).padder()
        padded_text = padder.update(text) + padder.finalize()
        iv = os.urandom(8)
        cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        cipher_text = encryptor.update(padded_text) + encryptor.finalize()
        logging.info(' Symmetric encryption was successful')
        return iv + cipher_text

    def symmetric_decrypt(self, key: bytes, cipher_text: bytes) -> bytes:
        """The function decrypts a symmetrical ciphertext using symmetric key.

        Args:
            key (bytes): Symmetric key of symmetric encryption algorithm.
            cipher_text (bytes): Encrypted text.

        Returns:
            bytes: Decrypted test.
        """
        cipher_text, iv = cipher_text[8:], cipher_text[:8]
        cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        text = decryptor.update(cipher_text) + decryptor.finalize()
        unpadder = symmetric_padding.ANSIX923(64).unpadder()
        unpadded_text = unpadder.update(text) + unpadder.finalize()
        logging.info(' Symmetric decryption was successful')
        return unpadded_text

    def load_symmetric_key(self, file_name: str) -> bytes:
        """The function loads  a symmetric key from txt file.

        Args:
            file_name (str): Name of txt file.

        Returns:
            bytes: Symmetric key for symmetric encoding algorithm.
        """
        try:
            with open(file_name, mode='rb') as key_file:
                key = key_file.read()
            logging.info(
                f' Symmetric key successfully loaded from {file_name}')
        except OSError as err:
            logging.warning(f' Symmetric key was not loaded.\nError:{err}')
            raise
        return key
