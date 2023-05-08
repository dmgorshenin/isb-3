import os
import json

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives import padding as symmetric_padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding



class CryptoSystem:
    def __init__(self, json_file: str) -> None:
        """Initialization of the cryptosystem.

        Args:
            json_file (str): The path to the json file with the settings.
        """
        self.settings=None
        try:
            with open(json_file) as json_file:
                self.settings = json.load(json_file)
        except OSError as err:
            raise
            
            
    def create_and_save_keys(self, length: int) -> None:
        """The function generates symmetric, public and private keys, 
        stores them in the specified paths and decrypts the symmetric key using the public key

        Args:
            length (int): Symmetric key length.

        Raises:
            ValueError: An exception is thrown if the length of the symmetric key specified by the user does not match the valid values.
        """
        if length == 64 or length == 128 or length == 192:
            length = int(length/8)
            symmetric_key = self.generate_symmetric_key(length)
            private_key, public_key = self.generate_asymmetric_keys()
            self.save_public_key(public_key, self.settings['public_key'])
            self.save_private_key(private_key, self.settings['secret_key'])
            ciphered_key = self.asymmetric_encrypt(public_key, symmetric_key)
            self.save_symmetric_key(ciphered_key, self.settings['symmetric_key'])
        else:
            raise ValueError 
        
    
    def encryption_text(self) -> None:
        """The function reads the saved keys and encrypts the specified text, writing it to a new text file.
        """
        private_key = self.load_private_key(self.settings['secret_key'])
        cipher_key = self.load_symmetric_key(self.settings['symmetric_key'])
        symmetric_key = self.asymmetric_decrypt(private_key, cipher_key)
        cipher_text = self.symmetric_encrypt(symmetric_key, self.byte_read_text(self.settings['text_file']))
        self.byte_write_text(cipher_text, self.settings['encrypted_file'])
      
    
    def decryption_text(self)->None:
        """The function reads an encrypted text file and decrypts the text using keys, saving it to a new file.
        """
        private_key = self.load_private_key(self.settings['secret_key'])
        cipher_key = self.load_symmetric_key(self.settings['symmetric_key'])
        symmetric_key = self.asymmetric_decrypt(private_key, cipher_key)
        cipher_text = self.byte_read_text(self.settings['encrypted_file'])
        text = self.symmetric_decrypt(symmetric_key, cipher_text)
        self.byte_write_text(text, self.settings['decrypted_file'])
        
          
    def generate_symmetric_key(self, length: int) -> bytes:
        """The function generates a symmetric key for symmetric encryption algorithm.

        Args:
            length (int): Key length in bytes.

        Returns:
            bytes: Symmetric key.
        """
        symmetric_key = os.urandom(length)
        return symmetric_key
    
    
    def generate_asymmetric_keys(self) -> tuple:
        """The function generates an asymmetric key for asymmetric encryption algorithm.

        Returns:
            tuple: Asymmetric keys.
        """
        keys = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048)
        private_key = keys
        public_key = keys.public_key()
        return private_key, public_key
    
    
    def save_symmetric_key(self, key: bytes, file_name: str) -> None:
        """The function saves a symmetric key to txt file.

        Args:
            key (bytes): Symmetric key.
            file_name (str): Name of txt file.
        """
        try:
            with open(file_name, 'wb') as key_file:
                key_file.write(key)
        except OSError as err:
            raise
    
    
    def save_private_key(self, private_key, private_pem: str) -> None:
        """ The function saves a private key to pem file.

        Args:
            private_key: Private key for asymmetric encoding algorithm.
            private_pem (str): Pem file for private key.
        """
        try:
            with open(private_pem, 'wb') as private_out:
                private_out.write(private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption()))
        except OSError as err:
            raise
        
        
    def save_public_key(self,public_key, public_pem:str)->None:
        """The function saves a public key to pem file.

        Args:
            public_key (_type_): Public key for asymmetric encoding algorithm.
            public_pem (str): Pem file for public key.
        """
        try:
            with open(public_pem, 'wb') as public_out:
                public_out.write(public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo))
        except OSError as err:
            raise
    
    
    def asymmetric_encrypt(self, public_key, text: bytes) -> bytes:
        """The function encrypts an input text using public key.

        Args:
            public_key: Public key of asymmetric encryption algorithm.
            text (bytes): Text for encryption.

        Returns:
            bytes: Encrypted text.
        """
        cipher_text = public_key.encrypt(text, asymmetric_padding.OAEP(mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        return cipher_text
    
    
    def asymmetric_decrypt(self, private_key, cipher_text: bytes) -> bytes:
        """The function decrypts an asymmetrical ciphertext using private key.

        Args:
            private_key: Private key of asymmetric encryption algorithm.
            cipher_text (bytes): Encrypted text.
            
        Returns:
            bytes: Decrypted text.
        """
        text = private_key.decrypt(cipher_text, asymmetric_padding.OAEP(mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        return text
    
    
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
        return unpadded_text
       
        
    def byte_read_text(self, file_name: str) -> bytes:
        """The function reads text in byte form from txt file.

        Args:
            file_name (str): Name of txt file.

        Returns:
            bytes: Text in byte form.
        """
        try:
            with open(file_name, mode='rb') as text_file:
                text = text_file.read()
        except OSError as err:
            raise
        return text


    def byte_write_text(self, text: bytes, file_name: str) -> None:
        """The function writes text in byte form to txt file.

        Args:
            text (bytes): Text for writing
            file_name (str): Name of txt file.
        """
        try:
            with open(file_name, mode='wb') as text_file:
                text_file.write(text)
        except OSError as err:
            raise


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
        except OSError as err:
            raise
        return key


    def load_private_key(self, private_pem: str):
        """The function loads a private key from pem file.

        Args:
            private_pem (str):  Name of pem file.

        Returns:
            Private key for asymmetric encoding algorithm.
        """
        private_key = None
        try:
            with open(private_pem, 'rb') as pem_in:
                private_bytes = pem_in.read()
            private_key = load_pem_private_key(private_bytes, password=None)
        except OSError as err:
            raise
        return private_key


    def load_public_key(self, public_pem: str):
        """The function loads a public key from pem file.

        Args:
            public_pem (str): Name of pem file.

        Returns:
            Public key for asymmetric encoding algorithm.
        """
        public_key = None
        try:
            with open(public_pem, 'rb') as pem_in:
                public_bytes = pem_in.read()
            public_key = load_pem_public_key(public_bytes)
        except OSError as err:
            raise
        return public_key
            