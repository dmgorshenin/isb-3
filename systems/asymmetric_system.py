import logging
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key

logger = logging.getLogger()
logger.setLevel('INFO')


class AsymmetricSystem:
    def __init__(self, settings: dict) -> None:
        self.settings = settings
        logging.info(
            ' Settings for asymmetric encryption have been successfully applied')

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
        logging.info(' Asymmetric keys successfully generated')
        return private_key, public_key

    def save_private_key(self, private_key, private_pem: str) -> None:
        """ The function saves a private key to pem file.

        Args:
            private_key: Private key for asymmetric encoding algorithm.
            private_pem (str): Pem file for private key.
        """
        try:
            with open(private_pem, 'wb') as private_out:
                private_out.write(private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                  format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption()))
            logging.info(f' Private key successfully saved to {private_pem}')
        except OSError as err:
            logging.warning(f' Private key not saved.\nError:{err}')
            raise

    def save_public_key(self, public_key, public_pem: str) -> None:
        """The function saves a public key to pem file.

        Args:
            public_key (_type_): Public key for asymmetric encoding algorithm.
            public_pem (str): Pem file for public key.
        """
        try:
            with open(public_pem, 'wb') as public_out:
                public_out.write(public_key.public_bytes(
                    encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo))
            logging.info(f' Public key successfully saved to {public_pem}')
        except OSError as err:
            logging.warning(f' Public key not saved.\nError:{err}')
            raise

    def asymmetric_encrypt(self, public_key, text: bytes) -> bytes:
        """The function encrypts an input text using public key.

        Args:
            public_key: Public key of asymmetric encryption algorithm.
            text (bytes): Text for encryption.

        Returns:
            bytes: Encrypted text.
        """
        cipher_text = public_key.encrypt(text, asymmetric_padding.OAEP(mgf=asymmetric_padding.MGF1(
            algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        logging.info(' Asymmetric encryption was successful')
        return cipher_text

    def asymmetric_decrypt(self, private_key, cipher_text: bytes) -> bytes:
        """The function decrypts an asymmetrical ciphertext using private key.

        Args:
            private_key: Private key of asymmetric encryption algorithm.
            cipher_text (bytes): Encrypted text.

        Returns:
            bytes: Decrypted text.
        """
        text = private_key.decrypt(cipher_text, asymmetric_padding.OAEP(mgf=asymmetric_padding.MGF1(
            algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        logging.info(' Asymmetric decryption was successful')
        return text

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
            logging.info(
                f' Private key successfully loaded from {private_pem}')
        except OSError as err:
            logging.warning(f' Private key was not loaded.\nError:{err}')
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
            logging.info(f' Public key successfully loaded from {public_pem}')
        except OSError as err:
            logging.warning(f' Public key was not loaded.\nError:{err}')
            raise
        return public_key
