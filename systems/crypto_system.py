import json
from systems.asymmetric_system import *
from systems.symmetric_system import *

logger = logging.getLogger()
logger.setLevel('INFO')


class CryptoSystem:
    def __init__(self, json_file: str) -> None:
        """Initialization of the cryptosystem.

        Args:
            json_file (str): The path to the json file with the settings.
        """
        self.settings = None
        try:
            with open(json_file) as json_file:
                self.settings = json.load(json_file)
            logging.info(' Encryption settings have been successfully applied')
        except OSError as err:
            logging.warning(
                f' Encryption settings were not applied.\nError:{err}')
            raise
        try:
            self.symmetric_sys = SymmetricSystem(self.settings)
            self.asymmetric_sys = AsymmetricSystem(self.settings)
        except Exception as err:
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
            symmetric_key = self.symmetric_sys.generate_symmetric_key(length)
            private_key, public_key = self.asymmetric_sys.generate_asymmetric_keys()
            self.asymmetric_sys.save_public_key(
                public_key, self.settings['public_key'])
            self.asymmetric_sys.save_private_key(
                private_key, self.settings['secret_key'])
            ciphered_key = self.asymmetric_sys.asymmetric_encrypt(
                public_key, symmetric_key)
            self.symmetric_sys.save_symmetric_key(
                ciphered_key, self.settings['symmetric_key'])
            logging.info(
                ' Symmetric and asymmetric keys have been successfully generated and saved')
        else:
            logging.warning(' Invalid symmetric key length value')
            raise ValueError

    def encryption_text(self) -> None:
        """The function reads the saved keys and encrypts the specified text, writing it to a new text file.
        """
        private_key = self.asymmetric_sys.load_private_key(
            self.settings['secret_key'])
        cipher_key = self.symmetric_sys.load_symmetric_key(
            self.settings['symmetric_key'])
        symmetric_key = self.asymmetric_sys.asymmetric_decrypt(
            private_key, cipher_key)
        cipher_text = self.symmetric_sys.symmetric_encrypt(
            symmetric_key, self.byte_read_text(self.settings['text_file']))
        self.byte_write_text(cipher_text, self.settings['encrypted_file'])
        logging.info(' Text has been successfully encrypted')

    def decryption_text(self) -> None:
        """The function reads an encrypted text file and decrypts the text using keys, saving it to a new file.
        """
        private_key = self.asymmetric_sys.load_private_key(
            self.settings['secret_key'])
        cipher_key = self.symmetric_sys.load_symmetric_key(
            self.settings['symmetric_key'])
        symmetric_key = self.asymmetric_sys.asymmetric_decrypt(
            private_key, cipher_key)
        cipher_text = self.byte_read_text(self.settings['encrypted_file'])
        text = self.symmetric_sys.symmetric_decrypt(symmetric_key, cipher_text)
        self.byte_write_text(text, self.settings['decrypted_file'])
        logging.info(' Text has been successfully decrypted')

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
            logging.info(f' Text was successfully read from file {file_name}')
        except OSError as err:
            logging.warning(f' Text was not read.\nError:{err}')
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
            logging.info(f' Text was successfully written to file {file_name}')
        except OSError as err:
            logging.warning(f' Text was not written.\nError:{err}')
            raise
