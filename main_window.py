import sys
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from systems.crypto_system import *


DEFAULT_FILE_SETTINGS = 'files/settings.json'


class CryptoSystemGUI(QMainWindow):
    def __init__(self) -> None:
        """Initialization of the application window.
        """
        super().__init__()
        self.are_settings_loaded = False
        self.setWindowTitle('CryptoSystem')
        self.setGeometry(100, 100, 500, 250)
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.settings_file_label = QLabel(
            'Settings file:', self.central_widget)
        self.settings_file_label.setGeometry(50, 50, 100, 30)
        self.load_settings_file_button = QPushButton(
            'Load', self.central_widget)
        self.load_settings_file_button.setGeometry(200, 50, 100, 30)
        self.load_settings_file_button.clicked.connect(
            self.init_settings)
        self.key_length_label = QLabel(
            'Length key (in bits):', self.central_widget)
        self.key_length_label.setGeometry(50, 100, 100, 30)
        self.key_length_input = QLineEdit(self.central_widget)
        self.key_length_input.setGeometry(160, 100, 200, 30)
        self.load_keys_file_button = QPushButton('Load', self.central_widget)
        self.load_keys_file_button.setGeometry(380, 100, 100, 30)
        self.load_keys_file_button.clicked.connect(self.generate_keys)
        self.encrypt_button = QPushButton('Encrypt', self.central_widget)
        self.encrypt_button.setGeometry(50, 170, 100, 30)
        self.encrypt_button.clicked.connect(self.encrypt_text)
        self.decrypt_button = QPushButton('Decrypt', self.central_widget)
        self.decrypt_button.setGeometry(380, 170, 100, 30)
        self.decrypt_button.clicked.connect(self.decrypt_text)

    def init_settings(self) -> None:
        """A function that initializes the cryptosystem, allowing the user to select a settings file or,
        in case of an error opening the file, initializes the system with the default file.
        """
        try:
            file_name, _ = QFileDialog.getOpenFileName(
                self, 'Open Settings File', '', 'Settings Files (*.json)')
            self.crypto_system = CryptoSystem(file_name)
            QMessageBox.information(
                self, 'Settings', f'Settings file successfully loaded from file {file_name}')
        except OSError as err:
            self.crypto_system = CryptoSystem(DEFAULT_FILE_SETTINGS)
            QMessageBox.information(
                self, 'Settings', f'Settings file was not loaded from file {file_name}.'
                f'The default path was applied.\nPath: {DEFAULT_FILE_SETTINGS}')
        self.are_settings_loaded = True

    def generate_keys(self) -> None:
        """A function that asks the user for the key length and generates keys for encryption,
        then writes them to the specified path.
        """
        if self.are_settings_loaded == False:
            self.init_settings()
            self.are_settings_loaded = True
            return
        try:
            key_length = int(self.key_length_input.text())
        except Exception as err:
            QMessageBox.information(
                self, 'Key Generation', f'Something went wrong.\n{err.__str__}')
            return
        try:
            self.crypto_system.create_and_save_keys(key_length)
        except ValueError as err:
            QMessageBox.information(
                self, 'Key Generation', 'Symmetric key must be 64, 128 or 192 bytes long')
        else:
            QMessageBox.information(
                self, 'Key Generation', 'Keys have been successfully generated and saved.')

    def encrypt_text(self) -> None:
        """A function that encrypts text.
        """
        if self.are_settings_loaded == False:
            self.init_settings()
            self.are_settings_loaded = True
        try:
            self.crypto_system.encryption_text()
        except Exception as err:
            QMessageBox.information(
                self, 'Encrypt', f'Something went wrong.\n{err.__str__}')
        else:
            QMessageBox.information(self, 'File Encryption',
                                    'File has been successfully encrypted.')

    def decrypt_text(self) -> None:
        """A function that decrypts text.
        """
        if self.are_settings_loaded == False:
            self.init_settings()
            self.are_settings_loaded = True
        try:
            self.crypto_system.decryption_text()
        except Exception as err:
            QMessageBox.information(
                self, 'Decrypt', f'Something went wrong.\n{err.__str__}')
        else:
            QMessageBox.information(self, 'File Decryption',
                                    'File has been successfully decrypted.')


if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = CryptoSystemGUI()
    win.show()
    sys.exit(app.exec_())
