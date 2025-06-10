from PyQt6.QtWidgets import (
    QApplication,
    QWidget,
    QVBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QMessageBox,
    QSizePolicy,
)
import sys
import time
import os

import pyfiles.arg2id as arg2id
import pyfiles.encrypt as encrypt


def resource_path(relative_path):
    """Get the absolute path to a resource, works for dev and for PyInstaller bundle."""
    if hasattr(sys, '_MEIPASS'):
        # If running as a PyInstaller bundle
        base_path = sys._MEIPASS
    else:
        base_path = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_path, relative_path)


def user_data_path(filename):
    """Get a path for user data files in the user's home directory."""
    home_dir = os.path.expanduser("~")
    app_dir = os.path.join(home_dir, ".simple_app_data")
    os.makedirs(app_dir, exist_ok=True)
    return os.path.join(app_dir, filename)


class SimpleApp(QWidget):
    def __init__(self):
        super().__init__()
        self.hasher = arg2id.Argon2IDHasher()
        self.encryptor = encrypt.AESFileEncryptor()
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("Simple App")

        # Create layout
        layout = QVBoxLayout()

        # Add a label
        self.label = QLabel("Enter some text:")
        layout.addWidget(self.label)

        # Add an input field
        self.input_field = QLineEdit()
        self.input_field.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed
        )
        self.input_field.setTextMargins(
            0, 0, 0, 0
        )  # Optional: Adjust margins if needed
        layout.addWidget(self.input_field)

        # Add a submit button
        self.submit_button = QPushButton("Submit")
        self.submit_button.clicked.connect(self.show_dialog)
        layout.addWidget(self.submit_button)

        # Set the layout for the main window
        self.setLayout(layout)

    def encode(self, password: str):
        input_path = resource_path("help.txt")
        encrypted_path = user_data_path("help.txt.bin")
        decrypted_path = user_data_path("help_de.txt")
        try:
            self.encryptor.encrypt_file(
                password=password,
                input_path=input_path,
                output_path=encrypted_path,
            )
            self.encryptor.decrypt_file(
                password=password,
                input_path=encrypted_path,
                output_path=decrypted_path,
            )
            QMessageBox.information(
                self, "Success", "Encryption and decryption completed successfully."
            )
        except Exception as exc:
            self.show_error(str(exc))

    def show_error(self, message):
        """Display errors in a message box."""
        QMessageBox.critical(self, "Error", message)

    def show_dialog(self):
        text = self.input_field.text()
        self.raw_password = text
        self.encode(password=text)
        start_time = time.time()
        try:
            hashed = self.hasher.hash(text)
            end_time = time.time()
            elapsed = end_time - start_time
            QMessageBox.information(
                self,
                "Submitted",
                f"Submitted text: {text}\n\nHashed password: {hashed}\n\nHashing took {elapsed:.3f} seconds",
            )
        except Exception as exc:
            self.show_error(str(exc))


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = SimpleApp()
    window.show()
    app.exec()
