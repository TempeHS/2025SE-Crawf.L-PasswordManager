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

import pyfiles.arg2id as arg2id
import pyfiles.encrypt as encrypt

PATH_TO_FILE: str = r"./help.txt"


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

    def show_dialog(self):
        text = self.input_field.text()
        self.raw_password = self.input_field.text()
        start_time = time.time()
        hashed = self.hasher.hash(text)
        end_time = time.time()
        elapsed = end_time - start_time
        QMessageBox.information(
            self,
            "Submitted",
            f"Submitted text: {text}\n\nHashed password: {hashed}\n\nHashing took {elapsed:.3f} seconds",
        )

    def encode(self, password: str):
        self.encryptor.encrypt_file(
            password=password, input_path=PATH_TO_FILE, output_path=r"./help.txt.bin"
        )
        self.encryptor.decrypt_file(
            password=password,
            input_path=r"./help.txt.bin",
            output_path=r"./help_de.txt",
        )


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = SimpleApp()
    window.show()
    app.exec()
