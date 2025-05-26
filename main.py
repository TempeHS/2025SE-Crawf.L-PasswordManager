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


class SimpleApp(QWidget):
    def __init__(self):
        super().__init__()
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
        QMessageBox.information(self, "Submitted", f"Submitted text: {text}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = SimpleApp()
    window.show()
    app.exec()
