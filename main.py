from PyQt6.QtWidgets import QApplication, QWidget, QPushButton

# Only needed for access to command line arguments
import sys

app = QApplication(sys.argv)

button = QPushButton("Push Me")
button.show()  # The window is not visible by default; call show() to display it

app.exec()
