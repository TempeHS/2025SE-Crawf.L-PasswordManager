from PyQt6.QtWidgets import QApplication, QWidget, QPushButton

# Only needed for access to command line arguments
import sys

app = QApplication(sys.argv)

window = QPushButton("Push Me")
window.show()  # The window is not visible by default; call show() to display it

app.exec()
