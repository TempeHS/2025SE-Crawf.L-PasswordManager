from PyQt6.QtWidgets import QApplication, QWidget, QPushButton

# Only needed for access to command line arguments
import sys

app = QApplication(sys.argv)

window = QPushButton("Push Me")
window.show()  # by default the windows doesn't show

app.exec()
