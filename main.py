from PySide6.QtWidgets import QApplication
from app import SteganographyApp
import sys

def main():
    app = QApplication(sys.argv)
    window = SteganographyApp()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
