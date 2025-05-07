from PySide6.QtWidgets import QDialog, QVBoxLayout, QTextEdit, QLabel, QPushButton, QLineEdit, QHBoxLayout, QMessageBox, QApplication
from PySide6.QtGui import QFont, QIcon
from PySide6.QtCore import Qt, Signal

class HelpDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Help - Secure Steganography Tool")
        self.setFixedSize(600, 500)
        self.setModal(True)

        # Apply main window's palette
        self.setPalette(parent.palette())

        layout = QVBoxLayout()

        help_text = QTextEdit()
        help_text.setReadOnly(True)
        help_text.setHtml("""
            <h2>Secure Steganography Tool - User Guide</h2>

            <h3>Basic Usage:</h3>
            <ol>
                <li><b>Open Image</b>: Select a cover image (PNG recommended)</li>
                <li><b>Hide Data</b>:
                    <ul>
                        <li>Enter text in the message field and click "Hide Text"</li>
                        <li>OR click "Hide File" to embed another file</li>
                    </ul>
                </li>
                <li><b>Save Image</b>: Save the stego image with hidden data</li>
            </ol>

            <h3>Advanced Features:</h3>
            <ul>
                <li><b>Encryption</b>: Toggle ON to password-protect hidden data</li>
                <li><b>Show Data</b>: Reveal hidden text from an image</li>
                <li><b>Show Image</b>: Reveal a hidden image from a stego image</li>
                <li><b>QR Code</b>: Generate QR codes from text messages</li>
            </ul>

            <h3>Tips:</h3>
            <ul>
                <li>For best results, use PNG images as cover files</li>
                <li>Larger cover images can hide more data</li>
                <li>Encrypted data requires the same password to reveal</li>
                <li>The tool preserves image quality during hiding</li>
            </ul>
        """)

        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.close)

        layout.addWidget(help_text)
        layout.addWidget(close_btn, alignment=Qt.AlignCenter)
        self.setLayout(layout)

class PasswordDialog(QDialog):
    submitted = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Enter Encryption Password")
        self.setFixedSize(350, 200)
        self.setModal(True)

        # Apply main window's palette
        self.setPalette(parent.palette())
        self.setWindowFlags(self.windowFlags() | Qt.WindowStaysOnTopHint)

        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(20, 20, 20, 20)

        # Header
        header = QLabel("Enter Password")
        header.setAlignment(Qt.AlignCenter)
        header_font = QFont("Arial", 14, QFont.Bold)
        header.setFont(header_font)
        header.setStyleSheet("color: #8e2dc5; margin-bottom: 15px;")
        main_layout.addWidget(header)

        # Password input
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Enter your encryption password...")
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setStyleSheet("""
            QLineEdit {
                background-color: #252525;
                color: white;
                border: 1px solid #555;
                border-radius: 4px;
                padding: 8px;
                font-size: 14px;
            }
        """)
        main_layout.addWidget(self.password_input)

        # Button layout
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(15)

        submit_btn = QPushButton("Submit")
        submit_btn.setIcon(QIcon.fromTheme("dialog-ok"))
        submit_btn.setStyleSheet("""
            QPushButton {
                background-color: #8e2dc5;
                color: white;
                padding: 8px 16px;
                border-radius: 4px;
                min-width: 100px;
            }
            QPushButton:hover {
                background-color: #7d25b5;
            }
        """)
        submit_btn.clicked.connect(self.on_submit)

        cancel_btn = QPushButton("Cancel")
        cancel_btn.setIcon(QIcon.fromTheme("dialog-cancel"))
        cancel_btn.setStyleSheet("""
            QPushButton {
                background-color: #555;
                color: white;
                padding: 8px 16px;
                border-radius: 4px;
                min-width: 100px;
            }
            QPushButton:hover {
                background-color: #666;
            }
        """)
        cancel_btn.clicked.connect(self.close)

        btn_layout.addWidget(submit_btn)
        btn_layout.addWidget(cancel_btn)
        main_layout.addLayout(btn_layout)

        self.setLayout(main_layout)

        # Center the dialog relative to parent
        if parent:
            self.move(
                parent.x() + parent.width() // 2 - self.width() // 2,
                parent.y() + parent.height() // 2 - self.height() // 2
            )

    def on_submit(self):
        password = self.password_input.text()
        if password:
            # Disable UI during processing
            self.setEnabled(False)
            QApplication.processEvents()

            try:
                # Emit the password signal
                self.submitted.emit(password)
                self.close()
            except Exception as e:
                QMessageBox.critical(self, "Error",
                                     f"Failed to process password: {str(e)}")
                self.setEnabled(True)
        else:
            QMessageBox.warning(self, "Warning", "Password cannot be empty!")
