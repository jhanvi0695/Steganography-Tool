from PySide6.QtWidgets import (QMainWindow, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QFileDialog, QMessageBox,
                               QWidget, QFrame, QSizePolicy, QGroupBox, QSpacerItem, QTextEdit)
from PySide6.QtGui import QPixmap, QImage, QFont, QIcon, QPalette, QColor
from PySide6.QtCore import Qt, QTimer
import os
import qrcode
from stegano import lsb
import base64
import hashlib
from PIL import Image

from dialogs import HelpDialog, PasswordDialog
from crypto_utils import encrypt_message, decrypt_message

class SteganographyApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Secure Steganography Tool")
        self.setWindowIcon(QIcon("logo.png"))
        self.setMinimumSize(1300, 700)

        # Store revealed image data
        self.revealed_image_data = None

        # Store original secret file extension for saving revealed files
        self.secret_file_extension = None

        # Set dark theme palette
        palette = QPalette()
        palette.setColor(QPalette.Window, QColor(53, 53, 53))
        palette.setColor(QPalette.WindowText, Qt.white)
        palette.setColor(QPalette.Base, QColor(35, 35, 35))
        palette.setColor(QPalette.AlternateBase, QColor(53, 53, 53))
        palette.setColor(QPalette.ToolTipBase, Qt.white)
        palette.setColor(QPalette.ToolTipText, Qt.white)
        palette.setColor(QPalette.Text, Qt.white)
        palette.setColor(QPalette.Button, QColor(53, 53, 53))
        palette.setColor(QPalette.ButtonText, Qt.white)
        palette.setColor(QPalette.BrightText, Qt.red)
        palette.setColor(QPalette.Highlight, QColor(142, 45, 197).lighter())
        palette.setColor(QPalette.HighlightedText, Qt.black)
        self.setPalette(palette)
        self.filename = None
        self.secret = None
        self.enable_encryption = False

        # Main widget and layout
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QVBoxLayout()
        main_widget.setLayout(main_layout)

        # Header
        header = QLabel("Secure Steganography")
        header.setAlignment(Qt.AlignCenter)
        header_font = QFont("Arial", 24, QFont.Bold)
        header.setFont(header_font)
        header.setStyleSheet("color: #8e2dc5; margin-bottom: 20px;")
        main_layout.addWidget(header)

        # Main content
        content_layout = QHBoxLayout()
        main_layout.addLayout(content_layout)

        # Image panel
        image_panel = QGroupBox("Image Preview")
        image_panel.setStyleSheet("QGroupBox { font-size: 16px; }")
        image_layout = QVBoxLayout()

        self.image_label = QLabel()
        self.image_label.setAlignment(Qt.AlignCenter)
        self.image_label.setFrameShape(QFrame.Box)
        self.image_label.setMinimumSize(400, 400)
        self.image_label.setStyleSheet("""
            QLabel {
                background-color: #252525;
                border: 2px dashed #555;
                border-radius: 8px;
            }
        """)
        image_layout.addWidget(self.image_label)

        # Image controls
        img_btn_layout = QHBoxLayout()
        open_btn = QPushButton("Open Image")
        open_btn.setIcon(QIcon.fromTheme("document-open"))
        open_btn.clicked.connect(self.show_image)
        img_btn_layout.addWidget(open_btn)

        save_btn = QPushButton("Save Image")
        save_btn.setIcon(QIcon.fromTheme("document-save"))
        save_btn.clicked.connect(self.save_image)
        img_btn_layout.addWidget(save_btn)

        save_file_btn = QPushButton("Save File")
        save_file_btn.setIcon(QIcon.fromTheme("document-save"))
        save_file_btn.clicked.connect(self.save_file)
        img_btn_layout.addWidget(save_file_btn)

        image_layout.addLayout(img_btn_layout)
        image_panel.setLayout(image_layout)
        content_layout.addWidget(image_panel)

        # Control panel
        control_panel = QGroupBox("Controls")
        control_panel.setStyleSheet("QGroupBox { font-size: 16px; }")
        control_layout = QVBoxLayout()

        # Encryption and QR code buttons layout
        enc_qr_layout = QHBoxLayout()

        # Encryption toggle button
        self.encryption_btn = QPushButton("🔓 Encryption: OFF")
        self.encryption_btn.setCheckable(True)
        self.encryption_btn.setStyleSheet("""
            QPushButton {
                background-color: #555;
                color: white;
                border: 2px solid #444;
                padding: 8px 16px;
                border-radius: 6px;
                min-width: 160px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:checked {
                background-color: #8e2dc5;
                border-color: #7d25b5;
            }
            QPushButton:hover {
                opacity: 0.9;
            }
        """)
        self.encryption_btn.clicked.connect(self.toggle_encryption)
        enc_qr_layout.addWidget(self.encryption_btn)

        # Information panel
        info_panel = QGroupBox("About Steganography")
        info_layout = QVBoxLayout()
        self.info_text = QTextEdit()
        self.info_text.setReadOnly(True)
        self.info_text.setHtml("""
            <h3>What is Steganography?</h3>
            <p>Steganography is the practice of concealing messages or information 
            within other non-secret text or data.</p>
            
            <h3>How It Works</h3>
            <p>This tool uses LSB (Least Significant Bit) steganography to hide data in images:</p>
            <ul>
                <li>Each pixel's color values are slightly modified</li>
                <li>The changes are imperceptible to human eyes</li>
                <li>Supports hiding text or other images</li>
                <li>Optional AES-256 encryption for security</li>
            </ul>
            
            <h3>Best Practices</h3>
            <ul>
                <li>Use PNG format for best results</li>
                <li>Larger images can hide more data</li>
                <li>Remember your encryption password</li>
                <li>Test extraction after hiding data</li>
            </ul>
        """)
        self.info_text.setStyleSheet("""
            QTextEdit {
                background-color: #252525;
                color: white;
                border: 1px solid #555;
                border-radius: 4px;
                padding: 8px;
                font-size: 13px;
            }
        """)
        info_layout.addWidget(self.info_text)
        info_panel.setLayout(info_layout)
        control_layout.addWidget(info_panel)

        # Message section
        message_group = QGroupBox("Secret Message")
        message_layout = QVBoxLayout()

        self.text_input = QLineEdit()
        self.text_input.setPlaceholderText("Enter your secret message here...")
        self.text_input.setStyleSheet("""
            QLineEdit {
                background-color: #252525;
                color: white;
                border: 1px solid #555;
                border-radius: 4px;
                padding: 8px;
                font-size: 14px;
            }
        """)
        message_layout.addWidget(self.text_input)
        message_group.setLayout(message_layout)
        control_layout.addWidget(message_group)

        # Action buttons
        action_btn_layout = QHBoxLayout()

        hide_text_btn = QPushButton("Hide Text")
        hide_text_btn.setIcon(QIcon.fromTheme("edit-hide"))
        hide_text_btn.setStyleSheet("background-color: #8e2dc5; color: white;")
        hide_text_btn.clicked.connect(self.hide_data)
        action_btn_layout.addWidget(hide_text_btn)

        show_text_btn = QPushButton("Show Text")
        show_text_btn.setIcon(QIcon.fromTheme("edit-show"))
        show_text_btn.setStyleSheet("background-color: #2d7fc5; color: white;")
        show_text_btn.clicked.connect(self.show_data)
        action_btn_layout.addWidget(show_text_btn)

        hide_img_btn = QPushButton("Hide File")
        hide_img_btn.setIcon(QIcon.fromTheme("image-x-generic"))
        hide_img_btn.setStyleSheet("background-color: #c58e2d; color: white;")
        hide_img_btn.clicked.connect(self.hide_file)
        action_btn_layout.addWidget(hide_img_btn)

        show_img_btn = QPushButton("Show File")
        show_img_btn.setIcon(QIcon.fromTheme("image-x-generic"))
        show_img_btn.setStyleSheet("background-color: #2dc58e; color: white;")
        show_img_btn.clicked.connect(self.reveal_file)
        action_btn_layout.addWidget(show_img_btn)

        control_layout.addLayout(action_btn_layout)

        # QR code button
        qr_btn = QPushButton("Generate QR Code")
        qr_btn.setIcon(QIcon.fromTheme("image-x-generic"))
        qr_btn.setStyleSheet("""
            QPushButton {
                background-color: #2dc58e;
                color: white;
                padding: 8px 16px;
                border-radius: 6px;
                min-width: 160px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover {
                opacity: 0.9;
            }
        """)
        qr_btn.clicked.connect(self.generate_qr)
        enc_qr_layout.addWidget(qr_btn)

        control_layout.addLayout(enc_qr_layout)

        # Help button
        help_btn = QPushButton("Help")
        help_btn.setIcon(QIcon.fromTheme("help-contents"))
        help_btn.setStyleSheet("background-color: #555; color: white;")
        help_btn.clicked.connect(self.show_help)
        control_layout.addWidget(help_btn)

        control_layout.addSpacerItem(QSpacerItem(20, 40, QSizePolicy.Minimum, QSizePolicy.Expanding))
        control_panel.setLayout(control_layout)
        content_layout.addWidget(control_panel)

        # Set button styles
        self.setStyleSheet("""
            QMainWindow {
                background-color: #353535;
            }
            QPushButton {
                padding: 8px 16px;
                border-radius: 6px;
                font-weight: bold;
                min-width: 140px;
                font-size: 14px;
                border: 2px solid #444;
            }
            QPushButton:hover {
                opacity: 0.9;
            }
            QGroupBox {
                margin-top: 15px;
                border: 2px solid #444;
                border-radius: 8px;
                padding-top: 20px;
                font-size: 16px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
            QLineEdit, QTextEdit {
                border-radius: 6px;9
                padding: 8px;
                font-size: 14px;
                border: 2px solid #555;
            }
            QLabel {
                font-size: 14px;
            }
        """)

    def toggle_encryption(self):
        self.enable_encryption = self.encryption_btn.isChecked()
        if self.enable_encryption:
            self.encryption_btn.setText("🔐 Encryption: ON")
            self.encryption_btn.setStyleSheet(self.encryption_btn.styleSheet() + """
                QPushButton {
                    background-color: #8e2dc5;
                }
            """)
        else:
            self.encryption_btn.setText("🔓 Encryption: OFF")
            self.encryption_btn.setStyleSheet(self.encryption_btn.styleSheet() + """
                QPushButton {
                    background-color: #555;
                }
            """)

    def save_file(self):
        filename = None
        if self.revealed_image_data:
            # Suggest default extension if known
            default_filter = "All Files (*)"
            if self.secret_file_extension:
                ext = self.secret_file_extension.lower()
                if ext == ".pdf":
                    default_filter = "PDF Files (*.pdf)"
                elif ext in [".doc", ".docx"]:
                    default_filter = "Word Documents (*.doc *.docx)"
                elif ext in [".txt"]:
                    default_filter = "Text Files (*.txt)"
                else:
                    default_filter = f"{ext.upper()} Files (*{ext})"

            filename, _ = QFileDialog.getSaveFileName(
                self, "Save File", os.getcwd(),
                default_filter
            )
            if filename:
                try:
                    with open(filename, "wb") as f:
                        f.write(self.revealed_image_data)
                    QMessageBox.information(self, "Success", "File saved successfully!")
                    # Clear revealed data after saving
                    self.revealed_image_data = None
                    self.filename = None
                    self.secret = None
                    self.secret_file_extension = None
                    self.image_label.clear()
                    self.text_input.clear()
                except Exception as e:
                    QMessageBox.critical(self, "Error", f"Failed to save file: {str(e)}")
            else:
                QMessageBox.warning(self, "Warning", "No file data found to save")

    def show_image(self):
        filename, _ = QFileDialog.getOpenFileName(
            self, "Select Image File", os.getcwd(),
            "Image Files (*.png *.jpg *.bmp *.gif)"
        )
        if filename:
            self.filename = filename
            img = Image.open(filename).convert("RGB").resize((400, 400))
            img = img.convert("RGBA")
            data = img.tobytes("raw", "RGBA")
            qimg = QImage(data, img.size[0], img.size[1], QImage.Format_RGBA8888)
            self.image_label.setPixmap(QPixmap.fromImage(qimg))

    def hide_data(self):
        message = self.text_input.text().strip()
        if message and self.filename:
            if self.enable_encryption:
                self.password_dialog = PasswordDialog(self)
                self.password_dialog.setAttribute(Qt.WA_DeleteOnClose)
                self.password_dialog.submitted.connect(
                    lambda p: self.complete_hide(message, p)
                )
                self.password_dialog.exec()
            else:
                self.complete_hide(message)
        else:
            QMessageBox.warning(self, "Warning",
                                "Please select an image and enter a message!")

    def complete_hide(self, message, password=None):
        try:
            if password:
                message = encrypt_message(message, password)
            self.secret = lsb.hide(self.filename, message)
            # Show success message after dialog closes
            QTimer.singleShot(100, lambda: QMessageBox.information(
                self, "Success", "File hidden successfully! Click on 'Save File' to save it. "))
        except Exception as e:
            QMessageBox.critical(self, "Error",
                                 f"Failed to hide data: {str(e)}")

    def show_data(self):
        try:
            if not self.filename:
                QMessageBox.warning(self, "Warning",
                                    "Please select an image first!")
                return

            message = lsb.reveal(self.filename)
            if not message:
                self.text_input.setText("No hidden message found!")
                return

            if self.enable_encryption:
                self.password_dialog = PasswordDialog(self)
                self.password_dialog.setAttribute(Qt.WA_DeleteOnClose)
                self.password_dialog.submitted.connect(
                    lambda p: self.decrypt_and_show(message, p)
                )
                self.password_dialog.exec()
            else:
                self.text_input.setText(message)
        except Exception as e:
            self.text_input.setText("Error revealing message!")

    def decrypt_and_show(self, message, password):
        decrypted = decrypt_message(message, password)
        self.text_input.setText(decrypted)

    def save_image(self):
        if self.secret or self.revealed_image_data:
            filename, _ = QFileDialog.getSaveFileName(
                self, "Save Image", os.getcwd(),
                "PNG Files (*.png)"
            )
            if filename:
                if self.secret:
                    self.secret.save(filename)
                else:
                    with open(filename, "wb") as f:
                        f.write(self.revealed_image_data)
                QMessageBox.information(self, "Success",
                                        "Image saved successfully!")
                # Clear all inputs
                self.filename = None
                self.secret = None
                self.revealed_image_data = None
                self.image_label.clear()
                self.text_input.clear()
        else:
            QMessageBox.warning(self, "Warning",
                                "No image data found to save")

    def generate_qr(self):
        data = self.text_input.text().strip()
        if data:
            filename, _ = QFileDialog.getSaveFileName(
                self, "Save QR Code", os.getcwd(),
                "PNG Files (*.png)"
            )
            if filename:
                qr = qrcode.make(data)
                qr.save(filename)
                QMessageBox.information(self, "Success",
                                        "QR code generated successfully!")

    def hide_file(self):
        if not self.filename:
            QMessageBox.warning(self, "Warning", "Please select a cover image first!")
            return

        secret_path, _ = QFileDialog.getOpenFileName(
            self, "Select Secret Image", os.getcwd(),
            "All files (*)"
        )
        if not secret_path:
            return

        # Store the secret file extension for later use
        self.secret_file_extension = os.path.splitext(secret_path)[1]

        try:
            # Convert secret image to bytes
            with open(secret_path, "rb") as f:
                secret_data = f.read()

            if self.enable_encryption:
                self.password_dialog = PasswordDialog(self)
                self.password_dialog.setAttribute(Qt.WA_DeleteOnClose)
                self.password_dialog.submitted.connect(
                    lambda p: self.complete_file_hide(secret_data, p)
                )
                self.password_dialog.exec()
            else:
                self.complete_file_hide(secret_data)

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to process file: {str(e)}")

    def complete_file_hide(self, secret_data, password=None):
        try:
            if password:
                # Encrypt the raw bytes directly without decoding
                key = hashlib.sha256(password.encode()).digest()
                from Crypto.Cipher import AES
                cipher = AES.new(key, AES.MODE_EAX)
                nonce = cipher.nonce
                ciphertext, tag = cipher.encrypt_and_digest(secret_data)
                secret_data = nonce + ciphertext  # Use raw bytes, no base64 here

            # Estimate max data size that can be hidden in the cover image
            img = Image.open(self.filename)
            max_bytes = img.width * img.height * 3 // 8  # 3 color channels, 1 bit per channel

            # Base64 encode the secret data for hiding
            secret_b64 = base64.b64encode(secret_data).decode()

            if len(secret_b64) > max_bytes:
                QMessageBox.warning(self, "Warning",
                                    f"File too large to hide in the selected image.\n"
                                    f"Max data size: {max_bytes} bytes, your data size: {len(secret_b64)} bytes.\n"
                                    "Please select a larger cover image.")
                return

            self.secret = lsb.hide(self.filename, secret_b64)
            QTimer.singleShot(100, lambda: QMessageBox.information(
                self, "Success", "File hidden successfully!"))

        except Exception as e:
            QMessageBox.critical(self, "Error",
                                 f"Failed to hide file: {str(e)}")

    def reveal_file(self):
        if not self.filename:
            QMessageBox.warning(self, "Warning", "Please select an image first!")
            return

        try:
            secret_b64 = lsb.reveal(self.filename)
            if not secret_b64:
                QMessageBox.warning(self, "Warning", "No hidden file found!")
                return

            if self.enable_encryption:
                self.password_dialog = PasswordDialog(self)
                self.password_dialog.setAttribute(Qt.WA_DeleteOnClose)

                def on_password(p):
                    self.password_dialog.close()
                    self.complete_file_reveal(secret_b64, p)

                self.password_dialog.submitted.connect(on_password)
                self.password_dialog.exec()
            else:
                self.complete_file_reveal(secret_b64)

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to reveal file: {str(e)}")

    def complete_file_reveal(self, secret_b64, password=None):
        try:
            secret_data = base64.b64decode(secret_b64)

            if password:
                key = hashlib.sha256(password.encode()).digest()
                from Crypto.Cipher import AES
                nonce = secret_data[:16]
                ciphertext = secret_data[16:]
                cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
                secret_data = cipher.decrypt(ciphertext)
            self.revealed_image_data = secret_data

            # Display a generic file icon in the image preview to indicate a file was revealed
            icon_path = os.path.join(os.path.dirname(__file__), "file.jpg")
            if os.path.exists(icon_path):
                pixmap = QPixmap(icon_path).scaled(400, 400, Qt.KeepAspectRatio, Qt.SmoothTransformation)
                self.image_label.setPixmap(pixmap)
            else:
                self.image_label.clear()

            QMessageBox.information(self, "Success", "File revealed successfully! You can now save it using 'Save File' button.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to reveal file: {str(e)}\nThis may be due to an incorrect password.")
            self.revealed_image_data = None

    def show_help(self):
        help_dialog = HelpDialog(self)
        help_dialog.show()

    def generate_qr(self):
        data = self.text_input.text().strip()
        if data:
            filename, _ = QFileDialog.getSaveFileName(
                self, "Save QR Code", os.getcwd(),
                "PNG Files (*.png)"
            )
            if filename:
                qr = qrcode.make(data)
                qr.save(filename)
                QMessageBox.information(self, "Success",
                                        "QR code generated successfully!")
