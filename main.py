import base64
import sys

from Cryptodome.Cipher import PKCS1_OAEP, AES
from Cryptodome.Hash import SHA1, SHA224, SHA256, SHA384, SHA512, SHA3_512, \
    SHA3_256, SHA3_224, SHA3_384
from Cryptodome.Signature import PKCS1_v1_5
from PyQt5.QtCore import QSize, QPoint
from PyQt5.QtWidgets import QApplication, QWidget, QPushButton, QPlainTextEdit, \
    QLabel, QComboBox, QTextEdit, QMessageBox, QFileDialog, QLineEdit
from Cryptodome.PublicKey import RSA
from file_format import CryptoFormat


class MyWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.buttons = []
        self.ui_specfic = []
        self.hashing_algorithms = [
            SHA1, SHA224, SHA256, SHA384, SHA512, SHA3_224, SHA3_256, SHA3_384,
            SHA3_512
        ]
        self.hash_names = [
            'SHA1', 'SHA-224', 'SHA-256', 'SHA-384', 'SHA-512',
            'SHA3-224', 'SHA3-256', 'SHA3-384', 'SHA3-512'
        ]
        self.current_hash_alg = None
        self.current_hash_index = 0
        self.key = None
        self.private_key = 'private_key.pem'
        self.public_key = 'public_key.pem'
        self.input_file = 'dummy.txt'

        self.set_ui()

    def set_ui(self):
        btn = QPushButton('Create Signed Document', self)
        btn.resize(QSize(300, 50))
        btn.clicked.connect(self.create_signed_doc)
        btn.move(1280 / 6 - 150, 720 / 2 - 50)
        self.buttons.append(btn)

        btn = QPushButton('Create Envelope', self)
        btn.resize(QSize(300, 50))
        btn.clicked.connect(self.create_envelope)
        btn.move(1280 / 6 * 3 - 150, 720 / 2 - 50)
        self.buttons.append(btn)

        btn = QPushButton('Create Signed Envelope', self)
        btn.resize(QSize(300, 50))
        btn.clicked.connect(self.create_signed_envelope)
        btn.move(1280 / 6 * 5 - 150, 720 / 2 - 50)
        self.buttons.append(btn)

        btn = QPushButton('Generate RSA', self)
        btn.resize(QSize(300, 50))
        btn.move(1280 / 6 * 3 - 150, 650)
        btn.clicked.connect(self.generate_rsa)
        self.ui_specfic.append(btn)

        self.resize(1280, 720)
        self.setWindowTitle('Message Crypter')
        self.show()

    def create_signed_doc(self):
        self.mode_selected(0)
        self.buttons[0].setEnabled(False)

    def create_envelope(self):
        self.mode_selected(1)
        self.buttons[1].setEnabled(False)

    def create_signed_envelope(self):
        self.mode_selected(2)
        self.buttons[2].setEnabled(False)
        pass

    def mode_selected(self, mode_index):
        while len(self.ui_specfic) > 0:
            self.ui_specfic[0].deleteLater()
            self.ui_specfic.pop(0)

        self.select_hashing_algorithm(0)

        self.input_file = 'dummy.txt'
        self.private_key = 'private_key.pem'
        self.public_key = 'public_key.pem'

        label = QLabel(self)
        label.setText('Input File')
        label.setStyleSheet('color: #4f4f4f')
        label.move(50, 290)
        label.show()
        self.ui_specfic.append(label)

        current_file = QLineEdit(self)
        current_file.move(50, 320)
        current_file.resize(480, 50)
        current_file.setText(self.input_file)
        current_file.setDisabled(True)
        current_file.setStyleSheet('color: #000000')
        current_file.show()
        self.ui_specfic.append(current_file)

        btn = QPushButton('Load', self)
        btn.resize(QSize(100, 50))
        btn.move(100 + 450, 320)
        btn.clicked.connect(self.load_input_file)
        self.ui_specfic.append(btn)
        btn.show()

        self.add_specific(mode_index)

        for i in range(len(self.buttons)):
            btn = self.buttons[i]
            if i == mode_index:
                btn.setEnabled(False)
            else:
                btn.setEnabled(True)

            btn.move(btn.pos().x(), 30)

    def load_input_file(self):
        fileName = self.load_file_dialog()
        if fileName:
            self.input_file = fileName
            self.ui_specfic[1].setText(self.input_file)

    def add_specific(self, mode_index):
        if mode_index == 0:
            self.add_digital_signature_options()
        if mode_index == 1:
            self.add_envelope_options()

    @staticmethod
    def sign(message, priv_key, digest):
        signer = PKCS1_v1_5.new(priv_key)
        digest.update(message)

        return signer.sign(digest)

    def signed_doc_action(self):
        key_file = open(self.private_key)
        self.key = RSA.import_key(key_file.read())
        key_file.close()

        f = open(self.input_file, 'rb')
        digest = MyWindow.sign(f.read(), self.key, self.current_hash_alg)
        f.close()

        encrypted_digest = base64.b64encode(digest).decode('ascii')

        file = CryptoFormat()
        file.add_data('Description', 'Signed data from message box')
        file.add_data(
            'Method', [
                'RSA', self.hash_names[self.current_hash_index]
            ]
        )
        if '-' in self.hash_names[self.current_hash_index]:
            file.add_data(
                'Key length',
                self.hash_names[self.current_hash_index].split('-')[1]
            )
        elif self.current_hash_index != 0:
            file.add_data(
                'Key length',
                self.hash_names[self.current_hash_index][3:]
            )

        file.add_data('File', self.input_file)
        file.add_data('Signature', encrypted_digest)

        filename = self.save_file_dialog()
        if not filename:
            file.dict = {}
            QMessageBox.about(
                self,
                'Cancelled',
                'Cancelled digital signature'
            )
            return

        file.output_data(filename)

        QMessageBox.about(
            self,
            'Success',
            'Digitally signed message. Result is saved to {}.'.format(filename)
        )

    def save_file_dialog(self):
        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog
        fileName, _ = QFileDialog.getSaveFileName(self,
                                                  "QFileDialog.getSaveFileName()",
                                                  "",
                                                  "NOS (*.os2)",
                                                  options=options)
        if fileName:
            return fileName
        return None

    def load_file_dialog(self):
        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog
        fileName, _ = QFileDialog.getOpenFileName(
            self,
            "QFileDialog.getOpenFileName()",
            "",
            "All Files (*.*)",
            options=options
        )
        if fileName:
            return fileName
        return None

    def signed_envelope_action(self):
        msg = self.ui_specfic[1].toPlainText()

    def envelope_action(self):
        key_file = open(self.public_key)
        self.key = RSA.import_key(key_file.read())
        key_file.close()

        with open(self.input_file) as f:
            data = f.read()

        file = CryptoFormat()
        file.add_data('Description', 'Signed data from message box')

        spec_key = self.ui_specfic[8].text()
        needed_zeroes = 16 - len(spec_key) % 16
        spec_key = spec_key.zfill(len(spec_key) + needed_zeroes)
        session_key = spec_key.encode('ascii')
        cipher = PKCS1_OAEP.new(self.key)
        encrypted_key = cipher.encrypt(session_key)

        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(data.encode('utf-8'))

        file.add_data('Session Key', base64.b64encode(encrypted_key).decode('ascii'))
        file.add_data('AES Tag', base64.b64encode(tag).decode('ascii'))
        file.add_data('NONCE', base64.b64encode(cipher_aes.nonce).decode('ascii'))
        file.add_data('Encrypted content', base64.b64encode(ciphertext).decode('ascii'))
        file.add_data(
            'Method', [
                'RSA', 'AES'
            ]
        )

        file.add_data('Original File', self.input_file)

        filename = self.save_file_dialog()
        if not filename:
            file.dict = {}
            QMessageBox.about(
                self,
                'Cancelled',
                'Cancelled digital signature'
            )
            return

        file.output_data(filename)

        QMessageBox.about(
            self,
            'Success',
            'Created envelope. Result is saved to {}.'.format(
                filename)
        )

    def add_digital_signature_options(self):
        action_button = QPushButton('Create', self)
        action_button.resize(550, 50)
        action_button.move(690, 640)
        action_button.show()
        action_button.clicked.connect(self.signed_doc_action)
        self.ui_specfic.append(action_button)

        label = QLabel(self)
        label.setText('Select hashing algorithm:')
        label.setStyleSheet('color: #4f4f4f')
        label.move(690, 130)
        label.show()
        self.ui_specfic.append(label)

        combo = QComboBox(self)
        combo.addItems(self.hash_names)

        combo.move(690, 160)
        combo.resize(550, 40)
        combo.currentIndexChanged.connect(self.select_hashing_algorithm)

        self.ui_specfic.append(combo)
        combo.show()

        label = QLabel(self)
        label.setText('Private key:')
        label.setStyleSheet('color: #4f4f4f')
        label.move(690, 240)
        label.show()
        self.ui_specfic.append(label)

        current_file = QLineEdit(self)
        current_file.move(690, 260)
        current_file.resize(430, 50)
        current_file.setText(self.private_key)
        current_file.setDisabled(True)
        current_file.setStyleSheet('color: #000000')
        current_file.show()
        self.ui_specfic.append(current_file)

        btn = QPushButton('Load', self)
        btn.resize(QSize(100, 50))
        btn.move(690 + 450, 260)
        btn.clicked.connect(self.load_private_key)
        self.ui_specfic.append(btn)
        btn.show()

    def add_envelope_options(self):
        action_button = QPushButton('Create', self)
        action_button.resize(550, 50)
        action_button.move(690, 640)
        action_button.show()
        action_button.clicked.connect(self.envelope_action)
        self.ui_specfic.append(action_button)

        label = QLabel(self)
        label.setText('Public key:')
        label.setStyleSheet('color: #4f4f4f')
        label.move(690, 160)
        label.show()
        self.ui_specfic.append(label)

        current_file = QLineEdit(self)
        current_file.move(690, 190)
        current_file.resize(430, 50)
        current_file.setText(self.public_key)
        current_file.setDisabled(True)
        current_file.setStyleSheet('color: #000000')
        current_file.show()
        self.ui_specfic.append(current_file)

        btn = QPushButton('Load', self)
        btn.resize(QSize(100, 50))
        btn.move(690 + 450, 190)
        btn.clicked.connect(self.load_envelope_public_key)
        self.ui_specfic.append(btn)
        btn.show()

        label = QLabel(self)
        label.setText('Encryption key:')
        label.setStyleSheet('color: #4f4f4f')
        label.move(690, 260)
        label.show()
        self.ui_specfic.append(label)

        current_file = QLineEdit(self)
        current_file.move(690, 290)
        current_file.resize(550, 50)
        current_file.setText('EncrYptioN')
        current_file.show()
        self.ui_specfic.append(current_file)

    def load_envelope_public_key(self):
        fileName = self.load_file_dialog()

        if fileName:
            self.public_key = fileName
            self.ui_specfic[5].setText(self.public_key)

    def select_hashing_algorithm(self, i):
        self.current_hash_alg = self.hashing_algorithms[i].new()
        self.current_hash_index = i

    def generate_rsa(self):
        key = RSA.generate(2048)
        private_key = key.export_key()
        file_out = open("private_key.pem", "wb")
        file_out.write(private_key)
        file_out.close()

        public_key = key.publickey().export_key()
        file_out = open("public_key.pem", "wb")
        file_out.write(public_key)
        file_out.close()

    def load_private_key(self):
        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog
        fileName, _ = QFileDialog.getOpenFileName(
            self,
            "QFileDialog.getOpenFileName()",
            "",
            "Key Files (*.pem)",
            options=options
        )
        if fileName:
            self.private_key = fileName
            self.ui_specfic[7].setText(self.private_key)
            self.ui_specfic[7].show()


if __name__ == '__main__':
    app = QApplication(sys.argv)

    w = MyWindow()

    sys.exit(app.exec_())
