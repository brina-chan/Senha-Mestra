# -*- coding: utf-8 -*-

import sys
import os
import sqlite3
import json
import base64
import string
import secrets
import hashlib
import webbrowser
from io import BytesIO

if sys.platform == "win32":
    import ctypes

from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QLineEdit, QDialog, QMessageBox, QTableWidget, QTableWidgetItem,
    QAbstractItemView, QHeaderView, QDialogButtonBox, QSlider, QCheckBox,
    QFormLayout, QFrame, QGroupBox
)
from PyQt6.QtGui import QPixmap, QFont, QIcon, QGuiApplication, QColor, QPalette
from PyQt6.QtCore import Qt, QTimer, QEvent

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

import pyotp
import qrcode

DB_FILE = ".cofre_seguro.db"
APP_NAME = "Senha Mestra"
APP_VERSION = "1.0.0"
ICON_FILE = "icon.ico"
INACTIVITY_TIMEOUT_MS = 5 * 60 * 1000
GITHUB_URL = "https://github.com/brina-chan/Senha-Mestra"

COLOR_BACKGROUND = "#0A192F"
COLOR_ACCENT = "#00C9A7"
COLOR_TEXT = "#CBD5E1"
COLOR_WHITE = "#FFFFFF"
COLOR_HIGHLIGHT = "#00FF88"

def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

def hide_file_windows(filename):
    if sys.platform == "win32":
        try:
            ret = ctypes.windll.kernel32.SetFileAttributesW(filename, 0x02)
            if ret:
                print(f"Arquivo '{filename}' ocultado com sucesso.")
            else:
                print(f"Erro ao ocultar o arquivo '{filename}'.")
        except Exception as e:
            print(f"Exceção ao tentar ocultar o arquivo: {e}")

class CryptoManager:
    def __init__(self, master_password: str, salt: bytes):
        self._master_password = master_password.encode('utf-8')
        self._salt = salt
        self._key = self._derive_key()

    def _derive_key(self) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self._salt,
            iterations=480000,
        )
        return kdf.derive(self._master_password)

    def encrypt(self, data: str) -> bytes:
        aesgcm = AESGCM(self._key)
        nonce = os.urandom(12)
        encrypted_data = aesgcm.encrypt(nonce, data.encode('utf-8'), None)
        return base64.b64encode(nonce + encrypted_data)

    def decrypt(self, encrypted_data_b64: bytes) -> str:
        encrypted_data = base64.b64decode(encrypted_data_b64)
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        aesgcm = AESGCM(self._key)
        decrypted_data = aesgcm.decrypt(nonce, ciphertext, None)
        return decrypted_data.decode('utf-8')

class DatabaseManager:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._conn = sqlite3.connect(self.db_path)
        self._cursor = self._conn.cursor()

    def create_tables(self):
        self._cursor.execute('''
            CREATE TABLE IF NOT EXISTS config (
                key TEXT PRIMARY KEY,
                value BLOB NOT NULL
            )
        ''')
        self._cursor.execute('''
            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                data BLOB NOT NULL
            )
        ''')
        self._conn.commit()

    def save_config(self, key: str, value: bytes):
        self._cursor.execute("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", (key, value))
        self._conn.commit()

    def get_config(self, key: str) -> bytes | None:
        self._cursor.execute("SELECT value FROM config WHERE key = ?", (key,))
        result = self._cursor.fetchone()
        return result[0] if result else None

    def add_entry(self, name: str, encrypted_data: bytes):
        self._cursor.execute("INSERT INTO passwords (name, data) VALUES (?, ?)", (name, encrypted_data))
        self._conn.commit()

    def update_entry(self, entry_id: int, name: str, encrypted_data: bytes):
        self._cursor.execute("UPDATE passwords SET name = ?, data = ? WHERE id = ?", (name, encrypted_data, entry_id))
        self._conn.commit()
    
    def get_all_entries(self) -> list:
        self._cursor.execute("SELECT id, name, data FROM passwords ORDER BY name")
        return self._cursor.fetchall()

    def delete_entry(self, entry_id: int):
        self._cursor.execute("DELETE FROM passwords WHERE id = ?", (entry_id,))
        self._conn.commit()

    def close(self):
        self._conn.close()

class BaseDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle(APP_NAME)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowType.WindowContextHelpButtonHint)

class AboutDialog(BaseDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Sobre o {APP_NAME}")
        
        layout = QVBoxLayout(self)
        layout.setSpacing(15)

        title_label = QLabel(APP_NAME)
        title_label.setFont(QFont("JetBrains Mono", 16, QFont.Weight.Bold))
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        version_label = QLabel(f"Versão {APP_VERSION}")
        version_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        security_title = QLabel("🔒 Privacidade com Zero Acesso a Dados")
        security_title.setFont(QFont("JetBrains Mono", 12, QFont.Weight.Bold))
        
        security_text = QLabel(
            "A Senha Mestra é a única chave capaz de descriptografar as senhas salvas, e ela nunca sai do seu computador."
            "\n⚠️Atenção: caso você esqueça sua Senha Mestra, não será possível recuperá-la."
        )
        security_text.setWordWrap(True)

        inactivity_text = QLabel(
            f"ℹ️ Para sua segurança, o aplicativo se encerra automaticamente após {int(INACTIVITY_TIMEOUT_MS / 60000)} minutos de inatividade."
        )
        inactivity_text.setWordWrap(True)

        update_button = QPushButton("Verificar Atualizações no GitHub")
        update_button.clicked.connect(lambda: webbrowser.open(GITHUB_URL))

        developed_by = QLabel("Desenvolvido por: Brina-chan")
        developed_by.setAlignment(Qt.AlignmentFlag.AlignCenter)

        layout.addWidget(title_label)
        layout.addWidget(version_label)
        layout.addWidget(QFrame(frameShape=QFrame.Shape.HLine))
        layout.addWidget(security_title)
        layout.addWidget(security_text)
        layout.addWidget(inactivity_text)
        layout.addWidget(update_button)
        layout.addWidget(QFrame(frameShape=QFrame.Shape.HLine))
        layout.addWidget(developed_by)
        
        self.setFixedSize(420, 380)

class PasswordGeneratorDialog(BaseDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Gerador de Senhas")
        
        layout = QVBoxLayout(self)
        form_layout = QFormLayout()

        self.length_slider = QSlider(Qt.Orientation.Horizontal)
        self.length_slider.setMinimum(8)
        self.length_slider.setMaximum(64)
        self.length_slider.setValue(16)
        self.length_slider.setTickInterval(4)
        self.length_slider.setTickPosition(QSlider.TickPosition.TicksBelow)
        self.length_label = QLabel(f"{self.length_slider.value()}")
        self.length_slider.valueChanged.connect(self.update_and_regenerate)
        
        slider_layout = QHBoxLayout()
        slider_layout.addWidget(self.length_slider)
        slider_layout.addWidget(self.length_label)

        checkbox_group = QGroupBox("Incluir Caracteres")
        checkbox_layout = QVBoxLayout()
        self.chk_upper = QCheckBox("Letras Maiúsculas (A-Z)")
        self.chk_upper.setChecked(True)
        self.chk_upper.stateChanged.connect(self.update_and_regenerate)
        self.chk_lower = QCheckBox("Letras Minúsculas (a-z)")
        self.chk_lower.setChecked(True)
        self.chk_lower.stateChanged.connect(self.update_and_regenerate)
        self.chk_digits = QCheckBox("Números (0-9)")
        self.chk_digits.setChecked(True)
        self.chk_digits.stateChanged.connect(self.update_and_regenerate)
        self.chk_symbols = QCheckBox("Símbolos (!@#$...%)")
        self.chk_symbols.setChecked(True)
        self.chk_symbols.stateChanged.connect(self.update_and_regenerate)
        checkbox_layout.addWidget(self.chk_upper)
        checkbox_layout.addWidget(self.chk_lower)
        checkbox_layout.addWidget(self.chk_digits)
        checkbox_layout.addWidget(self.chk_symbols)
        checkbox_group.setLayout(checkbox_layout)

        form_layout.addRow("Comprimento:", slider_layout)
        layout.addLayout(form_layout)
        layout.addWidget(checkbox_group)
        
        result_layout = QHBoxLayout()
        self.generated_password_field = QLineEdit()
        self.generated_password_field.setReadOnly(True)
        self.generated_password_field.setFont(QFont("JetBrains Mono", 10))
        self.strength_label = QLabel("Força: Média")
        result_layout.addWidget(self.generated_password_field)
        result_layout.addWidget(self.strength_label)
        layout.addLayout(result_layout)
        
        btn_layout = QHBoxLayout()
        generate_btn = QPushButton("Gerar Nova Senha")
        generate_btn.clicked.connect(self.generate_password)
        copy_btn = QPushButton("Copiar")
        copy_btn.clicked.connect(self.copy_to_clipboard)
        
        btn_layout.addWidget(generate_btn)
        btn_layout.addWidget(copy_btn)
        layout.addLayout(btn_layout)
        
        self.generate_password()

    def update_and_regenerate(self):
        self.length_label.setText(f"{self.length_slider.value()}")
        self.generate_password()

    def evaluate_password_strength(self, password):
        score = 0
        length = len(password)
        
        score += length * 2

        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_symbol = not password.isalnum()

        variety_count = sum([has_lower, has_upper, has_digit, has_symbol])
        score += variety_count * 10
        
        if length < 12 or variety_count < 2:
            return ("Fraca", "#FF4136")
        if length < 16 or variety_count < 4:
            return ("Média", "#FF851B")
        if score < 75:
            return ("Forte", "#FFDC00")
        
        return ("Muito Forte", COLOR_HIGHLIGHT)

    def generate_password(self):
        length = self.length_slider.value()
        char_sets = []
        if self.chk_upper.isChecked():
            char_sets.append(string.ascii_uppercase)
        if self.chk_lower.isChecked():
            char_sets.append(string.ascii_lowercase)
        if self.chk_digits.isChecked():
            char_sets.append(string.digits)
        if self.chk_symbols.isChecked():
            char_sets.append("!@#$%^&*()-_=+[]{}|;:,.<>?")

        if not char_sets:
            self.generated_password_field.setText("")
            self.strength_label.setText("Força: N/A")
            self.strength_label.setStyleSheet(f"color: {COLOR_TEXT};")
            return

        password_chars = [secrets.choice(cs) for cs in char_sets]
        all_chars = "".join(char_sets)
        password_chars += [secrets.choice(all_chars) for _ in range(length - len(password_chars))]
        
        secrets.SystemRandom().shuffle(password_chars)
        password = "".join(password_chars)
        self.generated_password_field.setText(password)
        
        strength_text, strength_color = self.evaluate_password_strength(password)
        self.strength_label.setText(f"Força: {strength_text}")
        self.strength_label.setStyleSheet(f"color: {strength_color}; font-weight: bold;")
    
    def show_temp_message(self, message, duration_ms):
        msg_box = QMessageBox(self)
        msg_box.setText(message)
        msg_box.setStandardButtons(QMessageBox.StandardButton.Ok)
        msg_box.setModal(False)
        msg_box.show()
        QTimer.singleShot(duration_ms, msg_box.close)

    def copy_to_clipboard(self):
        QGuiApplication.clipboard().setText(self.generated_password_field.text())
        self.show_temp_message("Senha copiada para a área de transferência!", 2000)

class Setup2FADialog(BaseDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Configurar 2FA")
        self.secret = pyotp.random_base32()
        
        layout = QVBoxLayout(self)
        
        instructions = QLabel(
            "1. Instale o Google Authenticator, Authy ou outro app similar no seu celular.\n"
            "2. Escaneie o QR Code abaixo.\n"
            "3. Digite o código de 6 dígitos gerado para confirmar."
        )
        instructions.setWordWrap(True)
        layout.addWidget(instructions)
        
        self.qr_label = QLabel()
        self.generate_qr_code()
        layout.addWidget(self.qr_label, alignment=Qt.AlignmentFlag.AlignCenter)
        
        layout.addWidget(QLabel("Código de Verificação (6 dígitos):"))
        self.code_field = QLineEdit()
        self.code_field.setMaxLength(6)
        layout.addWidget(self.code_field)

        self.buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        self.buttons.accepted.connect(self.verify_and_accept)
        self.buttons.rejected.connect(self.reject)
        layout.addWidget(self.buttons)

    def generate_qr_code(self):
        totp = pyotp.TOTP(self.secret)
        uri = totp.provisioning_uri(
            name="Cofre Pessoal", 
            issuer_name="Senha Mestra - GitHub - Brina-chan"
        )
        
        qr = qrcode.QRCode(version=1, box_size=10, border=4)
        qr.add_data(uri)
        qr.make(fit=True)
        img = qr.make_image(fill_color=COLOR_BACKGROUND, back_color=COLOR_WHITE)
        
        buffered = BytesIO()
        img.save(buffered, "PNG")
        
        pixmap = QPixmap()
        pixmap.loadFromData(buffered.getvalue())
        self.qr_label.setPixmap(pixmap)

    def verify_and_accept(self):
        totp = pyotp.TOTP(self.secret)
        if totp.verify(self.code_field.text()):
            self.accept()
        else:
            QMessageBox.warning(self, "Erro", "Código 2FA inválido. Tente novamente.")

class AddEditDialog(BaseDialog):
    leak_warning_shown = False

    def __init__(self, crypto_manager: CryptoManager, entry_data=None, parent=None):
        super().__init__(parent)
        self.crypto_manager = crypto_manager
        self.entry_data = entry_data
        
        title = "Editar Entrada" if entry_data else "Adicionar Nova Entrada"
        self.setWindowTitle(title)
        
        layout = QVBoxLayout(self)
        form_layout = QFormLayout()

        self.name_field = QLineEdit()
        self.login_field = QLineEdit()
        self.password_field = QLineEdit()
        self.password_field.setEchoMode(QLineEdit.EchoMode.Password)
        self.notes_field = QLineEdit()

        form_layout.addRow("Nome (Ex: Netflix, Gmail):", self.name_field)
        form_layout.addRow("Login/Email:", self.login_field)

        password_layout = QHBoxLayout()
        password_layout.setContentsMargins(0,0,0,0)
        password_layout.addWidget(self.password_field)
        self.verify_btn = QPushButton("Verificar Vazamentos")
        self.verify_btn.clicked.connect(self.check_password_leak)
        password_layout.addWidget(self.verify_btn)
        form_layout.addRow("Senha:", password_layout)
        
        form_layout.addRow("Notas:", self.notes_field)
        layout.addLayout(form_layout)
        
        btn_show_pass = QCheckBox("Mostrar senha")
        btn_show_pass.toggled.connect(self.toggle_password_visibility)
        layout.addWidget(btn_show_pass)
        
        btn_generate = QPushButton("Abrir Gerador de Senhas")
        btn_generate.clicked.connect(self.open_generator)
        layout.addWidget(btn_generate)

        self.buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        layout.addWidget(self.buttons)
        
        if self.entry_data:
            self.load_entry_data()
    
    def check_password_leak(self):
        if not AddEditDialog.leak_warning_shown:
            msg_box = QMessageBox(self)
            msg_box.setWindowTitle("Como a Verificação Funciona")
            msg_box.setIcon(QMessageBox.Icon.Information)
            msg_box.setTextFormat(Qt.TextFormat.RichText)
            msg_box.setText("<b>Sua privacidade é prioridade!</b>")
            msg_box.setInformativeText(
                "Para garantir sua segurança, veja como funciona a verificação:<br><br>"
                "1. Sua senha é convertida em um código anônimo (hash) <b>diretamente no seu computador.</b><br>"
                "2. Apenas um pequeno trecho desse código é enviado para verificação, <b>nunca a senha completa.</b><br><br>"
                "Assim, sua privacidade permanece totalmente protegida. Deseja continuar?"
            )
            msg_box.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            msg_box.button(QMessageBox.StandardButton.Yes).setText("Entendi, continuar")
            msg_box.button(QMessageBox.StandardButton.No).setText("Cancelar")
            
            reply = msg_box.exec()
            if reply == QMessageBox.StandardButton.No:
                return
            
            AddEditDialog.leak_warning_shown = True

        password = self.password_field.text()
        if not password:
            QMessageBox.information(self, "Senha Vazia", "Digite uma senha para verificar.")
            return

        self.verify_btn.setText("Verificando...")
        self.verify_btn.setEnabled(False)
        QApplication.processEvents()

        try:
            sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
            prefix, suffix = sha1_hash[:5], sha1_hash[5:]
            
            api_url = f"https://api.pwnedpasswords.com/range/{prefix}"
            response = requests.get(api_url, timeout=5)

            if response.status_code == 200:
                hashes = (line.split(':') for line in response.text.splitlines())
                count = next((int(c) for h, c in hashes if h == suffix), 0)

                if count > 0:
                    QMessageBox.warning(self, "Senha Comprometida!", 
                                        f"<b>Atenção!</b> Esta senha já apareceu <b>{count:,}</b> vezes em vazamentos de dados conhecidos.<br><br>"
                                        "É <b>altamente recomendável</b> que você não a utilize.".replace(',', '.'))
                else:
                    QMessageBox.information(self, "Senha Segura!", 
                                            "<b>Ótima notícia!</b> Esta senha não foi encontrada em nenhum vazamento de dados conhecido.")
            else:
                QMessageBox.critical(self, "Erro de API", f"Não foi possível verificar a senha. O serviço retornou o status: {response.status_code}")

        except requests.exceptions.RequestException as e:
            QMessageBox.critical(self, "Erro de Conexão", f"Não foi possível conectar ao serviço de verificação.<br><br>Verifique sua conexão com a internet.<br>Erro: {e}")
        finally:
            self.verify_btn.setText("Verificar Vazamentos")
            self.verify_btn.setEnabled(True)

    def load_entry_data(self):
        decrypted_json = self.crypto_manager.decrypt(self.entry_data['data'])
        data = json.loads(decrypted_json)
        self.name_field.setText(self.entry_data['name'])
        self.login_field.setText(data.get('login', ''))
        self.password_field.setText(data.get('password', ''))
        self.notes_field.setText(data.get('notes', ''))

    def get_data(self) -> tuple[str, bytes] | None:
        name = self.name_field.text().strip()
        if not name:
            QMessageBox.warning(self, "Erro", "O campo 'Nome' é obrigatório.")
            return None
            
        data = {
            "login": self.login_field.text(),
            "password": self.password_field.text(),
            "notes": self.notes_field.text()
        }
        json_data = json.dumps(data)
        encrypted_data = self.crypto_manager.encrypt(json_data)
        return name, encrypted_data

    def toggle_password_visibility(self, checked):
        if checked:
            self.password_field.setEchoMode(QLineEdit.EchoMode.Normal)
        else:
            self.password_field.setEchoMode(QLineEdit.EchoMode.Password)

    def open_generator(self):
        dialog = PasswordGeneratorDialog(self)
        dialog.exec()

class MainWindow(QWidget):
    def __init__(self, crypto_manager: CryptoManager, db_manager: DatabaseManager):
        super().__init__()
        self.crypto_manager = crypto_manager
        self.db_manager = db_manager
        self.setWindowTitle(APP_NAME)
        self.setGeometry(200, 200, 800, 500)
        
        self.inactivity_timer = QTimer(self)
        self.inactivity_timer.timeout.connect(self.lock_due_to_inactivity)
        QApplication.instance().installEventFilter(self)
        self.reset_inactivity_timer()

        layout = QVBoxLayout(self)
        
        toolbar_layout = QHBoxLayout()
        self.search_field = QLineEdit()
        self.search_field.setPlaceholderText("🔎 Buscar...")
        self.search_field.textChanged.connect(self.filter_table)
        
        add_btn = QPushButton("➕ Adicionar")
        add_btn.clicked.connect(self.add_entry)
        edit_btn = QPushButton("✏️ Editar")
        edit_btn.clicked.connect(self.edit_entry)
        delete_btn = QPushButton("❌ Excluir")
        delete_btn.clicked.connect(self.delete_entry)
        gen_btn = QPushButton("⚙️ Gerador")
        gen_btn.clicked.connect(lambda: PasswordGeneratorDialog(self).exec())
        about_btn = QPushButton("ℹ️ Sobre")
        about_btn.clicked.connect(self.show_about_dialog)

        toolbar_layout.addWidget(self.search_field)
        toolbar_layout.addWidget(add_btn)
        toolbar_layout.addWidget(edit_btn)
        toolbar_layout.addWidget(delete_btn)
        toolbar_layout.addWidget(gen_btn)
        toolbar_layout.addWidget(about_btn)
        layout.addLayout(toolbar_layout)

        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["Nome", "Login/Email", "Senha", "Notas"])
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.cellDoubleClicked.connect(self.copy_cell_content)
        
        layout.addWidget(self.table)
        
        self.load_entries()
        
    def show_about_dialog(self):
        dialog = AboutDialog(self)
        dialog.exec()

    def eventFilter(self, obj, event: QEvent) -> bool:
        activity_events = [
            QEvent.Type.KeyPress,
            QEvent.Type.MouseButtonPress,
        ]
        if event.type() in activity_events:
            self.reset_inactivity_timer()
        return super().eventFilter(obj, event)

    def reset_inactivity_timer(self):
        self.inactivity_timer.start(INACTIVITY_TIMEOUT_MS)

    def lock_due_to_inactivity(self):
        self.inactivity_timer.stop()
        QMessageBox.warning(None, "Sessão Expirada", f"A aplicação foi encerrada por inatividade de {int(INACTIVITY_TIMEOUT_MS / 60000)} minutos para sua segurança.")
        QApplication.instance().quit()

    def load_entries(self):
        self.table.setRowCount(0)
        self.all_data = []
        
        raw_entries = self.db_manager.get_all_entries()
        for entry_id, name, encrypted_data in raw_entries:
            try:
                decrypted_json = self.crypto_manager.decrypt(encrypted_data)
                data = json.loads(decrypted_json)
                self.all_data.append({
                    'id': entry_id, 'name': name, 'data': encrypted_data,
                    'decrypted': data
                })
            except Exception as e:
                print(f"Erro ao descriptografar entrada ID {entry_id}: {e}")
                row_position = self.table.rowCount()
                self.table.insertRow(row_position)
                self.table.setItem(row_position, 0, QTableWidgetItem(f"Erro na entrada: {name}"))

        self.populate_table(self.all_data)

    def populate_table(self, data_to_show):
        self.table.setRowCount(0)
        for entry in data_to_show:
            decrypted = entry['decrypted']
            row_position = self.table.rowCount()
            self.table.insertRow(row_position)
            
            id_item = QTableWidgetItem(entry['name'])
            id_item.setData(Qt.ItemDataRole.UserRole, entry['id'])
            self.table.setItem(row_position, 0, id_item)

            self.table.setItem(row_position, 1, QTableWidgetItem(decrypted.get('login', '')))
            self.table.setItem(row_position, 2, QTableWidgetItem("••••••••"))
            self.table.setItem(row_position, 3, QTableWidgetItem(decrypted.get('notes', '')))

    def filter_table(self):
        filter_text = self.search_field.text().lower()
        if not filter_text:
            self.populate_table(self.all_data)
            return

        filtered_data = [
            entry for entry in self.all_data
            if filter_text in entry['name'].lower()
            or filter_text in entry['decrypted'].get('login', '').lower()
            or filter_text in entry['decrypted'].get('notes', '').lower()
        ]
        self.populate_table(filtered_data)

    def add_entry(self):
        dialog = AddEditDialog(self.crypto_manager, parent=self)
        if dialog.exec():
            data = dialog.get_data()
            if data:
                name, encrypted_data = data
                self.db_manager.add_entry(name, encrypted_data)
                self.load_entries()

    def edit_entry(self):
        selected_row = self.table.currentRow()
        if selected_row < 0:
            QMessageBox.information(self, "Aviso", "Selecione uma entrada para editar.")
            return

        entry_id_item = self.table.item(selected_row, 0)
        entry_id = entry_id_item.data(Qt.ItemDataRole.UserRole)
        
        entry_data = next((item for item in self.all_data if item['id'] == entry_id), None)
        
        if entry_data:
            dialog = AddEditDialog(self.crypto_manager, entry_data, self)
            if dialog.exec():
                new_data = dialog.get_data()
                if new_data:
                    name, encrypted_data = new_data
                    self.db_manager.update_entry(entry_id, name, encrypted_data)
                    self.load_entries()

    def delete_entry(self):
        selected_row = self.table.currentRow()
        if selected_row < 0:
            QMessageBox.information(self, "Aviso", "Selecione uma entrada para excluir.")
            return

        reply = QMessageBox.question(self, "Confirmar Exclusão",
                                     "Tem certeza que deseja excluir esta entrada? Esta ação não pode ser desfeita.",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)

        if reply == QMessageBox.StandardButton.Yes:
            entry_id_item = self.table.item(selected_row, 0)
            entry_id = entry_id_item.data(Qt.ItemDataRole.UserRole)
            self.db_manager.delete_entry(entry_id)
            self.load_entries()

    def copy_cell_content(self, row, column):
        item = self.table.item(row, column)
        if not item: return

        if column == 2:
            entry_id_item = self.table.item(row, 0)
            entry_id = entry_id_item.data(Qt.ItemDataRole.UserRole)
            entry_data = next((item for item in self.all_data if item['id'] == entry_id), None)
            if entry_data:
                password = entry_data['decrypted']['password']
                QGuiApplication.clipboard().setText(password)
                self.show_temp_message("Senha copiada!", 2000)
                QTimer.singleShot(30000, lambda: self.clear_clipboard_if_unchanged(password))
        else:
            QGuiApplication.clipboard().setText(item.text())
            self.show_temp_message(f"'{item.text()}' copiado!", 2000)

    def show_temp_message(self, message, duration_ms):
        msg_box = QMessageBox(self)
        msg_box.setText(message)
        msg_box.setStandardButtons(QMessageBox.StandardButton.Ok)
        msg_box.setModal(False)
        msg_box.show()
        QTimer.singleShot(duration_ms, msg_box.close)

    def clear_clipboard_if_unchanged(self, old_text):
        if QGuiApplication.clipboard().text() == old_text:
            QGuiApplication.clipboard().clear()
            print("Área de transferência limpa por segurança.")


class LoginWindow(BaseDialog):
    def __init__(self, db_manager: DatabaseManager, parent=None):
        super().__init__(parent)
        self.db_manager = db_manager
        self.setWindowTitle("Destravar Cofre")
        
        self.crypto_manager = None
        self.has_2fa = self.db_manager.get_config("2fa_secret") is not None
        
        layout = QVBoxLayout(self)
        form_layout = QFormLayout()
        
        self.password_field = QLineEdit()
        self.password_field.setEchoMode(QLineEdit.EchoMode.Password)
        form_layout.addRow("Senha Mestra:", self.password_field)

        if self.has_2fa:
            self.two_fa_field = QLineEdit()
            self.two_fa_field.setPlaceholderText("Código de 6 dígitos")
            self.two_fa_field.setMaxLength(6)
            form_layout.addRow("Código 2FA:", self.two_fa_field)
        
        layout.addLayout(form_layout)

        self.buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        self.buttons.accepted.connect(self.try_login)
        self.buttons.rejected.connect(self.reject)
        layout.addWidget(self.buttons)

    def try_login(self):
        master_password = self.password_field.text()
        salt = self.db_manager.get_config("master_salt")
        verifier_data = self.db_manager.get_config("master_verifier")

        if not master_password or not salt or not verifier_data:
            QMessageBox.critical(self, "Erro", "Cofre inválido ou corrompido.")
            return

        try:
            temp_crypto = CryptoManager(master_password, salt)
            temp_crypto.decrypt(verifier_data)
            
            if self.has_2fa:
                secret_encrypted = self.db_manager.get_config("2fa_secret")
                secret = temp_crypto.decrypt(secret_encrypted)
                totp = pyotp.TOTP(secret)
                if not totp.verify(self.two_fa_field.text()):
                    QMessageBox.warning(self, "Falha no Login", "Código 2FA inválido.")
                    return

            self.crypto_manager = temp_crypto
            self.accept()

        except InvalidTag:
            QMessageBox.warning(self, "Falha no Login", "Senha Mestra incorreta.")
        except Exception as e:
            QMessageBox.critical(self, "Erro Inesperado", f"Ocorreu um erro: {e}")


class SetupWindow(BaseDialog):
    def __init__(self, db_manager: DatabaseManager, parent=None):
        super().__init__(parent)
        self.db_manager = db_manager
        self.setWindowTitle("Configurar Senha Mestra")
        self.crypto_manager = None
        
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Bem-vindo(a)! Primeiro, vamos criar sua Senha Mestra."))
        
        warning_label = QLabel("⚠️ Guarde bem sua Senha Mestra! Ela é a única forma de acessar seus dados e <b>não pode ser recuperada</b> se for perdida.")
        warning_label.setWordWrap(True)
        warning_label.setStyleSheet("color: #FFDC00;")
        layout.addWidget(warning_label)
        
        form_layout = QFormLayout()
        self.password_field = QLineEdit()
        self.password_field.setEchoMode(QLineEdit.EchoMode.Password)
        self.confirm_password_field = QLineEdit()
        self.confirm_password_field.setEchoMode(QLineEdit.EchoMode.Password)
        
        form_layout.addRow("Crie sua Senha Mestra:", self.password_field)
        form_layout.addRow("Confirme a Senha Mestra:", self.confirm_password_field)
        layout.addLayout(form_layout)
        
        self.chk_2fa = QCheckBox("Proteger com Autenticação de Dois Fatores (Recomendado)")
        self.chk_2fa.setChecked(True)
        layout.addWidget(self.chk_2fa)

        self.buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        self.buttons.accepted.connect(self.create_vault)
        self.buttons.rejected.connect(self.reject)
        layout.addWidget(self.buttons)

    def create_vault(self):
        password = self.password_field.text()
        confirm_password = self.confirm_password_field.text()
        
        if len(password) < 12:
            QMessageBox.warning(self, "Senha Fraca", "Sua senha mestra deve ter pelo menos 12 caracteres.")
            return

        if password != confirm_password:
            QMessageBox.warning(self, "Erro", "As senhas não coincidem.")
            return

        salt = os.urandom(16)
        self.db_manager.save_config("master_salt", salt)
        
        self.crypto_manager = CryptoManager(password, salt)
        
        verifier = self.crypto_manager.encrypt("senha-correta")
        self.db_manager.save_config("master_verifier", verifier)
        
        if self.chk_2fa.isChecked():
            dialog_2fa = Setup2FADialog(self)
            if dialog_2fa.exec():
                secret_2fa = dialog_2fa.secret
                encrypted_secret = self.crypto_manager.encrypt(secret_2fa)
                self.db_manager.save_config("2fa_secret", encrypted_secret)
            else:
                self.reject()
                return

        self.accept()

def set_new_theme(app):
    app.setFont(QFont("JetBrains Mono", 10))
    
    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window, QColor(COLOR_BACKGROUND))
    palette.setColor(QPalette.ColorRole.WindowText, QColor(COLOR_TEXT))
    palette.setColor(QPalette.ColorRole.Base, QColor("#1D2B45"))
    palette.setColor(QPalette.ColorRole.AlternateBase, QColor(COLOR_BACKGROUND))
    palette.setColor(QPalette.ColorRole.ToolTipBase, QColor(COLOR_WHITE))
    palette.setColor(QPalette.ColorRole.ToolTipText, QColor(COLOR_BACKGROUND))
    palette.setColor(QPalette.ColorRole.Text, QColor(COLOR_TEXT))
    palette.setColor(QPalette.ColorRole.Button, QColor(COLOR_ACCENT))
    palette.setColor(QPalette.ColorRole.ButtonText, QColor(COLOR_BACKGROUND))
    palette.setColor(QPalette.ColorRole.BrightText, QColor(Qt.GlobalColor.red))
    palette.setColor(QPalette.ColorRole.Link, QColor(COLOR_ACCENT))
    palette.setColor(QPalette.ColorRole.Highlight, QColor(COLOR_ACCENT))
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor(COLOR_BACKGROUND))
    app.setPalette(palette)

    app.setStyleSheet(f"""
        QWidget {{
            color: {COLOR_TEXT};
            background-color: {COLOR_BACKGROUND};
        }}
        QTableWidget {{
            background-color: #1D2B45;
            gridline-color: {COLOR_BACKGROUND};
            border-radius: 5px;
        }}
        QHeaderView::section {{
            background-color: {COLOR_BACKGROUND};
            color: {COLOR_ACCENT};
            padding: 4px;
            border: 1px solid {COLOR_ACCENT};
        }}
        QLineEdit {{
            border: 1px solid #2A3A5B;
            border-radius: 5px;
            padding: 5px;
            background-color: #1D2B45;
        }}
        QPushButton {{
            background-color: transparent;
            color: {COLOR_ACCENT};
            border: 1px solid {COLOR_ACCENT};
            padding: 8px;
            border-radius: 5px;
        }}
        QPushButton:hover {{
            background-color: {COLOR_ACCENT};
            color: {COLOR_BACKGROUND};
        }}
        QPushButton:pressed {{
            background-color: {COLOR_HIGHLIGHT};
        }}
        QCheckBox {{
            spacing: 5px;
        }}
        QCheckBox:checked {{
            color: {COLOR_HIGHLIGHT};
            font-weight: bold;
        }}
        QSlider::groove:horizontal {{
            border: 1px solid #bbb;
            background: {COLOR_TEXT};
            height: 8px;
            border-radius: 4px;
        }}
        QSlider::handle:horizontal {{
            background: {COLOR_ACCENT};
            border: 1px solid {COLOR_ACCENT};
            width: 18px;
            margin: -2px 0;
            border-radius: 9px;
        }}
        QGroupBox {{
            color: {COLOR_ACCENT};
            border: 1px solid #2A3A5B;
            border-radius: 5px;
            margin-top: 10px;
        }}
        QGroupBox::title {{
            subcontrol-origin: margin;
            subcontrol-position: top center;
            padding: 0 3px;
        }}
    """)

def main():
    app = QApplication(sys.argv)
    
    icon_path = resource_path(ICON_FILE)
    if os.path.exists(icon_path):
        app.setWindowIcon(QIcon(icon_path))
    
    if sys.platform == "win32":
        myappid = 'brina-chan.senhamestra.v1-6-3'
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)
    
    if not REQUESTS_AVAILABLE:
        msg_box = QMessageBox()
        msg_box.setIcon(QMessageBox.Icon.Critical)
        msg_box.setText("Erro de Dependência Não Encontrada")
        msg_box.setInformativeText(
            "A biblioteca 'requests' é necessária para a verificação de vazamentos, mas não foi encontrada.\n\n"
            "Por favor, instale-a abrindo o terminal (Prompt de Comando ou PowerShell) e executando o comando:\n\n"
            "<b>pip install requests</b>"
        )
        msg_box.setWindowTitle("Erro de Instalação")
        msg_box.setStandardButtons(QMessageBox.StandardButton.Ok)
        msg_box.exec()
        sys.exit(1)

    set_new_theme(app)
    
    vault_exists = os.path.exists(DB_FILE)
    db_manager = DatabaseManager(DB_FILE)
    
    if not vault_exists:
        db_manager.create_tables()
        setup_dialog = SetupWindow(db_manager)
        if setup_dialog.exec():
            crypto_manager = setup_dialog.crypto_manager
            hide_file_windows(DB_FILE)
        else:
            db_manager.close()
            if os.path.exists(DB_FILE):
                os.remove(DB_FILE)
            sys.exit()
    else:
        login_dialog = LoginWindow(db_manager)
        if login_dialog.exec():
            crypto_manager = login_dialog.crypto_manager
        else:
            db_manager.close()
            sys.exit()

    if crypto_manager:
        main_window = MainWindow(crypto_manager, db_manager)
        main_window.show()
        sys.exit(app.exec())

if __name__ == '__main__':
    main()
