import sys
import bson
from PySide6.QtWidgets import (
    QApplication, QWidget, QLineEdit, QTextEdit, QPushButton, QVBoxLayout, QHBoxLayout, QListWidget, QLabel, QListWidgetItem, QMessageBox, QInputDialog
)
from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtGui import QShortcut, QKeySequence
import keyboard
from random import uniform
import kryptonator
import keyring
from argon2 import PasswordHasher, exceptions as argon2_exceptions
import json
import time
import stat
import traceback
from pathlib import Path
import os
import sys

# PASSPHRASE = "1234567812345678"
# Константы
DATA_FILE = "data.json"
APP_NAME = "secure_pyside_app_v1"
KEY_PASSWORD_HASH = "password_hash"
KEY_SECURITY = "security_settings"
KEY_BACKEND = "storage_backend"
LOCK_KEY = "lock_state"
KEY_FILE_PW = "local_store_password"  # для хранения сгенерированного пароля файла в keyring

DEFAULT_SECURITY = {"max_attempts": 5, "lock_duration": 5 * 60}
LOCAL_STORE_DEFAULT = str(Path.home() / ".secure_app_store.bin")

# Argon2 для хэшей пароля приложения
PH = PasswordHasher(time_cost=3, memory_cost=64 * 1024, parallelism=2, hash_len=32)


# -------------------------
# Keyring & password handling
# -------------------------
def password_is_set():
    try:
        return bool(keyring.get_password(APP_NAME, KEY_PASSWORD_HASH))
    except Exception:
        return False


def set_password_hash(pwd):
    phash = PH.hash(pwd)
    keyring.set_password(APP_NAME, KEY_PASSWORD_HASH, phash)
    clear_lock_state()
    # очистка
    try:
        del phash
    except Exception:
        pass


def verify_password(pwd):
    phash = None
    try:
        phash = keyring.get_password(APP_NAME, KEY_PASSWORD_HASH)
        if not phash:
            return False
        PH.verify(phash, pwd)
        if PH.check_needs_rehash(phash):
            set_password_hash(pwd)
        return True
    except argon2_exceptions.VerifyMismatchError:
        return False
    except Exception:
        traceback.print_exc()
        return False
    finally:
        try:
            del phash
        except Exception:
            pass


# -------------------------
# Keyring json helpers & security settings
# -------------------------
def load_json_key(key, default):
    try:
        raw = keyring.get_password(APP_NAME, key)
        if raw:
            return json.loads(raw)
    except Exception:
        traceback.print_exc()
    return default


def save_json_key(key, value):
    try:
        keyring.set_password(APP_NAME, key, json.dumps(value))
    except Exception:
        traceback.print_exc()


def get_security_settings():
    return load_json_key(KEY_SECURITY, DEFAULT_SECURITY.copy())


def set_security_settings(settings):
    save_json_key(KEY_SECURITY, settings)


def get_lock_state():
    return load_json_key(LOCK_KEY, {"attempts": 0, "unlock_time": 0.0})


def set_lock_state(state):
    save_json_key(LOCK_KEY, state)


def clear_lock_state():
    set_lock_state({"attempts": 0, "unlock_time": 0.0})


def is_locked():
    st = get_lock_state()
    return time.time() < st.get("unlock_time", 0)


def get_remaining_lock_seconds():
    st = get_lock_state()
    return max(0, int(st.get("unlock_time", 0) - time.time()))


def increment_attempts_and_lock_if_needed(settings):
    st = get_lock_state()
    attempts = st.get("attempts", 0) + 1
    if attempts >= settings.get("max_attempts", 5):
        st = {"attempts": attempts, "unlock_time": time.time() + settings.get("lock_duration", 300)}
        set_lock_state(st)
        return True, 0
    st["attempts"] = attempts
    set_lock_state(st)
    return False, settings.get("max_attempts", 5) - attempts


def load_backend_choice():
    try:
        raw = keyring.get_password(APP_NAME, KEY_BACKEND)
        if raw:
            return json.loads(raw)
    except Exception:
        pass
    return {"type": "keyring"}


def save_backend_choice(b):
    keyring.set_password(APP_NAME, KEY_BACKEND, json.dumps(b))


# -------------------------
# Security environment checks
# -------------------------
def check_security_environment(parent=None):
    messages = []

    # keyring backend type
    try:
        kr = keyring.get_keyring()
        backend_type = type(kr).__name__
        if "Plaintext" in backend_type or "fail" in backend_type.lower():
            messages.append("Keyring работает в небезопасном режиме (Plaintext backend). Данные могут храниться в открытом виде.")
    except Exception:
        messages.append("Не удалось определить backend keyring (возможна некорректная конфигурация).")

    # PEPPER env variable
    if "PEPPER" in os.environ:
        messages.append("Найдена переменная окружения PEPPER. Не рекомендуется хранить pepper в env; используйте keyring/TPM.")

    # check local backend file permissions if configured
    try:
        backend_choice = load_backend_choice()
        if backend_choice.get("type") == "local_encrypted_file":
            path = backend_choice.get("file")
            if path and os.path.exists(path):
                st = os.stat(path)
                if os.name == "posix":
                    perms = stat.S_IMODE(st.st_mode)
                    if perms != 0o600:
                        messages.append(f"Файл {path} имеет права {oct(perms)}; рекомендуется установить 0o600 (rw-------).")
    except Exception:
        pass

    if messages:
        text = "Обнаружены потенциальные проблемы безопасности:\n\n" + "\n\n".join(messages)
        if parent is None:
            QMessageBox.warning(None, "Проверка безопасности", text)
        else:
            QMessageBox.warning(parent, "Проверка безопасности", text)


class PasswordWindow(QWidget):
    def keyPressEvent(self, event):
        if event.key() == Qt.Key_Escape:
            self.close()
        else:
            super().keyPressEvent(event)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Авторизация - Password manager <by ivnsam>")
        self.setFixedSize(420, 200)
        self.settings = get_security_settings()
        self.backend = load_backend_choice()

        # warn if keyring insecure (early)
        try:
            kr = keyring.get_keyring()
            backend_type = type(kr).__name__
            if "Plaintext" in backend_type:
                QMessageBox.warning(self, "Предупреждение безопасности",
                                    "Keyring работает в незашифрованном режиме (Plaintext backend). Рекомендуется использовать локальное зашифрованное хранилище.")
        except Exception:
            pass

        layout = QVBoxLayout()
        self.label = QLabel("Введите пароль приложения:")
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.login_button = QPushButton("Войти")
        login_shortcut = QShortcut('return', self)
        login_shortcut.activated.connect(self.login_button.click)
        self.login_button.setShortcut(Qt.Key.Key_Enter)
        self.login_button.clicked.connect(self.check_password)

        layout.addWidget(self.label)
        layout.addWidget(self.password_input)
        layout.addWidget(self.login_button)

        if not password_is_set():
            self.label.setText("Пароль не установлен. Создайте новый (рекомендуем не менее 16 символов):")
            self.login_button.setText("Создать пароль")
            self.login_button.clicked.disconnect()
            self.login_button.clicked.connect(self.set_new_password)

        self.setLayout(layout)
        # store session password after successful login (kept only in memory during session)
        self.session_password = None

    def set_new_password(self):
        pwd = self.password_input.text().strip()
        if not pwd:
            QMessageBox.warning(self, "Ошибка", "Пароль не может быть пустым.")
            return
        confirm, ok = QInputDialog.getText(self, "Подтверждение", "Повторите пароль:", QLineEdit.Password)
        if not ok or pwd != confirm:
            QMessageBox.warning(self, "Ошибка", "Пароли не совпадают.")
            return
        set_password_hash(pwd)
        # clear UI field
        self.password_input.clear()
        # store session password
        self.session_password = pwd
        QMessageBox.information(self, "Готово", "Пароль создан.")
        # open main window and pass the session password
        self.open_main_window()

    def check_password(self):
        if is_locked():
            remain = get_remaining_lock_seconds()
            QMessageBox.critical(self, "Заблокировано", f"Подождите {remain // 60} мин {remain % 60} сек.")
            QApplication.quit()
            return
        pwd = self.password_input.text().strip()
        self.password_input.clear()
        if verify_password(pwd):
            clear_lock_state()
            self.session_password = pwd  # keep for session (used e.g. for "use app password for local store")
            self.open_main_window()
        else:
            locked, remaining = increment_attempts_and_lock_if_needed(self.settings)
            if locked:
                QMessageBox.critical(self, "Блокировка", f"Достигнуто {self.settings.get('max_attempts')} неверных попыток. Приложение заблокировано.")
                QApplication.quit()
            else:
                QMessageBox.warning(self, "Ошибка", f"Неверный пароль. Осталось попыток: {remaining}")
        # try to remove pwd from memory
        try:
            del pwd
        except Exception:
            pass

    def open_main_window(self):
        self.main_window = PassMgrWindow(passphrase=self.session_password)#session_password=self.session_password)
        self.main_window.show()
        # clear session_password in this window (MainWindow keeps reference if needed)
        self.session_password = None
        self.close()


class TimerButton(QPushButton):
    finished = Signal()  # сигнал, который сработает, когда таймер закончится

    def __init__(self, text="Start Timer", duration_seconds=5.0, parent=None):
        super().__init__(text, parent)

        self.default_text = text
        self.duration = duration_seconds
        self.remaining = 0.0
        self.interval_ms = 100  # шаг таймера (100мс = точность до 0.1с)

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_timer)

        # по клику запускаем таймер
        self.clicked.connect(self._on_click)

    def _on_click(self):
        if self.timer.isActive():
            return  # если таймер уже идёт — игнорируем
        self.start_timer()

    def start_timer(self):
        """Запустить отсчет."""
        self.remaining = self.duration
        self.setText(f"{self.remaining:.1f}")
        self.timer.start(self.interval_ms)

    def update_timer(self):
        self.remaining -= self.interval_ms / 1000.0
        if self.remaining > 0:
            self.setText(f"{self.remaining:.1f}")
        else:
            self.timer.stop()
            self.setText(self.default_text)
            self.finished.emit()  # сообщаем, что таймер завершился

class PassMgrWindow(QWidget):
    def __init__(self, passphrase):
        self.passphrase = passphrase
        passphrase = None
        del passphrase
        # Подбираем параметры Argon2
        sample = self.passphrase.encode("utf-8") + kryptonator.get_pepper()
        self.t, self.m, self.p = kryptonator.autotune_argon2(sample)
        super().__init__()
        self.setWindowTitle("Password manager <by ivnsam>")
        # input fields
        self.id_edit = QLineEdit()
        self.id_edit.setPlaceholderText("Name this password")
        self.id_edit.setEnabled(False)
        login_field = QHBoxLayout()
        self.copy_login_btn = QPushButton("🪪Copy login")
        self.login_edit = QLineEdit()
        self.login_edit.setPlaceholderText("Write here your login")
        self.login_edit.setEnabled(False)
        login_field.addWidget(self.copy_login_btn)
        login_field.addWidget(self.login_edit)
        password_field = QHBoxLayout()
        self.copy_password_btn = TimerButton("🔑Copy password")
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.Password)
        self.password_edit.setPlaceholderText("Write here your password")
        self.password_edit.setEnabled(False)
        self.toggle_password_btn = QPushButton("👁")
        self.toggle_password_btn.setCheckable(True)
        password_field.addWidget(self.copy_password_btn)
        password_field.addWidget(self.password_edit)
        password_field.addWidget(self.toggle_password_btn)
        self.comment_edit = QTextEdit()
        self.comment_edit.setEnabled(False)
        self.comment_edit.setPlaceholderText("Comment (ex. site or service name)")

        # buttons
        self.add_new_btn = QPushButton("➕New")
        self.save_btn = QPushButton("💾Save")
        self.save_btn.setHidden(True)
        self.edit_btn = QPushButton("✏️Edit")
        self.edit_btn.setCheckable(True)
        self.edit_btn.setEnabled(False)
        self.delete_btn = QPushButton("🗑️Delete")
        self.delete_btn.setEnabled(False)
        btn_layout = QHBoxLayout()
        btn_layout.addWidget(self.add_new_btn)
        btn_layout.addWidget(self.save_btn)
        btn_layout.addWidget(self.edit_btn)
        btn_layout.addWidget(self.delete_btn)

        # saved passwords list
        self.list_widget = QListWidget()
        self.passwords = self.load_passwords_file()
        for entry in self.passwords.values():
            self.add_password_item(entry)
        self.list_widget.setCurrentRow(-1)

        # complete screen
        layout = QVBoxLayout()
        layout.addWidget(QLabel("Password name:"))
        layout.addWidget(self.id_edit)
        layout.addWidget(QLabel("Login:"))
        layout.addLayout(login_field)
        layout.addWidget(QLabel("Password:"))
        layout.addLayout(password_field)
        layout.addWidget(QLabel("Comment:"))
        layout.addWidget(self.comment_edit)
        layout.addLayout(btn_layout)
        layout.addWidget(QLabel("Saved passwords:"))
        layout.addWidget(self.list_widget)
        self.setLayout(layout)

        # connections
        self.add_new_btn.clicked.connect(self.on_new)
        self.save_btn.clicked.connect(self.on_save)
        self.copy_login_btn.clicked.connect(lambda: QApplication.clipboard().setText(self.login_edit.text()))
        self.copy_password_btn.clicked.connect(lambda: keyboard.add_hotkey('ctrl+alt+v', self.print_password))
        self.copy_password_btn.finished.connect(lambda: keyboard.remove_hotkey('ctrl+alt+v'))
        self.edit_btn.clicked.connect(self.toggle_edit)
        self.delete_btn.clicked.connect(self.on_delete)
        self.toggle_password_btn.toggled.connect(self.toggle_password)
        self.list_widget.itemSelectionChanged.connect(self.on_select)


    def reset_ui_states(self):
        self.id_edit.setPlaceholderText("Name this password")
        self.id_edit.setEnabled(False)
        self.login_edit.setPlaceholderText("Write here your login")
        self.login_edit.setEnabled(False)
        self.password_edit.setEchoMode(QLineEdit.Password)
        self.password_edit.setPlaceholderText("Write here your password")
        self.password_edit.setEnabled(False)
        self.toggle_password_btn.setCheckable(True)
        self.comment_edit.setEnabled(False)
        self.comment_edit.setPlaceholderText("Comment (ex. site or service name)")
        self.save_btn.setHidden(True)
        self.edit_btn.setCheckable(True)
        self.edit_btn.setEnabled(False)
        self.delete_btn.setEnabled(False)

    def toggle_password(self, checked):
        if checked:
            selected_items = self.list_widget.selectedItems()
            if selected_items:
                item = selected_items[0]
                item = item.text().split(" | ")[0]
                item = self.passwords[item]
                self.password_edit.setText(kryptonator.decrypt_string(item["password"], self.passphrase))
                item = ""
                del item
            self.password_edit.setEchoMode(QLineEdit.Normal)
        else:
            self.password_edit.setText("***")
            self.password_edit.setEchoMode(QLineEdit.Password)
    
    def on_select(self):
        # get all selected items
        selected_items = self.list_widget.selectedItems()
        if selected_items:
            item = selected_items[0]
            # here is no multiselect, so it needs only first one
            item = item.text().split(" | ")[0]
            item = self.passwords[item]
            # UI modifications
            self.toggle_password_btn.setChecked(False)
            self.id_edit.setText(item["id"])
            self.id_edit.setEnabled(False)
            self.login_edit.setText(item["login"])
            self.login_edit.setEnabled(False)
            self.copy_login_btn.setEnabled(True)
            self.password_edit.setText("***")
            self.password_edit.setEnabled(False)
            self.copy_password_btn.setEnabled(True)
            self.comment_edit.setText(item["comment"])
            self.comment_edit.setEnabled(False)
            self.edit_btn.setEnabled(True)
            self.delete_btn.setEnabled(True)
            self.save_btn.setHidden(True)
            self.add_new_btn.setHidden(False)
            item = ""
            del item
    
    def on_new(self):
        self.list_widget.clearSelection()
        self.id_edit.clear()
        self.id_edit.setEnabled(True)
        self.id_edit.setFocus()
        self.login_edit.clear()
        self.login_edit.setEnabled(True)
        self.password_edit.clear()
        self.password_edit.setEnabled(True)
        self.comment_edit.clear()
        self.comment_edit.setEnabled(True)
        self.save_btn.setHidden(False)
        self.add_new_btn.setHidden(True)

    def on_save(self):
        entry = {
            "id": self.id_edit.text(),
            "login": self.login_edit.text(),
            "password": kryptonator.encrypt_string(self.password_edit.text(), self.passphrase, self.t, self.m, self.p),
            "comment": self.comment_edit.toPlainText()
        }

        if entry["id"] in self.passwords:
            find_results = self.list_widget.findItems(entry["id"], Qt.MatchStartsWith)
            item_number = self.list_widget.indexFromItem(find_results[0]).row()
            self.passwords[entry["id"]] = entry
            self.save_passwords_file()
            self.update_password_item(item_number, entry)
        else:
            self.passwords[entry["id"]] = entry
            self.save_passwords_file()
            self.add_password_item(entry)
        self.edit_btn.setChecked(False)
    
    def on_delete(self):
        # get all selected items
        item = self.list_widget.selectedItems()[0]
        # here is no multiselect, so it needs only first one
        item = item.text().split(" | ")[0]
        item = self.passwords[item]
        if item["id"] in self.passwords:
            find_results = self.list_widget.findItems(item["id"], Qt.MatchStartsWith)
            item_number = self.list_widget.indexFromItem(find_results[0]).row()
            self.passwords.pop(item["id"])
            self.list_widget.takeItem(item_number)
            self.list_widget.clearSelection()
            self.save_passwords_file()
            self.edit_btn.setEnabled(False)
            self.delete_btn.setChecked(False)
            self.delete_btn.setEnabled(False)
            # for fixing bug when button stays hovered when makes disabled
            self.delete_btn.setAttribute(Qt.WidgetAttribute.WA_UnderMouse, False)
            self.id_edit.clear()
            self.login_edit.clear()
            self.password_edit.clear()
            self.comment_edit.clear()
    
    def toggle_edit(self, checked):
        if checked:
            # Edit was clicked
            self.edit_btn.setText("✖️Cancel")
        else:
            # Cancel was clicked
            self.edit_btn.setText("✏️Edit")
            # get all selected items
            selected_items = self.list_widget.selectedItems()
            if selected_items:
                item = selected_items[0]
                # here is no multiselect, so it needs only first one
                item = item.text().split(" | ")[0]
                item = self.passwords[item]
                # UI modifications
                self.id_edit.setText(item["id"])
                self.login_edit.setText(item["login"])
                self.toggle_password_btn.setChecked(False)
                self.password_edit.setText("***")
                self.comment_edit.setText(item["comment"])
                item = ""
                del item

        self.id_edit.setEnabled(checked)
        self.login_edit.setEnabled(checked)
        self.password_edit.setEnabled(checked)
        self.comment_edit.setEnabled(checked)
        self.save_btn.setHidden(not checked)
        self.add_new_btn.setHidden(checked)


    def print_password(self):
        selected_items = self.list_widget.selectedItems()
        if selected_items:
            item = selected_items[0]
            # here is no multiselect, so it needs only first one
            item = item.text().split(" | ")[0]
            item = self.passwords[item]
            item = kryptonator.decrypt_string(item["password"], self.passphrase)
            for symbol in item:
                keyboard.write(symbol, uniform(0.02, 0.1))
            item = ""
            del item

    def save_passwords_file(self):
        # Save passwords from memory to file
        with open(DATA_FILE+".bson", "wb") as f:
            f.write(bson.dumps(self.passwords))

    def load_passwords_file(self) -> dict:
        # Load passwords from file
        data = {}
        try:
            with open(DATA_FILE+".bson", "rb") as f:
                data = bson.loads(f.read())
        except FileNotFoundError:
            with open(DATA_FILE+".bson", "wb") as f:
                f.write(bson.dumps(data))
            with open(DATA_FILE+".bson", "rb") as f:
                data = bson.loads(f.read())
        return data

    def add_password_item(self, entry):
        display_str = f"{entry['id']} | {entry['login']} | {'*' * 8} | {entry['comment']}"
        new_item = QListWidgetItem()
        new_item.setText(display_str)
        new_item.setSelected(True)
        self.list_widget.addItem(new_item)
        self.list_widget.sortItems()
        self.list_widget.setCurrentItem(new_item)
    
    def update_password_item(self, item_number, entry):
        self.list_widget.takeItem(item_number)
        self.add_password_item(entry)
        self.list_widget.setCurrentRow(item_number)


def main():
    app = QApplication(sys.argv)
    if is_locked():
        remain = get_remaining_lock_seconds()
        QMessageBox.critical(None, "Блокировка", f"Приложение заблокировано. Подождите {remain // 60} мин {remain % 60} сек.")
        sys.exit(0)
    w = PasswordWindow()
    w.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
