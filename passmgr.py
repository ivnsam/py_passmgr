import sys
# import json
import bson
from PySide6.QtWidgets import (
    QApplication, QWidget, QLineEdit, QTextEdit, QPushButton, QVBoxLayout, QHBoxLayout, QListWidget, QLabel, QListWidgetItem
)
from PySide6.QtCore import Qt
import kryptonator

DATA_FILE = "data.json"
PASSPHRASE = "1234567812345678"


class SimpleForm(QWidget):
    def __init__(self):
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
        self.copy_pw_btn = QPushButton("🔑Copy password")
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.Password)
        self.password_edit.setPlaceholderText("Write here your password")
        self.password_edit.setEnabled(False)
        self.toggle_pw_btn = QPushButton("👁")
        self.toggle_pw_btn.setCheckable(True)
        self.toggle_pw_btn.toggled.connect(self.toggle_password)
        password_field.addWidget(self.copy_pw_btn)
        password_field.addWidget(self.password_edit)
        password_field.addWidget(self.toggle_pw_btn)
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
        self.list_widget.itemSelectionChanged.connect(self.on_select)

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
        self.copy_pw_btn.clicked.connect(lambda: QApplication.clipboard().setText(self.password_edit.text()))
        self.edit_btn.clicked.connect(self.toggle_edit)
        self.delete_btn.clicked.connect(self.on_delete)


    def toggle_password(self, checked):
        if checked:
            selected_items = self.list_widget.selectedItems()
            if selected_items:
                item = selected_items[0]
                item = item.text().split(" | ")[0]
                item = self.passwords[item]
                self.password_edit.setText(kryptonator.decrypt_string(item["password"], PASSPHRASE))
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
            self.toggle_pw_btn.setChecked(False)
            self.id_edit.setText(item["id"])
            self.id_edit.setEnabled(False)
            self.login_edit.setText(item["login"])
            self.login_edit.setEnabled(False)
            self.copy_login_btn.setEnabled(True)
            self.password_edit.setText("***")
            self.password_edit.setEnabled(False)
            self.copy_pw_btn.setEnabled(True)
            self.comment_edit.setText(item["comment"])
            self.comment_edit.setEnabled(False)
            self.edit_btn.setEnabled(True)
            self.delete_btn.setEnabled(True)
            self.save_btn.setHidden(True)
            self.add_new_btn.setHidden(False)
    
    def on_new(self):
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
        # Подбираем параметры Argon2
        sample = PASSPHRASE.encode("utf-8") + kryptonator.get_pepper()
        t, m, p = kryptonator.autotune_argon2(sample)
        entry = {
            "id": self.id_edit.text(),
            "login": self.login_edit.text(),
            "password": kryptonator.encrypt_string(self.password_edit.text(), PASSPHRASE, t, m, p),
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
            # self.delete_password_item(item_number)
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
        self.id_edit.setEnabled(checked)
        self.login_edit.setEnabled(checked)
        self.password_edit.setEnabled(checked)
        self.comment_edit.setEnabled(checked)
        self.save_btn.setHidden(not checked)
        self.add_new_btn.setHidden(checked)


    def save_passwords_file(self):
        # Save passwords from memory to file
        ## old insecure json format
        # with open(DATA_FILE, "w", encoding="utf-8") as f:
        #     json.dump(self.passwords, f, ensure_ascii=False, indent=2)
        with open(DATA_FILE+".bson", "wb") as f:
            f.write(bson.dumps(self.passwords))

        # with open(DATA_FILE, "r", encoding="utf-8") as f:
        #     print(kryptonator.decrypt_string(f.read(), "1234567812345678"))
    def load_passwords_file(self) -> dict:
        # Load passwords from file
        data = {}
        try:
            ## old insecure json format
            # with open(DATA_FILE, "r", encoding="utf-8") as f:
            #     data = json.load(f)
            with open(DATA_FILE+".bson", "rb") as f:
                data = bson.loads(f.read())
        except FileNotFoundError:
            with open(DATA_FILE+".bson", "wb") as f:
                f.write(bson.dumps(data))
            with open(DATA_FILE+".bson", "rb") as f:
                data = bson.loads(f.read())
            ## old insecure json format
            # with open(DATA_FILE, "w", encoding="utf-8") as f:
            #     json.dump(data, f, ensure_ascii=False, indent=2)
            # with open(DATA_FILE, "r", encoding="utf-8") as f:
            #     data = json.load(f)
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
    window = SimpleForm()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
