import PySimpleGUI as sg
from getpass import getpass
from secret_vault import secret_vault  # Replace with "file_vault.py" if that's your filename
from cryptography.fernet import Fernet
import os

class VaultGUI:
    def __init__(self):
        self.window = None
        self.vault = None
        self.password = None

    def init_widgets(self):
        layout = [
            [sg.Text("Secret File Vault", font=("Arial", 18))],
            [sg.Frame("", [
                [sg.Button("Add File", key="-ADD_FILE-")],
                [sg.Button("Unhide File", key="-UNHIDE_FILE-")],
                [sg.Button("View Hidden Files",  key="-VIEW_HIDDEN_FILES-")],
                [sg.Exit(width=10, key="-EXIT-")]
            ], size=(15, 15), relief=sg.RAISED)],
            [sg.Frame("", [
                [sg.Input(key="-PASSWORD_ENTRY-", password_char="*", size=(25, 1))],
                [sg.Text("Password:", key="-PASSWORD_ENTRY_LABEL-")]
            ], size=(15, 15), relief=sg.RAISED)],
            [sg.Text("", key="-STATUS_LABEL-", text_color="red", font=("Arial", 12))]
        ]

        self.window = sg.Window("Secret File Vault", layout, finalize=True)

    def authenticate(self):
        password = self.window["-PASSWORD_ENTRY-"].get()
        self.window["-PASSWORD_ENTRY-"].update("")  # Clear password entry after use

        self.vault = secret_vault(password)
        self.vault.generate_key()  # Generate key from password
        fernet = Fernet(self.vault.key)

        path = os.path.expanduser('~/.vaultcfg')

        if not os.path.exists(path):
            with open(path, 'wb') as file:
                file.write(self.vault.key)

        with open(path, 'rb') as file:
            stored_key = file.read()

        if stored_key != self.vault.key:
            self.window["-STATUS_LABEL-"].update("Invalid password!")
            return

        self.window["-STATUS_LABEL-"].update("")

    def add_file(self):
        self.authenticate()
        file_path = sg.popup_get_file("Select file to add", file_types=(("All files", "*.*"),))

        if not file_path:
            return

        self.vault.add_file(file_path)

    def unhide_file(self):
        self.authenticate()
        file_path = sg.popup_get_file("Select hidden file to unhide", file_types=(("Hidden files", ".*"),))

        if not file_path:
            return

        self.vault.unhide_file(file_path)

    def view_hidden_files(self):
        self.authenticate()
        hidden_files = self.vault.get_hidden_files()

        if not hidden_files:
            sg.popup("No hidden files found!")
            return

        file_list = "\n".join(hidden_files)
        sg.popup("Hidden files:\n\n" + file_list)

    def run(self):
        self.init_widgets()

        while True:
            event, values = self.window.read()

            if event == "-EXIT-":
                break

            if event == "-ADD_FILE-":
                self.add_file()

            if event == "-UNHIDE_FILE-":
                self.unhide_file()

            if event == "-VIEW_HIDDEN_FILES-":
                self.view_hidden_files()

        self.window.close()


if __name__ == "__main__":
    app = VaultGUI()
    app.run()