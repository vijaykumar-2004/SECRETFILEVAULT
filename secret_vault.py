#!/usr/bin/env python
import os
import base64
import shutil
import pyAesCrypt
from subprocess import call
import PySimpleGUI as sg
from getpass import getpass
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class secret_vault:
	
	buffer_size = 64 * 1024

	def __init__(self, masterpwd):
		self.masterpwd = masterpwd

	def add_file(self, path, encrypt):
		if encrypt:
			filenameWithExt = os.path.basename(path) + '.aes'
			vaultpath = self.hid_dir + filenameWithExt
			pyAesCrypt.encryptFile(path, vaultpath, self.key.decode(), self.buffer_size)
		else:
			shutil.copy(path, self.hid_dir)

	def del_file(self, index):
		filenameWithExt = self.files[index]
		vaultpath = self.hid_dir + filenameWithExt
		if filenameWithExt.endswith('.aes'):
			filename = filenameWithExt[:-4]
			pyAesCrypt.decryptFile(vaultpath, filename, self.key.decode(), self.buffer_size)
			os.remove(vaultpath)
		else:
			shutil.copy(vaultpath, filenameWithExt)
			os.remove(vaultpath)

	def list_files(self):
		self.get_files()
		if not self.files:
			print("\nVault is empty!!!")
			return
		maxlen = max([len(x) for x in self.files])
		print('')
		print('-'*(maxlen+10))
		print("index\t|files")
		print('-'*(maxlen+10))
		for i, file in enumerate(self.files):
			print("{}\t|{}".format(i, file))
			print('-'*(maxlen+10))

	def generate_key(self, salt=b"\xb9\x1f|}'S\xa1\x96\xeb\x154\x04\x88\xf3\xdf\x05", length=32):
		password = self.masterpwd.encode()    
		kdf = PBKDF2HMAC(algorithm = hashes.SHA256(),
	                     length = length,
	                     salt = salt,
	                     iterations = 100000,
	                     backend = default_backend())
	    
		self.key = base64.urlsafe_b64encode(kdf.derive(password))
	def get_files(self):
		self.files = os.listdir(self.hid_dir)

	def set_hid_dir(self):
		path = '~/.vault'
		hid_path = os.path.expanduser(path)
		self.hid_dir = hid_path + '/'

def main():
	print("Welcome to the secret vault!!!")
	path = os.path.expanduser('~/.vaultcfg')
	if os.path.exists(path):
		masterpwd = getpass("Enter your Master Password : ")
		vault = secret_vault(masterpwd)
		vault.generate_key()
		fernet = Fernet(vault.key)
		with open(path, 'rb') as f:
			actual_mpwd = f.read()
			try:
				fernet.decrypt(actual_mpwd)
				print('Welcome Back')
			except:
				print("Wrong Master Password!")
				exit()
	else:
		masterpwd = getpass("Create a Master Password : ")
		vault = secret_vault(masterpwd)
		vault.generate_key()
		fernet = Fernet(vault.key)
		enc_mpwd = fernet.encrypt(masterpwd.encode())
		with open(path, 'wb') as f:
			f.write(enc_mpwd)
			vault.set_hid_dir()
		try:
			os.makedirs(vault.hid_dir[:-1])
		except FileExistsError:
			pass

		if os.name == 'nt':
			call(["attrib", "+H", vault.hid_dir[:-1]])
			call(["attrib", "+H", path])

		print("Welcome")

	vault.set_hid_dir()

	choice = 0
	while choice != 4:
		print("\nEnter 1 to hide a file\nEnter 2 to unhide a file\nEnter 3 to view hidden files\nEnter 4 to Exit\nEnter 5 to Reset the vault and delete all of its contents\n")
		try:
			choice = int(input("Enter your choice : "))
		except:
			print("\nUnknown value!")
			continue

		if choice == 1:
			print("\nTip : Drag and Drop the file")
			filepath = input("Enter the path of the file to hide : ")
			filepath = filepath.replace('\\', '')
			if filepath.endswith(' '):
				filepath = filepath[:-1]
			if os.path.exists(filepath):
				if os.path.isfile(filepath):
					while True:
						enc_or_not = input("Do you want to encrypt the file? (Y or N) : ")
						if enc_or_not == 'y' or enc_or_not == 'Y':
							print('\nAdding file to the vault...')
							vault.add_file(filepath, 1)
							print("\nFile successfully added to the vault")
							print("You can now delete the original file if you want")
							break
						elif enc_or_not == 'n' or enc_or_not == 'N':
							print('\nAdding file to the vault...')
							vault.add_file(filepath, 0)
							print("\nFile successfully added to the vault")
							print("You can now delete the original file if you want")
							break
						else:
							print("Type Y or N")
				else:
					print("\nGiven path is a directory and not a file!")
			else:
				print('\nFile does not exists!')

		elif choice == 2:
			print('')
			try:
				file = int(input("Enter the index of the file from view hidden files : "))
				vault.del_file(file)
				print('\nFile unhided successfully')
				print('The file will be present in {}'.format(os.getcwd()))
			except:
				print("\nInvalid index!")

		elif choice == 3:
			vault.list_files()

		elif choice == 5:
			while True:
				confirm = input("\nDo you really want to delete and reset the vault?(Y or N) : ")
				if confirm == 'y' or confirm == 'Y':
					pwdCheck = getpass("\nEnter the password to confirm : ")
					reset = secret_vault(pwdCheck)
					reset.generate_key()
					resetFernet = Fernet(reset.key)
					path = os.path.expanduser('~/.vaultcfg')
					with open(path, 'rb') as f:
						actual_mpwd = f.read()
						try:
							resetFernet.decrypt(actual_mpwd)
							print('Removing and resetting all data...')
						except Exception as e:
							print(e)
							print("\nWrong Master Password!")
							print("Closing program now...")
							exit()
					os.remove(path)
					shutil.rmtree(vault.hid_dir[:-1])
					print('\nReset done. Thank You')
					exit()
				elif confirm == 'n' or confirm == 'N':
					print("\nHappy for that")
					break
				else:
					print("Type Y or N")

def create_secret_vault_gui():
    """Creates and displays the Secret Vault GUI."""

    sg.theme('DarkBlue3')

    layout = [
        [sg.Text('Welcome to the Secret Vault!')],
        [sg.Text('Enter your Master Password:'), sg.Input(key='master_pwd', password_char='*')],
        [sg.Checkbox('Create a new vault', default=False, key='create_new_vault'), sg.Button('Continue')],
        [sg.Text('', key='welcome_back_text', visible=False), sg.Text('', key='error_text', visible=False, text_color='red')],
        [sg.Text('Select a file to hide:'), sg.Input(key='filepath', disabled=True), sg.FileBrowse(key='file_browse')],
        [sg.Checkbox('Encrypt the file', default=True, key='encrypt_file')],
        [sg.Button('Add File'), sg.Button('List Files'), sg.Button('Delete File'), sg.Exit()],
        [sg.Text('', key='result_text', visible=False, text_color='green')],
    ]

    window = sg.Window('Secret Vault', layout, finalize=True)

    def handle_file_selection(values):
        """Updates the filepath input field based on user selection."""
        if values['file_browse']:
            window['filepath'].update(values['file_browse'])

    window.bind('<Button>', handle_file_selection)  # Bind file selection handler

    vault = None  # Initialize vault object

    while True:
        event, values = window.read(timeout=100)
        if event == sg.WIN_CLOSED or event == 'Exit':
            break

        if event == 'Continue':
            master_pwd = values['master_pwd']
            create_new_vault = values['create_new_vault']

            # Handle authentication and vault setup
            if not master_pwd:
                window['error_text'].update('Please enter a master password.')
                continue

            try:
                vault = secret_vault(master_pwd)
                vault.set_hid_dir()

                if create_new_vault:
                    # Create a new configuration file for the vault
                    vault.generate_key()
                    # (Add logic to write the encrypted master password to a file)
                    window['welcome_back_text'].update('Vault created successfully!')
                else:
                    # Load the encrypted master password from the configuration file
                    # (Add logic to read the encrypted master password from a file)
                    vault.generate_key()  # Replace with decryption logic if needed
                    window['welcome_back_text'].update('Welcome back!')
                window['master_pwd'].update('')  # Clear password field
                window['error_text'].update('')
                window['filepath'].update(disabled=False)  # Enable file selection

            except Exception as e:
                window['error_text'].update(f'An error occurred: {str(e)}')

        elif event == 'Add File':
            if not vault:
                window['error_text'].update('Please create or open a vault first.')
                continue

            filepath = values['filepath']
            encrypt_file = values['encrypt_file']

            if not filepath:
                window['error_text'].update('Please select a file to add.')
                continue

            try:
                vault.add_file(filepath, encrypt_file)
                window['result_text'].update('File added successfully!')
                window['filepath'].update('')  # Clear file path
            except Exception as e:
                window['error_text'].update(f'An error occurred: {str(e)}')

        elif event == 'List Files':
            if not vault:
                window['error_text'].update('Please create or open a vault first.')
                continue

            vault.list_files()



        window['result_text'].update('')  # Clear previous result text
        window['error_text'].update('')  # Clear previous error text

    window.close()


if __name__ == '__main__':
    create_secret_vault_gui()
