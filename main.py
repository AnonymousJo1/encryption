#!/usr/bin/env python3
import base64
import os
import argparse
from getpass import getpass
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import sys
from colorama import Fore, Back, Style, init
import time
import shutil

# Initialize colorama
init(autoreset=True)

__version__ = "2.1"

class AESEncryptor:
    def __init__(self, password: str, iterations: int = 100000):
        self.password = password.encode()
        self.iterations = iterations
        self.backend = default_backend()

    def _derive_key(self, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self.iterations,
            backend=self.backend
        )
        return kdf.derive(self.password)

    def encrypt(self, data: bytes) -> bytes:
        # Generate salt
        salt = os.urandom(16)
        key = self._derive_key(salt)
        
        # Generate IV
        iv = os.urandom(16)
        
        # Pad data
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        
        # Encrypt
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        # Combine salt, iv and ciphertext
        return b'Salted__' + salt + iv + ciphertext

    def decrypt(self, data: bytes) -> bytes:
        if not data.startswith(b'Salted__'):
            raise ValueError("Invalid file format. Missing salt header.")
            
        # Extract components
        salt = data[8:24]
        iv = data[24:40]
        ciphertext = data[40:]
        
        # Derive key
        key = self._derive_key(salt)
        
        # Decrypt
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Unpad
        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()
        
        return data

def encrypt_file(input_path: str, output_path: str, encryptor: AESEncryptor):
    try:
        file_size = os.path.getsize(input_path)
        processed = 0
        
        with open(input_path, 'rb') as f:
            data = f.read()
        
        encrypted_data = encryptor.encrypt(data)
        
        with open(output_path, 'wb') as f:
            f.write(encrypted_data)
            
        print(f"\n{Fore.GREEN}[✓] File encrypted successfully: {output_path}")
    except Exception as e:
        print(f"{Fore.RED}[×] Error encrypting file: {e}")
        sys.exit(1)

def decrypt_file(input_path: str, output_path: str, encryptor: AESEncryptor):
    try:
        file_size = os.path.getsize(input_path)
        processed = 0
        
        with open(input_path, 'rb') as f:
            data = f.read()
        
        decrypted_data = encryptor.decrypt(data)
        
        with open(output_path, 'wb') as f:
            f.write(decrypted_data)
            
        print(f"\n{Fore.GREEN}[✓] File decrypted successfully: {output_path}")
    except Exception as e:
        print(f"{Fore.RED}[×] Error decrypting file: {e}")
        sys.exit(1)

def clear_screen():
    """Clear the console screen"""
    os.system('cls' if os.name == 'nt' else 'clear')

def get_terminal_size():
    """Get terminal size for better formatting"""
    return shutil.get_terminal_size((80, 20))

def show_banner():
    """Display the tool banner with credits and animation"""
    clear_screen()
    width = get_terminal_size().columns
    
    # ASCII Art Banner
    ascii_art = [
        " ██████╗ ███████╗ █████╗ ███████╗██████╗ ███╗   ██╗",
        "██╔════╝ ██╔════╝██╔══██╗╚══███╔╝██╔══██╗████╗  ██║",
        "██║  ███╗█████╗  ███████║  ███╔╝ ██████╔╝██╔██╗ ██║",
        "██║   ██║██╔══╝  ██╔══██║ ███╔╝  ██╔══██╗██║╚██╗██║",
        "╚██████╔╝███████╗██║  ██║███████╗██║  ██║██║ ╚████║",
        " ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝",
    ]
    
    # Print ASCII Art
    print(Fore.CYAN + Style.BRIGHT + "=" * width)
    for line in ascii_art:
        print(Fore.CYAN + Style.BRIGHT + line.center(width))
    print(Fore.CYAN + Style.BRIGHT + "=" * width)
    
    # Credits
    print(Fore.YELLOW + "           Made By: Anonymous Jordan Team".center(width))
    print(Fore.YELLOW + "           Telegram: https://t.me/AnonymousJordan ".center(width))
    print(Fore.CYAN + Style.BRIGHT + "=" * width)
    print()

def loading_animation(message, duration=0.5):
    """Display a loading animation"""
    symbols = ['|', '/', '-', '\\']
    for _ in range(int(duration * 4)):
        for symbol in symbols:
            print(f"\r{Fore.CYAN}[{symbol}] {message}", end="")
            time.sleep(0.2)
    print()

def show_main_menu():
    """Display the main menu options with numbers"""
    show_banner()
    width = get_terminal_size().columns
    
    print(Fore.MAGENTA + Style.BRIGHT + "[ MAIN MENU ]".center(width))
    print()
    print(Fore.WHITE + "  [1] Start New Operation".center(width))
    print(Fore.WHITE + "  [2] Exit Application".center(width))
    print()
    
    menu_width = 50
    prompt = "Select an option [1-2]:".center(width)
    
    return prompt

def file_operation_menu(encryptor: AESEncryptor, operation: str):
    """Handle file encryption or decryption"""
    show_banner()
    
    print(Fore.MAGENTA + Style.BRIGHT + f"[ {operation.upper()} FILE OPERATION ]".center(get_terminal_size().columns))
    
    input_path = input(Fore.CYAN + "\n➤ Enter input file path: " + Fore.WHITE)
    if not os.path.exists(input_path):
        print(Fore.RED + "[×] Input file does not exist!")
        return
    
    output_path = input(Fore.CYAN + "➤ Enter output file path: " + Fore.WHITE)
    
    loading_animation(f"{operation}ing file...")
    
    if operation == "encrypt":
        encrypt_file(input_path, output_path, encryptor)
    elif operation == "decrypt":
        decrypt_file(input_path, output_path, encryptor)
    
    input(Fore.YELLOW + "\n[→] Press Enter to continue...")

def text_operation_menu(encryptor: AESEncryptor, operation: str):
    """Handle text encryption or decryption"""
    show_banner()
    print(Fore.MAGENTA + Style.BRIGHT + f"[ {operation.upper()} TEXT OPERATION ]".center(get_terminal_size().columns))
    
    if operation == "encrypt":
        password = getpass(Fore.CYAN + "\n➤ Enter encryption password: " + Fore.WHITE)
        confirm_pass = getpass(Fore.CYAN + "➤ Confirm password: " + Fore.WHITE)
        
        if password != confirm_pass:
            print(Fore.RED + "[×] Passwords do not match!")
            return
        
        encryptor = AESEncryptor(password)
        
        print(Fore.YELLOW + "[*] Enter text (Ctrl+D to end):")
        text = sys.stdin.read().encode()
        
        output_path = input(Fore.CYAN + "➤ Enter output file path: " + Fore.WHITE)
        
        loading_animation("Encrypting text...")
        
        encrypted_data = encryptor.encrypt(text)
        
        with open(output_path, 'wb') as f:
            f.write(encrypted_data)
            
        print(Fore.GREEN + f"[✓] Text encrypted successfully: {output_path}")
    
    elif operation == "decrypt":
        input_path = input(Fore.CYAN + "\n➤ Enter input file path: " + Fore.WHITE)
        
        if not os.path.exists(input_path):
            print(Fore.RED + "[×] Input file does not exist!")
            return
        
        password = getpass(Fore.CYAN + "➤ Enter decryption password: " + Fore.WHITE)
        encryptor = AESEncryptor(password)
        
        loading_animation("Decrypting file...")
        
        try:
            with open(input_path, 'rb') as f:
                data = f.read()
            
            decrypted_text = encryptor.decrypt(data).decode()
            
            print(Fore.YELLOW + "\n[¤] Decrypted text:")
            print(Fore.WHITE + "-" * 50)
            print(decrypted_text)
            print("-" * 50)
        except Exception as e:
            print(Fore.RED + f"[×] Error decrypting text: {e}")
    
    input(Fore.YELLOW + "\n[→] Press Enter to continue...")

def show_operations_menu(encryptor: AESEncryptor):
    """Display the operations menu with numbers"""
    while True:
        show_banner()
        width = get_terminal_size().columns
        
        print(Fore.MAGENTA + Style.BRIGHT + "[ OPERATION MENU ]".center(width))
        print()
        print(Fore.WHITE + "  [1] Encrypt File".center(width))
        print(Fore.WHITE + "  [2] Decrypt File".center(width))
        print(Fore.WHITE + "  [3] Encrypt Text".center(width))
        print(Fore.WHITE + "  [4] Decrypt Text".center(width))
        print(Fore.WHITE + "  [5] Return to Main Menu".center(width))
        print()
        
        menu_width = 50
        prompt = "Select an option [1-5]:".center(width)
        choice = input(Fore.CYAN + prompt + Fore.WHITE + " ")
        
        try:
            choice = int(choice)
            
            if choice == 1:
                file_operation_menu(encryptor, "encrypt")
            elif choice == 2:
                file_operation_menu(encryptor, "decrypt")
            elif choice == 3:
                text_operation_menu(encryptor, "encrypt")
            elif choice == 4:
                text_operation_menu(encryptor, "decrypt")
            elif choice == 5:
                break
            else:
                print(Fore.RED + "[×] Invalid option selected!".center(width))
                input(Fore.YELLOW + "[→] Press Enter to continue...")
        except ValueError:
            print(Fore.RED + "[×] Please enter a valid number!".center(width))
            input(Fore.YELLOW + "[→] Press Enter to continue...")

def main():
    show_banner()
    
    while True:
        prompt = show_main_menu()
        choice = input(prompt + " ")
        
        try:
            choice = int(choice)
            
            if choice == 1:
                # Start New Operation
                show_banner()
                password = getpass(Fore.CYAN + "\n➤ Enter encryption/decryption password: " + Fore.WHITE)
                encryptor = AESEncryptor(password)
                show_operations_menu(encryptor)
            elif choice == 2:
                # Exit Application
                show_banner()
                print(Fore.CYAN + "[*] Thank you for using AES Encryption/Decryption Tool!".center(get_terminal_size().columns))
                print(Fore.YELLOW + "[*] Exiting...".center(get_terminal_size().columns))
                time.sleep(1)
                clear_screen()
                break
            else:
                print(Fore.RED + "[×] Invalid option selected!".center(get_terminal_size().columns))
                input(Fore.YELLOW + "[→] Press Enter to continue...")
        except ValueError:
            print(Fore.RED + "[×] Please enter a valid number!".center(get_terminal_size().columns))
            input(Fore.YELLOW + "[→] Press Enter to continue...")

if __name__ == "__main__":
    main()
