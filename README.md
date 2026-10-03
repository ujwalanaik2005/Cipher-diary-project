# 🔐 Cipher Diary

Cipher Diary is a command-line diary management application developed in C.
It allows multiple users to register, log in, and securely manage their personal
diary entries.

## ✨ Features

- User registration and login
- Password input hidden while typing
- Passwords stored as a djb2 hash instead of plain text
- Separate diary file for each user
- Add new diary entries
- View and decrypt entries
- Edit existing entries
- Delete entries
- Search entries by title or date
- Automatic date recording
- Vigenère-style byte-level encryption
- Encrypted diary data stored in hexadecimal format
- Windows and Linux/Mac terminal support

## 🛠️ Technologies Used

- C Programming
- File Handling
- Structures and Arrays
- String Handling
- Functions
- Modular Arithmetic
- Hashing
- Encryption / Decryption
- Command-Line Interface

## 🔐 Encryption

The project uses a Vigenère-style cipher based on byte addition/subtraction
modulo 256.

### Encryption

```text
encrypted = (plain_text + key) mod 256