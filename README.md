# Password-Manager
A personal project to learn C programming and encryption techniques.This password manager uses OpenSSL for AES encryption to securely manager  passwords through a command-line interface.
## How to Compile and Run
1. Make sure you have **GCC** and **OpenSSL** installed.
2. Clone this repository:
   ```bash
   git clone https://github.com/lorencomingla/Password-Manager.git
   cd Password-Manager
   ```
3. Compile the program using:
   ```bash
   gcc password_manager.c -o password_manager -lssl -lcrypto
   ```
4. Run the program:
   ```bash
   ./password_manager
   ```
5. Follow the prompts to add, retrieve, or view stored passwords.

## Features
- Store and retrieve passwords securely using AES-128 encryption.
- Command-line interface for easy interaction.
- User authentication through a master password.

## Technologies Used
- C Programming
- OpenSSL (AES-128 Encryption)
