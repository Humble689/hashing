# Secure Password Manager (C Implementation)

A command-line password manager written in C that uses bcrypt for secure password hashing.
  
## Features
- Secure password hashing using bcrypt
- Password storage and retrieval
- Password verification
- Simple command-line interface
- JSON-based storage 
 
## Dependencies
- GCC compiler
- libbcrypt
- libjson-c

## Installation
1. Install the required dependencies:
   - On Ubuntu/Debian:
     ```
     sudo apt-get install gcc libbcrypt-dev libjson-c-dev
     ```
   - On Windows (using MinGW):
     ```
     pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-bcrypt mingw-w64-x86_64-json-c
     ```

2. Compile the program:
   ```
   make
   ```

## Usage
Run the password manager:
```
./password_manager
```

Available commands:
- `1`: Add a new password
- `2`: Retrieve a stored password
- `3`: Verify a password
- `4`: List all stored passwords
- `5`: Exit the program

## Security Notes
- Passwords are hashed using bcrypt before storage
- The master password is required to access stored passwords
- All data is stored locally in a JSON file
- Each password is hashed with a unique salt 