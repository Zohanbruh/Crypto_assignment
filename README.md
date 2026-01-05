# Secure File Encryption System

A small demo demonstrating secure file encryption using ECDH for key agreement, AES-256-GCM for authenticated encryption, and ECDSA for signing. This project includes a CLI/GUI file selector and a manual decryption mode for demonstration and teaching purposes.

## Features
- ECDH (secp256r1) for symmetric key derivation
- AES-256-GCM for authenticated encryption
- ECDSA (secp256r1) for signing/verifying the encrypted payload
- Manual decryption mode (user supplies nonce and ciphertext hex) for learning/demo

## Usage
From the repository root:

- Non-interactive (use environment variable):
  ```powershell
  $env:AES_INPUT='C:\path\to\file.txt'; python "path/to/import os.py"
  ```

- Interactive GUI file selection will open a dialog to pick a file.

- The script prints the nonce and ciphertext (hex) for manual decryption.

## Testing
- Default test command: `pytest` (no tests included by default).

## Contributing
Contributions welcome — open an issue or a pull request.

## License
This project is licensed under the MIT License — see `LICENSE`.
