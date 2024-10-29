# DES Algorithm Implementation - README

This project contains a simple implementation of the **Data Encryption Standard (DES)** algorithm for file encryption and decryption. DES is a symmetric-key algorithm widely used for secure data encryption. This README provides instructions for running the program to encrypt and decrypt files on a Linux system.

## Project Structure
- **g22.exe**: Executable file for encrypting and decrypting files using DES.
- **key.txt**: Text file containing the encryption key.
- **input.txt**: Sample input file (plaintext) to be encrypted.
- **output_encr.txt**: File where encrypted data (ciphertext) is saved.
- **output_decr.txt**: File where decrypted data (retrieved plaintext) is saved.

## Requirements
- **Linux OS**: This implementation is intended to be run on a Linux environment.
- **C++ Compiler**: The code has been compiled to create `g22.exe` as the executable. If recompilation is needed, a C++ compiler such as `g++` is required.

## Running the Program

### Encrypting a File
To encrypt a file, use the following command:
```bash
./g22.exe e key.txt input.txt output_encr.txt
```

- **Explanation**:
  - `e`: Specifies the encryption mode.
  - `key.txt`: The file containing the DES encryption key.
  - `input.txt`: The plaintext file you want to encrypt.
  - `output_encr.txt`: The output file where the encrypted text (ciphertext) will be saved.

### Decrypting a File
To decrypt a file, use the following command:
```bash
./g22.exe d key.txt output_encr.txt output_decr.txt
```

- **Explanation**:
  - `d`: Specifies the decryption mode.
  - `key.txt`: The file containing the DES decryption key (same key as used in encryption).
  - `output_encr.txt`: The file containing the encrypted text.
  - `output_decr.txt`: The output file where the decrypted text (original plaintext) will be saved.

After decryption, `output_decr.txt` should match the contents of `input.txt`, restoring the original plaintext.

## Example Usage
1. **Encrypt**: Run the encryption command to create `output_encr.txt` as the encrypted version of `input.txt`.
   ```bash
   ./g22.exe e key.txt input.txt output_encr.txt
   ```

2. **Decrypt**: Run the decryption command to create `output_decr.txt`, which should match the original plaintext from `input.txt`.
   ```bash
   ./g22.exe d key.txt output_encr.txt output_decr.txt
   ```

## Important Notes
- Ensure that the key in `key.txt` is secure and only known to trusted parties, as DES uses symmetric encryption (same key for both encryption and decryption).
- This implementation is designed for educational purposes and does not cover the full security measures required for production use, as DES has known vulnerabilities.

## Troubleshooting
- Ensure `g22.exe` has executable permissions. If not, set them with:
  ```bash
  chmod +x g22.exe
  ```
- Make sure `key.txt` exists and is accessible, as the program will not run without it.
  