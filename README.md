# Cryptography
Encrypting and Decrypting files/strings

This C++ code implements a simple file encryption and decryption program using AES-256 in GCM mode and PBKDF2 for key derivation. The program uses the Botan cryptographic library for encryption and decryption operations.

Here's an overview of how the code works:

- The deriveKey function is used to derive the encryption/decryption key from the user-provided password and a randomly generated salt using PBKDF2 with SHA-512 as the underlying hash function.

- The encrypt function takes the filename of the plaintext file, filename for the encrypted output, encryption key, initialization vector (IV), and salt as input. It reads the plaintext file in blocks of size BLOCK_SIZE, encrypts each block using AES-256 in GCM mode, and writes the encrypted data to the output file.

- The startEncryption function generates a random salt and IV, derives the encryption key, and then calls the encrypt function to encrypt the input file.

- The decrypt function takes the filename of the encrypted file, filename for the decrypted output, and the decryption key as input. It reads the encrypted file in blocks of size BLOCK_SIZE + 16 (where 16 is the size of the GCM tag), decrypts each block using AES-256 in GCM mode, and writes the decrypted data to the output file.

- The startDecryption function reads the salt from the encrypted file, derives the decryption key, and then calls the decrypt function to decrypt the file.

- In the main function, the user is prompted to enter the password to encrypt the file. The name of the plaintext file to encrypt is also asked. The encryption process is then started using startEncryption, and the encrypted data is written to "cipheredText.txt."

- For decryption, the user is asked to enter the decryption password. The program allows three attempts to enter the correct password. If the password is correct, the decryption process is started using startDecryption, and the decrypted data is written to the user-provided filename.

- The program uses a random salt and IV for each encryption operation, which adds randomness and security to the encryption process.

Overall, this code provides a basic example of how to use AES-256 in GCM mode for file encryption and decryption with password-based key derivation using PBKDF2. However, keep in mind that security is a complex topic, and this code may not cover all security aspects or best practices. When implementing encryption in a real-world scenario, it's important to consider additional security measures and thoroughly test the code to ensure its correctness and resilience against various attacks.
