# Cryptography
Encrypting and Decrypting files/strings

This C++ code provides an example of file encryption and decryption using AES-256 in GCM mode. The code uses the Botan cryptography library for key derivation, encryption, and decryption operations. Let's break down the code:

- Includes: The code includes necessary headers for file I/O, AES encryption, and other required Botan headers.

- Constants: The code defines some constants like AES_IV_LENGTH, BLOCK_SIZE, and AES_KEY_LENGTH for AES-256 encryption.

- deriveKey: This function takes a password and a salt as input and derives a key using PBKDF2 with SHA-512 as the hash function. PBKDF2 (Password-Based Key Derivation Function 2) is used to derive a cryptographic key from the password and salt.

- encrypt: This function performs the file encryption. It reads the input plaintext file, encrypts it using AES-256 in GCM mode, and writes the ciphertext to the output file. The function uses the derived key, random IV, and salt to perform encryption.

- startEncryption: This function initiates the encryption process. It generates a random salt, derives a key using the provided password and salt, generates a random IV, and then calls the 'encrypt' function.

- decrypt: This function performs the file decryption. It reads the input ciphertext file, decrypts it using AES-256 in GCM mode, and writes the decrypted data to the output file. The function reads the salt and IV from the ciphertext file and uses the derived key to perform decryption.

- startDecryption: This function initiates the decryption process. It reads the salt from the input ciphertext file, derives the key using the provided password and salt, and then calls the 'decrypt' function.

- main: The main function is the entry point of the program. It takes command-line arguments to specify the operation (encrypt/decrypt) and the input/output file names. The user is prompted to enter a password for encryption or decryption. Then, the respective operation is performed.

Overall, this code provides a basic example of how to use AES-256 in GCM mode for file encryption and decryption with password-based key derivation using PBKDF2. However, keep in mind that security is a complex topic, and this code may not cover all security aspects or best practices. When implementing encryption in a real-world scenario, it's important to consider additional security measures and thoroughly test the code to ensure its correctness and resilience against various attacks.
