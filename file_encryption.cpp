#include <iostream>
#include <fstream>
#include <botan/botan.h>
#include <botan/system_rng.h>
#include <botan/aes.h>
#include <botan/hex.h>
#include <botan/pbkdf.h>
#include "botan/pwdhash.h"

// Random number generator
Botan::System_RNG rng;

// AES-256 Initialization Vector size in bytes (128/8=16)
size_t AES_IV_LENGTH = 16;

// AES-256 Initialization Vector size in bytes (128/8=16)
size_t BLOCK_SIZE = 4096;

// AES-256 key size in bytes (256/8=32)
size_t AES_KEY_LENGTH = 32;

std::vector<uint8_t> deriveKey(const std::string& password, std::vector<uint8_t>& salt)
{
    const std::string pbkdf_algo = "PBKDF2(SHA-512)";
    auto key_derivation_function = Botan::PasswordHashFamily::create_or_throw(pbkdf_algo);

    std::vector<uint8_t> key(AES_KEY_LENGTH);
    key_derivation_function
            ->default_params()
            ->derive_key(key.data(), key.size(), password.c_str(), password.size(), salt.data(), salt.size());
    return key;
}

void encrypt(const std::string& plaintextFilename, const std::string& ciphertextFilename, const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv, const std::vector<uint8_t>& salt)
{
    // Create input and output file streams
    std::ifstream inputFile(plaintextFilename, std::ios::binary);
    if (!inputFile){
        std::cerr << "Error: Unable to open input file: " << plaintextFilename << std::endl;
        return;
    }

    std::ofstream outputFile(ciphertextFilename, std::ios::binary | std::ios::out);
    if (!outputFile){
        std::cerr << "Error: Unable to open output file: " << ciphertextFilename << std::endl;
        return;
    }

    // Create the object that performs the encryption (AES-256, GCM mode)
    std::unique_ptr<Botan::Cipher_Mode> enc = Botan::Cipher_Mode::create("AES-256/GCM", Botan::Cipher_Dir::ENCRYPTION);
    enc->set_key(key);

    // Write the salt to the output file
    outputFile.write(reinterpret_cast<const char*>(salt.data()), salt.size());

    // Header for GCM
    outputFile.write(reinterpret_cast<const char*>(iv.data()), AES_IV_LENGTH);

    // Read data from input file and encrypt it
    Botan::secure_vector<uint8_t> buffer(BLOCK_SIZE); // Buffer size for reading data

    while (!inputFile.eof())
    {
        inputFile.read(reinterpret_cast<char*>(buffer.data()), BLOCK_SIZE);
        size_t bytesRead = inputFile.gcount();

        buffer.resize(bytesRead);
        enc->start(iv);
        enc->finish(buffer);

        // Write encrypted data to output file
        outputFile.write(reinterpret_cast<const char*>(buffer.data()), buffer.size());
    }

    // Close file streams
    inputFile.close();
    outputFile.close();
}

void startEncryption(const std::string& plaintextFilename, const std::string& ciphertextFilename, const std::string& password)
{
    // Generate a random salt
    std::vector<uint8_t> salt(16);
    rng.randomize(salt.data(), salt.size());

    // Derive the key from the password and salt
    std::vector<uint8_t> key = deriveKey(password, salt);

    // Generate a random IV
    std::vector<uint8_t> iv(AES_IV_LENGTH);
    rng.randomize(iv.data(), iv.size());

    // Encrypt the file and pass the salt to the function
    encrypt(plaintextFilename, ciphertextFilename, key, iv, salt);

    std::cout << "File encrypted." << std::endl;
}

void decrypt(const std::string& ciphertextFilename, const std::string& decryptionResultFile, const std::vector<uint8_t>& key)
{
    // Create input and output file streams
    std::ifstream ciphertextStream(ciphertextFilename, std::ios::binary);
    if (!ciphertextStream)
    {
        std::cerr << "Error: Unable to open input file: " << ciphertextFilename << std::endl;
        return;
    }
    std::ofstream decryptionResultStream(decryptionResultFile, std::ios::binary | std::ios::out);
    if (!decryptionResultStream)
    {
        std::cerr << "Error: Unable to open output file: " << decryptionResultFile << std::endl;
        ciphertextStream.close();
        return;
    }

    // Read the salt from the input file
    std::vector<uint8_t> salt(16);
    ciphertextStream.read(reinterpret_cast<char*>(salt.data()), salt.size());

    // Read the IV from the input file
    std::vector<uint8_t> iv(AES_IV_LENGTH);
    ciphertextStream.read(reinterpret_cast<char*>(iv.data()), iv.size());

    // Create the object that performs the decryption (AES-256, GCM mode)
    std::unique_ptr<Botan::Cipher_Mode> decrypt = Botan::Cipher_Mode::create("AES-256/GCM", Botan::Cipher_Dir::DECRYPTION);
    decrypt->set_key(key);

    // Read data from input file and decrypt it
    Botan::secure_vector<uint8_t> ciphertextBuffer(BLOCK_SIZE + 16);

    while (!ciphertextStream.eof())
    {
        ciphertextBuffer.resize(BLOCK_SIZE + 16);
        ciphertextStream.read(reinterpret_cast<char*>(ciphertextBuffer.data()), BLOCK_SIZE + 16);
        size_t bytesRead = ciphertextStream.gcount();
        ciphertextBuffer.resize(bytesRead);

        // Set the IV from the header
        decrypt->start(iv);
        decrypt->finish(ciphertextBuffer);

        // Write decrypted data to output file
        decryptionResultStream.write(reinterpret_cast<const char*>(ciphertextBuffer.data()), ciphertextBuffer.size());
    }

    // Close file streams
    ciphertextStream.close();
    decryptionResultStream.close();
}

void startDecryption(const std::string& ciphertextFilename, const std::string& decryptionResultFile, const std::string& password)
{
    // Create input and output file streams
    std::ifstream ciphertextStream(ciphertextFilename, std::ios::binary);
    if (!ciphertextStream)
    {
        std::cerr << "Error: Unable to open input file: " << ciphertextFilename << std::endl;
        return;
    }
    std::ofstream decryptionResultStream(decryptionResultFile, std::ios::binary | std::ios::out);
    if (!decryptionResultStream)
    {
        std::cerr << "Error: Unable to open output file: " << decryptionResultFile << std::endl;
        ciphertextStream.close();
        return;
    }

    // Read the salt from the input file
    std::vector<uint8_t> salt(16);
    ciphertextStream.read(reinterpret_cast<char*>(salt.data()), salt.size());

    // Derive the key from the password and the read salt
    std::vector<uint8_t> key = deriveKey(password, salt);

    // Decrypt the file
    decrypt(ciphertextFilename, decryptionResultFile, key);

    std::cout << "File decrypted." << std::endl;

    // Close file streams
    ciphertextStream.close();
    decryptionResultStream.close();
}

int main()
{
    // Ask the user for the password
    std::string password;
    std::cout << "Enter password to encrypt: ";
    std::cin >> password;


    // Encryption
    std::string plaintextFilename;
    std::cout << "Enter the name of the file to encrypt: ";
    std::cin >> plaintextFilename;
    std::string ciphertextFilename = "cipheredText.txt";

    startEncryption(plaintextFilename, ciphertextFilename, password);

    // Decryption
    std::string decryptionResultFile;
    std::cout << "Enter name of file to store the decrypted text; ";
    std::cin >> decryptionResultFile;

    // if password is incorrect, allow only 3 attempts
    bool passwordMatched = false;
    for (int i = 0; i < 3; ++i)
    {
        std::string decryptPassword;
        std::cout << "Enter the password for decryption: ";
        std::cin >> decryptPassword;

        // Verify the password for decryption before starting the decryption process
        if (password == decryptPassword)
        {
            passwordMatched = true;
            break;
        }
        else
        {
            std::cerr << "Error: Incorrect password. Please try again." << std::endl;
        }
    }

    // Check if password is correct
    if (passwordMatched)
    {
        startDecryption(ciphertextFilename, decryptionResultFile, password);
    }
    else
    {
        std::cerr << "Error: Maximum number of attempts reached. Exiting..." << std::endl;
    }

    return 0;
}
