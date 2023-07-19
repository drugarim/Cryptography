#include <iostream>
#include <fstream>
#include <botan/botan.h>
#include <botan/system_rng.h>
#include <botan/aes.h>
#include <botan/hex.h>

// Random number generator
Botan::System_RNG rng;

// AES-256 Initialization Vector size in bytes (128/8=16)
size_t AES_IV_LENGTH = 16;

// AES-256 Initialization Vector size in bytes (128/8=16)
size_t BLOCK_SIZE = 4096;

// AES-256 key size in bytes (256/8=32)
size_t AES_KEY_LENGTH = 32;

void encrypt(const std::string &plaintextFilename, const std::string &ciphertextFilename, const std::vector<uint8_t> &key, const std::vector<uint8_t> &iv)
{
    // Create input and output file streams
    std::ifstream inputFile(plaintextFilename, std::ios::binary);
    std::ofstream outputFile(ciphertextFilename, std::ios::binary);

    // Create the object that performs the encryption (AES-256, GCM mode)
    std::unique_ptr<Botan::Cipher_Mode> enc = Botan::Cipher_Mode::create("AES-256/GCM", Botan::Cipher_Dir::ENCRYPTION);
    enc->set_key(key);

    // Read data from input file and encrypt it
    Botan::secure_vector<uint8_t> buffer(BLOCK_SIZE); // Buffer size for reading data

    // Header for GCM
    outputFile.write(reinterpret_cast<const char *>(iv.data()), AES_IV_LENGTH);

    while (!inputFile.eof())
    {
        inputFile.read(reinterpret_cast<char *>(buffer.data()), BLOCK_SIZE);
        size_t s = buffer.size();
        size_t bytesRead = inputFile.gcount();

        buffer.resize(bytesRead);
        enc->start(iv);
        enc->finish(buffer);
        s = buffer.size();

        // Write encrypted data to output file
        outputFile.write(reinterpret_cast<const char *>(buffer.data()), buffer.size());
    }
    // Close file streams
    inputFile.close();
    outputFile.close();
}

void startEncryption(std::string plaintextFilename, std::string ciphertextFilename, const std::vector<uint8_t> &key, const std::vector<uint8_t> &iv)
{
    // // Write plain text to input file
    // std::ofstream inputFile(plaintextFilename, std::ios::binary);
    // inputFile.write(plaintextContent.c_str(), plaintextContent.size());
    // inputFile.close();

    // Encryption of file
    encrypt(plaintextFilename, ciphertextFilename, key, iv);
    std::cout << "File encrypted." << std::endl;

    // Displays the contents of the encrypted file on terminal
    std::ifstream encryptedFile(ciphertextFilename, std::ios::binary);
    std::string encryptedData((std::istreambuf_iterator<char>(encryptedFile)), std::istreambuf_iterator<char>());
    encryptedFile.close();
    std::cout << "Cipher data: " << encryptedData << std::endl;
}

void decrypt(const std::string &ciphertextFilename, const std::string &decryptionResultFile, const std::vector<uint8_t> &key, const std::vector<uint8_t> &iv)
{
    // Create input and output file streams
    std::ifstream ciphertextStream(ciphertextFilename, std::ios::binary);
    std::ofstream decryptionResultStream(decryptionResultFile, std::ios::binary);

    // Read the header for GCM
    std::vector<uint8_t> header(AES_IV_LENGTH);
    ciphertextStream.read(reinterpret_cast<char *>(header.data()), AES_IV_LENGTH);

    // Create the object that performs the decryption (AES-256,GCM mode)
    std::unique_ptr<Botan::Cipher_Mode> decrypt = Botan::Cipher_Mode::create("AES-256/GCM", Botan::Cipher_Dir::DECRYPTION);
    decrypt->set_key(key);

    // Read data from input file and decrypt it
    Botan::secure_vector<uint8_t> ciphertextBuffer(BLOCK_SIZE + 16); // Buffer size for reading data

    while (!ciphertextStream.eof())
    {
        ciphertextBuffer.resize(BLOCK_SIZE + 16);
        ciphertextStream.read(reinterpret_cast<char *>(ciphertextBuffer.data()), BLOCK_SIZE + 16);
        size_t bytesRead = ciphertextStream.gcount();
        ciphertextBuffer.resize(bytesRead);
        size_t s = ciphertextBuffer.size();

        // Set the IV from the header
        decrypt->start(header);
        decrypt->finish(ciphertextBuffer);
        s = ciphertextBuffer.size();
        // Write decrypted data to output file
        decryptionResultStream.write(reinterpret_cast<const char *>(ciphertextBuffer.data()), ciphertextBuffer.size());
    }

    // Close file streams
    ciphertextStream.close();
    decryptionResultStream.close();
}

void startDecryption(std::string ciphertextFilename, std::string decryptionResultFile, const std::vector<uint8_t> &key, const std::vector<uint8_t> &iv)
{
    // Decryption of file
    decrypt(ciphertextFilename, decryptionResultFile, key, iv);
    std::cout << "File decrypted." << std::endl;

    // Read decrypted data from file and display it on terminal
    std::ifstream decryptedFile(decryptionResultFile, std::ios::binary);
    std::string decryptedData((std::istreambuf_iterator<char>(decryptedFile)), std::istreambuf_iterator<char>());
    decryptedFile.close();
    std::cout << "Decrypted data: " << decryptedData << std::endl;
}

int main()
{
    // Create Initialization Vector by randomizing an array of 256 bits
    std::vector<uint8_t> key(AES_KEY_LENGTH);
    rng.randomize(key.data(), key.size());

    // Create Initialization Vector by randomizing an array of 128 bits
    std::vector<uint8_t> iv(AES_IV_LENGTH);
    rng.randomize(iv.data(), iv.size());

    // Encrytion
    // std::string plaintextFilename = "plaintext.txt";
    // std::string plaintextContent = "Cryptography is really hard!";
    std::string ciphertextFilename = "ciphertext.txt";

    // ask the user what file they want to encrypt
    std::string plaintextFilename;
    std::cout << "Which file would you like to encrypt: " << std::endl;
    std::cin >> plaintextFilename;

    startEncryption(plaintextFilename, ciphertextFilename, key, iv);

    // Decryption
    std::string decryptionResultFile = "result.txt";
    startDecryption(ciphertextFilename, decryptionResultFile, key, iv);

    return 0;
}
