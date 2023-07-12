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

// AES-256 key size in bytes (256/8=32)
size_t AES_KEY_LENGTH = 32;

void encrypt(const std::string& plaintextFilename, const std::string& ciphertextFilename, const std::vector<uint8_t> &key, const std::vector<uint8_t> &iv)
{
    // Create input and output file streams
    std::ifstream inputFile(plaintextFilename, std::ios::binary);
    std::ofstream outputFile(ciphertextFilename, std::ios::binary);

    // Create the object that performs the encryption (AES-256, GCM mode)
    std::unique_ptr<Botan::Cipher_Mode> enc= Botan::Cipher_Mode::create("AES-256/GCM", Botan::Cipher_Dir::ENCRYPTION);
    enc->set_key(key);

    // Read data from input file and encrypt it
    Botan::secure_vector<uint8_t> buffer(4096); // Buffer size for reading data
    // outputFile.write(reinterpret_cast<const char*>(iv.data()), iv.size());
    while (!inputFile.eof()) {
        inputFile.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
        buffer.resize(inputFile.gcount());

        // size_t bytesRead = inputFile.gcount();
        enc->start(iv);
        // Botan::secure_vector<uint8_t> ciphertext;
        enc->finish(buffer);

        // Write encrypted data to output file
        outputFile.write(reinterpret_cast<const char*>(buffer.data()), buffer.size());
    }
    // Close file streams
    inputFile.close();
    outputFile.close();
}

void decrypt(const std::string& ciphertextFilename, const std::string& plaintextFilename, const std::vector<uint8_t> &key, const std::vector<uint8_t> &iv)
{
    // Create input and output file streams
    std::ifstream ciphertextStream(ciphertextFilename, std::ios::binary);
    std::ofstream plaintextStream(plaintextFilename, std::ios::binary);

    // Create the object that performs the decryption (AES-256,GCM mode)
    std::unique_ptr<Botan::Cipher_Mode> decrypt = Botan::Cipher_Mode::create("AES-256/GCM", Botan::Cipher_Dir::DECRYPTION);
    decrypt->set_key(key);

    // Read data from input file and decrypt it
   Botan::secure_vector<uint8_t> ciphertextBuffer(4096); // Buffer size for reading data
    while (!ciphertextStream.eof()) {
        ciphertextStream.read(reinterpret_cast<char*>(ciphertextBuffer.data()), ciphertextBuffer.size());
        ciphertextBuffer.resize(ciphertextStream.gcount());
        // size_t bytesRead = ;

        // Botan::secure_vector<uint8_t> plaintext(4096);
        decrypt->start(iv);
        decrypt->finish(ciphertextBuffer);
        // Write decrypted data to output file
        plaintextStream.write(reinterpret_cast<const char*>(ciphertextBuffer.data()), ciphertextBuffer.size()); 
    }

    // Close file streams
    ciphertextStream.close();
    plaintextStream.close();
}

int main()
{
    std::string plaintextFilename = "input.txt";
    std::string ciphertextFilename = "output.txt";
    std::string plainText = "Cryptography is really hard!";

    // Create Initialization Vector by randomizing an array of 256 bits
    std::vector<uint8_t> key(AES_KEY_LENGTH);
    rng.randomize(key.data(), key.size());

    // Create Initialization Vector by randomizing an array of 128 bits
    std::vector<uint8_t> iv(AES_IV_LENGTH);
    rng.randomize(iv.data(), iv.size());

    // Write plain text to input file
    std::ofstream inputFile(plaintextFilename, std::ios::binary);
    inputFile.write(plainText.c_str(), plainText.size());
    inputFile.close();

    // Encrypt input file
    encrypt(plaintextFilename, ciphertextFilename, key, iv);
    std::cout << "File encrypted." << std::endl;

    // Decrypt encrypted file
    decrypt(ciphertextFilename, plaintextFilename, key, iv);
    std::cout << "File decrypted." << std::endl;

    // Read decrypted data from file
    std::ifstream decryptedFile(plaintextFilename, std::ios::binary);
    std::ifstream encryptedFile(ciphertextFilename, std::ios::binary);
    std::string decryptedData((std::istreambuf_iterator<char>(decryptedFile)), std::istreambuf_iterator<char>());
    std::string encryptedData((std::istreambuf_iterator<char>(encryptedFile)), std::istreambuf_iterator<char>());
    decryptedFile.close();
    encryptedFile.close();

    std::cout << "Cipher data: " << encryptedData << std::endl;
    std::cout << "Decrypted data: " << decryptedData << std::endl;

    return 0;
}

