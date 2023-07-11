#include <iostream>
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

void encrypt(Botan::secure_vector<uint8_t> &buffer, const std::vector<uint8_t> &key, const std::vector<uint8_t> &iv)
{
    // Create the object that performs the encryption (AES-256, GCM mode)
    std::unique_ptr<Botan::Cipher_Mode> enc = Botan::Cipher_Mode::create("AES-256/GCM", Botan::Cipher_Dir::ENCRYPTION);
    enc->set_key(key);

    enc->start(iv);
    enc->finish(buffer);
}

void decrypt(Botan::secure_vector<uint8_t> &ciphertext, const std::vector<uint8_t> &key, const std::vector<uint8_t> &iv)
{
    // Create the object that performs the encryption (AES-256, GCM mode)
    std::unique_ptr<Botan::Cipher_Mode> enc = Botan::Cipher_Mode::create("AES-256/GCM", Botan::Cipher_Dir::DECRYPTION);
    enc->set_key(key);

    enc->start(iv);
    enc->finish(ciphertext);
}

int main()
{
    Botan::secure_vector<uint8_t> buffer;
    std::string plain_text = "At first I was afraid, I was petrified";

    // Create Initialization Vector by randomizing an array of 128 bits
    std::vector<uint8_t> key(AES_KEY_LENGTH);
    rng.randomize(key.data(), key.size());

    // Create Initialization Vector by randomizing an array of 128 bits
    std::vector<uint8_t> iv(AES_IV_LENGTH);
    rng.randomize(iv.data(), iv.size());

    // Copy input data to a buffer that will be encrypted
    buffer.insert(buffer.begin(), plain_text.begin(), plain_text.end());

    encrypt(buffer, key, iv);
    std::cout << "CIPHERTEXT:\t" << Botan::hex_encode(buffer) << std::endl;

    decrypt(buffer, key, iv);
    std::string plainText(buffer.begin(), buffer.end());
    std::cout << "PLAINTEXT:\t" << plainText << std::endl;
}
