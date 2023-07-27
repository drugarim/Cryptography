#include <botan/hex.h>
#include <botan/pwdhash.h>
#include <botan/system_rng.h>
#include <iostream>


/**
 * Documentation: https://github.com/randombit/botan/blob/master/doc/api_ref/pbkdf.rst
 * Example: https://github.com/randombit/botan/blob/master/src/examples/pwdhash.cpp
 * @return
 */
int main() {
    const int AES_KEY_LENGTH = 32;
    const std::string password = "PASSWORD";
    const std::string pbkdf_algo = "PBKDF2(SHA-512)";

    auto key_derivation_function = Botan::PasswordHashFamily::create_or_throw(pbkdf_algo);

    std::vector<uint8_t> salt(16);
    Botan::system_rng().randomize(salt.data(), salt.size());

    std::vector<uint8_t> key(AES_KEY_LENGTH);
    key_derivation_function
            ->default_params()
            ->derive_key(key.data(), key.size(), password.c_str(), password.size(), salt.data(), salt.size());

    std::cout << Botan::hex_encode(key) << "\n";
    return 0;
}
