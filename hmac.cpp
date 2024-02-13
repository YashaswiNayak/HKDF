#include <iostream>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <string.h>

bool deriveKey(const unsigned char *inputKey, size_t inputKeyLength, unsigned char *salt, size_t saltLength, unsigned char *outputKey, size_t outputKeyLength) {
    if (outputKeyLength > EVP_MAX_MD_SIZE) {
        std::cerr << "Output key length is too large" << std::endl;
        return false;
    }

    // Check for valid input key length
    if (inputKeyLength == 0) {
        std::cerr << "Input key length must be non-zero" << std::endl;
        return false;
    }

    // Generate a random salt
    if (RAND_bytes(salt, saltLength) != 1) {
        std::cerr << "Error generating random salt" << std::endl;
        return false;
    }

    // Perform HMAC computation
    if (HMAC(EVP_sha256(), inputKey, inputKeyLength, salt, saltLength, outputKey, nullptr) == nullptr) {
        std::cerr << "Error in HMAC" << std::endl;
        return false;
    }

    // Clear the input key from memory
    OPENSSL_cleanse(const_cast<unsigned char*>(inputKey), inputKeyLength);

    return true;
}

int main() {
    // Secret input key (should be securely generated)
    const unsigned char inputKey[] = "MySecretKey";
    const size_t inputKeyLength = strlen((const char *) inputKey);

    // Length of the salt in bytes (you can adjust as needed)
    const size_t saltLength = 32;

    // Desired output key length in bytes
    const size_t outputKeyLength = 32;

    unsigned char salt[saltLength];
    unsigned char outputKey[outputKeyLength];

    // Derive the key
    if (deriveKey(inputKey, inputKeyLength, salt, saltLength, outputKey, outputKeyLength)) {
        // Print salt
        std::cout << "Salt: ";
        for (size_t i = 0; i < saltLength; ++i) {
            printf("%02x", salt[i]);
        }
        std::cout << std::endl;

        // Print derived key
        std::cout << "Derived Key: ";
        for (size_t i = 0; i < outputKeyLength; ++i) {
            printf("%02x", outputKey[i]);
        }
        std::cout << std::endl;
        
        // Clear sensitive data from memory
        OPENSSL_cleanse(salt, saltLength);
        OPENSSL_cleanse(outputKey, outputKeyLength);
    } else {
        std::cerr << "Key derivation failed" << std::endl;
        return 1;
    }

    return 0;
}