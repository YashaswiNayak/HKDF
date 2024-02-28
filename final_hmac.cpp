#include <iostream>
#include <openssl/evp.h>
#include <fstream>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <cstring> // Add this line to include <cstring>
#include <vector>

std::string sha256(const std::string &str, unsigned char* hashBuffer)
{
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new(); // Create an EVP context

    EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr);    // Initialize the digest
    EVP_DigestUpdate(mdctx, str.c_str(), str.length()); // Update with input data
    EVP_DigestFinal_ex(mdctx, hashBuffer, nullptr);     // Finalize and obtain the hash

    EVP_MD_CTX_free(mdctx); // Clean up the context

    std::string hashedString;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
    {
        char hex[3];
        sprintf(hex, "%02x", hashBuffer[i]);
        hashedString += hex;
    }
    return hashedString;
}

bool hkdf(const unsigned char *inputKey, size_t inputKeyLength, unsigned char *outputKey, size_t outputKeyLength)
{
    if (outputKeyLength > EVP_MAX_MD_SIZE)
    {
        std::cerr << "Output key length is too large" << std::endl;
        return false;
    }

    unsigned char prk[EVP_MAX_MD_SIZE];  // Pseudorandom key
    unsigned char temp[EVP_MAX_MD_SIZE]; // Temporary buffer

    // Extract step: Generate the pseudorandom key (prk)
    if (HMAC(EVP_sha256(), inputKey, inputKeyLength, inputKey, inputKeyLength, prk, nullptr) == nullptr)
    {
        std::cerr << "Error in HMAC during extract step" << std::endl;
        return false;
    }

    // Expand step: Derive the output key
    size_t remainingBytes = outputKeyLength;
    size_t outputOffset = 0;
    unsigned char counter = 1;

    while (remainingBytes > 0)
    {
        // Compute HMAC using prk
        if (HMAC(EVP_sha256(), prk, EVP_MD_size(EVP_sha256()), &counter, sizeof(counter), temp, nullptr) == nullptr)
        {
            std::cerr << "Error in HMAC during expand step" << std::endl;
            return false;
        }

        // Copy part of the result into the output key
        size_t bytesToCopy = std::min(remainingBytes, static_cast<size_t>(EVP_MD_size(EVP_sha256()))); // Cast to size_t
        memcpy(outputKey + outputOffset, temp, bytesToCopy);
        outputOffset += bytesToCopy;
        remainingBytes -= bytesToCopy;

        // Increment the counter
        ++counter;
    }

    return true;
}

std::string encrypt(const std::string &plaintext, const unsigned char *key, size_t keyLength) {
    unsigned char iv[EVP_MAX_IV_LENGTH];
    RAND_bytes(iv, EVP_MAX_IV_LENGTH);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv);

    int ciphertextLength = plaintext.length() + EVP_MAX_BLOCK_LENGTH; // Maximum length of ciphertext
    std::vector<unsigned char> ciphertext(ciphertextLength + EVP_MAX_IV_LENGTH);

    int len;
    EVP_EncryptUpdate(ctx, ciphertext.data() + EVP_MAX_IV_LENGTH, &len, (const unsigned char *)plaintext.c_str(), plaintext.length());
    ciphertextLength = len;
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + EVP_MAX_IV_LENGTH + len, &len);
    ciphertextLength += len;

    EVP_CIPHER_CTX_free(ctx);

    memcpy(ciphertext.data(), iv, EVP_MAX_IV_LENGTH); // Prepend IV to ciphertext

    return std::string(reinterpret_cast<char*>(ciphertext.data()), ciphertextLength + EVP_MAX_IV_LENGTH);
}

std::string decrypt(const std::string &ciphertext, const unsigned char *key, size_t keyLength) {
    unsigned char iv[EVP_MAX_IV_LENGTH];
    memcpy(iv, ciphertext.c_str(), EVP_MAX_IV_LENGTH);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv);

    int plaintextLength = ciphertext.length() - EVP_MAX_IV_LENGTH; // Length of actual ciphertext
    std::vector<unsigned char> plaintext(plaintextLength);

    int len;
    EVP_DecryptUpdate(ctx, plaintext.data(), &len, (const unsigned char *)ciphertext.c_str() + EVP_MAX_IV_LENGTH, plaintextLength);
    plaintextLength = len;
    EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    plaintextLength += len;

    EVP_CIPHER_CTX_free(ctx);

    return std::string(reinterpret_cast<char*>(plaintext.data()), plaintextLength);
}


int main() {
    // Read the content of the file "signature.json"
    std::ifstream file("signature.json");
    if (!file.is_open()) {
        std::cerr << "Failed to open file 'signature.json'" << std::endl;
        return 1;
    }

    std::string jsonData((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();

    // Hash the JSON data to derive the key
    unsigned char hashBuffer[SHA256_DIGEST_LENGTH];
    std::string seed = sha256(jsonData, hashBuffer);
    const unsigned char *inputKey = reinterpret_cast<const unsigned char *>(seed.c_str());
    const size_t inputKeyLength = strlen((const char *)inputKey);
    const size_t outputKeyLength = 64; // Desired output key length in bytes
    unsigned char outputKey[outputKeyLength];

    // Derive the key using HKDF
    if (!hkdf(inputKey, inputKeyLength, outputKey, outputKeyLength)) {
        std::cerr << "Key derivation failed" << std::endl;
        return 1;
    }

    // Print the derived key
    std::cout << "Derived Key: ";
    for (size_t i = 0; i < outputKeyLength; ++i) {
        printf("%02x", outputKey[i]);
    }
    std::cout << std::endl;

    // Test encryption and decryption
    std::string plaintext = "Hello, World!";
    std::string encrypted = encrypt(plaintext, outputKey, outputKeyLength);
    std::cout << "Encrypted: " << encrypted << std::endl;

    std::string decrypted = decrypt(encrypted, outputKey, outputKeyLength);
    std::cout << "Decrypted: " << decrypted << std::endl;

    return 0;
}
