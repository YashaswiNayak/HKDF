#include <iostream>
#include <openssl/evp.h>
#include <fstream>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <string.h>

std::string sha256(const std::string &str)
{
    unsigned char hash[EVP_MAX_MD_SIZE];  // Use EVP_MAX_MD_SIZE for hash buffer
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new(); // Create an EVP context

    EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr);    // Initialize the digest
    EVP_DigestUpdate(mdctx, str.c_str(), str.length()); // Update with input data
    EVP_DigestFinal_ex(mdctx, hash, nullptr);           // Finalize and obtain the hash

    EVP_MD_CTX_free(mdctx); // Clean up the context

    std::string hashedString;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
    {
        char hex[3];
        sprintf(hex, "%02x", hash[i]);
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

int main()
{
    std::ifstream file("signature.json");
    std::string jsonData((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();
    std::string seed = sha256(jsonData);
    const unsigned char *inputKey = reinterpret_cast<const unsigned char *>(seed.c_str());

    const size_t inputKeyLength = strlen((const char *)inputKey);

    const size_t outputKeyLength = 64; // Desired output key length in bytes

    unsigned char outputKey[outputKeyLength];

    if (hkdf(inputKey, inputKeyLength, outputKey, outputKeyLength))
    {
        std::cout << "Derived Key: ";
        for (size_t i = 0; i < outputKeyLength; ++i)
        {
            printf("%02x", outputKey[i]);
        }
        std::cout << std::endl;
    }
    else
    {
        std::cerr << "Key derivation failed" << std::endl;
        return 1;
    }

    return 0;
}
