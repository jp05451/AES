#ifndef AES_HPP
#define AES_HPP
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <cstdint>
#include <memory>
#include <cstring>
#include <stdexcept>
#include <iostream>

class AES
{
public:
    AES();
    ~AES();
    void setKey(unsigned char *key, size_t keyLength);
    void encrypt(unsigned char *input, unsigned char *output, size_t len);
    std::string encrypt(const std::string &input);
    void decrypt(unsigned char *input, unsigned char *output, size_t len);
    std::string decrypt(const std::string &input);
    void generateIV(unsigned char *iv);
    void setIV(unsigned char *iv);
    const unsigned char *getIV();
    void dumpIV();

private:
    AES_KEY encryptKey, decryptKey;
    unsigned char iv[AES_BLOCK_SIZE];
};

#endif // AES_HPP