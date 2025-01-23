#include <openssl/aes.h>
#include "aes.hpp"

using namespace std;

AES::AES()
{
    AES_set_encrypt_key(0x00, 128, &this->encryptKey);
    AES_set_decrypt_key(0x00, 128, &this->decryptKey);
}

AES::~AES()
{
    AES_set_encrypt_key(0x00, 128, &this->encryptKey);
    AES_set_decrypt_key(0x00, 128, &this->decryptKey);
}

void AES::setKey(unsigned char *key, size_t keyLength = 256)
{
    try
    {
        if (key == nullptr || (keyLength != 128 && keyLength != 192 && keyLength != 256))
        {
            throw invalid_argument("Invalid key or key length");
        }
        else if (keyLength == 128 && strlen((const char *)key) != 16)
        {
            throw invalid_argument("Key length does not match 128-bit key size");
        }
        else if (keyLength == 192 && strlen((const char *)key) != 24)
        {
            throw invalid_argument("Key length does not match 192-bit key size");
        }
        else if (keyLength == 256 && strlen((const char *)key) != 32)
        {
            throw invalid_argument("Key length does not match 256-bit key size");
        }
        else
        {
            AES_set_encrypt_key(key, keyLength, &this->encryptKey);
            AES_set_decrypt_key(key, keyLength, &this->decryptKey);
        }
    }
    catch (const invalid_argument &e)
    {
        cout << e.what() << endl;
    }
}

string AES::encrypt(const string &input)
{
    // backup iv
    unsigned char iv[AES_BLOCK_SIZE];
    memcpy(iv, &this->iv, AES_BLOCK_SIZE);

    size_t len = input.length();
    unsigned char *outputBuffer = new unsigned char[len*2];
    unsigned char *inputBuffer = (unsigned char *)input.c_str();

    AES_cbc_encrypt(inputBuffer, outputBuffer, len, &this->encryptKey, iv, AES_ENCRYPT);
    string output((char *)outputBuffer);
    delete[] outputBuffer;
    return output;
}

void AES::encrypt(unsigned char *input, unsigned char *output, size_t len)
{
    unsigned char iv[AES_BLOCK_SIZE];
    memcpy(iv, &this->iv, AES_BLOCK_SIZE);
    AES_cbc_encrypt(input, output, len, &this->encryptKey, iv, AES_ENCRYPT);
}

void AES::decrypt(unsigned char *input, unsigned char *output, size_t len)
{
    AES_cbc_encrypt(input, output, len, &this->decryptKey, this->iv, AES_DECRYPT);
}

string AES::decrypt(const string &input)
{
    size_t len = input.length();
    unsigned char *inputBuffer = (unsigned char *)input.c_str();
    unsigned char *outputBuffer = new unsigned char[len];

    AES_cbc_encrypt(inputBuffer, outputBuffer, len, &this->decryptKey, this->iv, AES_DECRYPT);
    string output((char *)outputBuffer);
    delete[] outputBuffer;

    return output;
}

void AES::generateIV(unsigned char *iv)
{
    RAND_bytes(iv, AES_BLOCK_SIZE);
}

void AES::setIV(unsigned char *iv)
{
    memcpy(this->iv, iv, AES_BLOCK_SIZE);
}

int main()
{
    unsigned char key[33] = "thisisaverysecurekey123456789012";
    unsigned char iv[AES_BLOCK_SIZE];
    memset(iv, 0xff, AES_BLOCK_SIZE);

    unsigned char plaintext[1024] = "Hello, World!!! This is a test message to check the AES encryption and decryption.";
    unsigned char ciphertext[1024] = {'\0'};
    unsigned char decryptedtext[1024] = {'\0'};

    AES aes;
    aes.setKey(key, 256);
    aes.setIV(iv);

    // cout << "Plaintext: " << plaintext << endl;

    // aes.encrypt(plaintext, ciphertext, strlen((const char *)plaintext));
    // cout << "Ciphertext: ";
    // for (int i = 0; i < 98; i++)
    // {
    //     for (int j = 7; j >= 0; --j)
    //     {
    //         printf("%d", (ciphertext[i] >> j) & 1);
    //     }
    //     printf(" ");
    // }

    // cout << endl;

    // memset(iv, 0xff, AES_BLOCK_SIZE); // Reset IV for decryption
    // aes.decrypt(ciphertext, decryptedtext, strlen((const char *)plaintext));
    // cout << "Decrypted text: " << decryptedtext << endl;
    printf("Plaintext: %s\n", plaintext);

    string encrypted = aes.encrypt((const char *)plaintext);
    cout << "Encrypted: " << encrypted << endl;
    string decrypted = aes.decrypt(encrypted);
    cout << "Decrypted: " << decrypted << endl;

    return 0;
}