#include "aes.hpp"

using namespace std;

int main()
{
    unsigned char key[33] = "12345678901234567890123456789012";
    unsigned char iv[AES_BLOCK_SIZE];

    unsigned char plaintext[1024] = "Hello, World!!! This is a test message to check the AES encryption and decryption.";
    unsigned char ciphertext[1024] = {'\0'};
    unsigned char decryptedtext[1024] = {'\0'};

    AES aes;
    aes.setKey(key, 256);

    aes.generateIV(iv);
    aes.setIV(iv);
    for (int i = 0; i < 10; i++)
    {
        printf("================Iteration %d==============\n", i);
        aes.dumpIV();
        // aes.encrypt(plaintext, ciphertext, strlen((const char *)plaintext));
        string cypher = aes.encrypt((const char *)plaintext);
        // aes.decrypt(ciphertext, decryptedtext, strlen((const char *)ciphertext));
        string decryptedtext = aes.decrypt(cypher);
        // if(strcmp((const char *)plaintext, (const char *)decryptedtext) != 0)
        if(strcmp((const char *)plaintext, decryptedtext.c_str()) != 0)
        {
            cout << "Plaintext: " << plaintext << endl;
            cout << "Ciphertext: " << ciphertext << endl;
            cout << "Decryptedtext: " << decryptedtext << endl;
        }
        else
        {
            cout << "Success" << endl;
        }
        aes.dumpIV();

        // cout << "Plaintext: " << plaintext << endl;
        // cout << "Ciphertext: " << ciphertext << endl;
        // cout << "Decryptedtext: " << decryptedtext << endl;
    }
    return 0;
}