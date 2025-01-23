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
    // aes.generateIV(iv);
    // aes.setIV(iv);

    for (int i = 0; i < 5; i++)
    {
        cout<<"========== Iteration: "<<i<<" =============="<<endl;
        cout << "Plaintext: " << plaintext << endl;
        aes.dumpIV();

        string encrypted = aes.encrypt((const char *)plaintext);
        cout << "Encrypted: " << encrypted << endl;
        string decrypted = aes.decrypt(encrypted);
        cout << "Decrypted: " << decrypted << endl;
        aes.dumpIV();
    }
    return 0;
}