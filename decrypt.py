
from Crypto.Cipher import AES

AES_KEY = [0x50, 0x96, 0x22, 0x66, 0x70, 0x79, 0x60, 0x66, 0x31, 0x70, 0x68, 0x80, 0x33, 0x18, 0x28, 0x66]
print(f'\nArrayLetters          : {bytes(AES_KEY)}')
print(f'\nByte Key Length       : {len(AES_KEY)}')

def doDecrypt():
    strFilePath = "./sample-encrypt-Python.txt"

    in_file = open(strFilePath, "rb")
    data = in_file.read()
    in_file.close()
    print(f'\ndata                    : {data}')
    print(f'\ndata-length             : {len(data)}')

    cipher = AES.new(bytes(AES_KEY), AES.MODE_ECB)
    decrypted = cipher.decrypt(data)

    with open("raw.txt",'w+',encoding='utf8') as f:
        # f.write(decrypted.decode('utf-8'))

        print(f'\ndecrypted               : {decrypted}')
        print(f'\ndecrypted-length        : {len(decrypted)}')

        string = decrypted.decode('utf-8')
        f.write(string)
        
        print(f'\ndecrypted-string        : {string}')
        print(f'\ndecrypted-string-length : {len(string)}')

doDecrypt()