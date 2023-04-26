
import json
from Crypto.Cipher import AES

AES_KEY = [0x50, 0x96, 0x22, 0x66, 0x70, 0x79, 0x60, 0x66, 0x31, 0x70, 0x68, 0x80, 0x33, 0x18, 0x28, 0x66]
print(f'\nArrayLetters          : {bytes(AES_KEY)}')
print(f'\nByte Key Length       : {len(AES_KEY)}')

BLOCK_SIZE = 16
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)

def doEncrypt():
    strFilePath = "./sample-encrypt-Python.txt"
    fileName = "Pipfile"
    with open(fileName,'r',encoding='utf8') as f:
        temp=f.readlines()
        data=""
        for i in temp:
            data+=i+'\n'
        dataDict = {
            "o2": 99,
            "pr": 92,
            "datetime": "2022-05-22 09:33:07",
            "sn": "7533967"
        }


        cipher = AES.new(bytes(AES_KEY), AES.MODE_ECB)
        # test=json.dumps(dataDict)
        # cipheredData = cipher.encrypt(pad(test).encode("utf8"))
        cipheredData = cipher.encrypt(pad(data).encode("utf8"))

    with open(strFilePath, "wb") as f:
        f.write(cipheredData)
        
doEncrypt()