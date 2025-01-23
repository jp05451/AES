try:
    from Cryptodome.PublicKey import ECC
    from Cryptodome.Hash import SHAKE128, SHA256
    from Cryptodome.Protocol.DH import key_agreement
    from Cryptodome.Cipher import AES
except:
    from Crypto.PublicKey import ECC
    from Crypto.Hash import SHAKE128, SHA256
    from Crypto.Protocol.DH import key_agreement
    from Crypto.Cipher import AES

from base64 import b64encode, b64decode
import socket
import sys
import json


def Encrypt(data, key, nonce):
    if nonce is None:
        # create nonce
        cipher = AES.new(key, AES.MODE_GCM)
    else:
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    data = bytes.fromhex(data)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    json_k = ["ciphertext", "tag", "nonce"]
    json_v = [b64encode(x).decode("utf-8") for x in (ciphertext, tag, cipher.nonce)]
    json_data = json.dumps(dict(zip(json_k, json_v)))
    return json_data


def Decrypt(data, key):
    b64 = json.loads(data.decode("utf-8"))
    json_k = ["ciphertext", "tag", "nonce"]
    json_v = {x: b64decode(b64[x]) for x in json_k}
    # print(json_v)
    cipher = AES.new(key, AES.MODE_GCM, nonce=json_v["nonce"])
    plaintext = cipher.decrypt_and_verify(json_v["ciphertext"], json_v["tag"])
    result_k = ["plaintext", "nonce"]
    result_v = [plaintext, cipher.nonce]
    result_data = dict(zip(result_k, result_v))
    return result_data
