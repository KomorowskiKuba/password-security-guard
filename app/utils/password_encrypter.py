from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


class PasswordEncrypter:
    @staticmethod
    def encrypt(plain_text, key, iv):
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        ct_bytes = cipher.encrypt(pad(plain_text, AES.block_size))
        ct = b64encode(ct_bytes).decode('utf-8')
        return ct

    @staticmethod
    def decrypt(encrypted_text, key, iv):
        encrypted_text = b64decode(encrypted_text)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(encrypted_text), AES.block_size)

        return pt


# data = 'secret_message'.encode()
# k = get_random_bytes(16) # TODO: ADD HASH ENCRYPTION AND BRUTEFORCE LIKE DECRYPTION
# iv = get_random_bytes(16)
#
# import json
# f = open('../secrets.json')
# json_data = json.load(f)
#
# k = b64decode(json_data['password_key'])
# iv = b64decode(json_data['password_iv'])
#
#
# ct = PasswordEncrypter.encrypt(data, k, iv)
# print('Encrypted:', ct)
#
# plain_t = PasswordEncrypter.decrypt(ct, iv, k)
# print('Decrypted:', plain_t.decode())