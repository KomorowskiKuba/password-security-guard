from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


class PasswordEncrypter:
    @staticmethod
    def encrypt(plain_text, key):
        cipher = AES.new(key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(plain_text, AES.block_size))
        iv = b64encode(cipher.iv).decode('utf-8')
        ct = b64encode(ct_bytes).decode('utf-8')
        return iv, ct

    @staticmethod
    def decrypt(encrypted_text, iv, key):
        iv = b64decode(iv)
        encrypted_text = b64decode(encrypted_text)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(encrypted_text), AES.block_size)

        return pt


data = b'secret_message'
k = get_random_bytes(16) # TODO: ADD HASH ENCRYPTION AND BRUTEFORCE LIKE DECRYPTION

iv, ct = PasswordEncrypter.encrypt(data, k)
print('Encrypted:', ct)

plain_t = PasswordEncrypter.decrypt(ct, iv, k)
print('Decrypted:', plain_t)