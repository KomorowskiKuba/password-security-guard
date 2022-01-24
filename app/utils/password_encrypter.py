from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


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