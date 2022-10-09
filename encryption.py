import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES
from argon2 import PasswordHasher


class AESCipher:
    def __init__(self, key):
        self.bs = AES.block_size
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw):
        raw += 'Hello World!@123'
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw.encode()))

    def decrypt(self, enc):
        try:
            enc = base64.b64decode(enc)
            iv = enc[:AES.block_size]
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            dec = self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')
            if str(dec).endswith('Hello World!@123'):
                return dec[:-16]
            return False

        except Exception:
            return False

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]



def argon2_hash(password):
    ph = PasswordHasher()
    return ph.hash(password)


def argon2_verify(h, password):
    ph = PasswordHasher()
    try:
        return ph.verify(h, password)
    except Exception:
        return False



if __name__ == '__main__':
    hash = argon2_hash("autotasks2526")
    print(type(hash))
    print(argon2_verify(hash, "autotasks2526"))







