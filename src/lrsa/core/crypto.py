"""
AES encryption/decryption matching LRSA's .NET implementation.
Extracted from Software Fix.exe.config:
  AESKey: jdkei3ffkjijut46#$%6y7U8km4p<mdT
  AESIV: 52,*u^yhNjk<./O0
  ConnectionField: PLJoR50KSVLIIiQC
"""

import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


class LRSACrypto:
    # From Software Fix.exe.config
    AES_KEY = b"jdkei3ffkjijut46#$%6y7U8km4p<mdT"
    AES_IV = b"52,*u^yhNjk<./O0"
    CONNECTION_FIELD = "PLJoR50KSVLIIiQC"
    # From webservices.dll (SDE warranty API)
    SDE_USER = "LMSA"
    SDE_PASS = "6en)T;a7R1T;"
    DEFAULT_DECRYPT_PASSWORD = "OSD"

    @staticmethod
    def encrypt(plaintext: str) -> str:
        cipher = AES.new(LRSACrypto.AES_KEY, AES.MODE_CBC, LRSACrypto.AES_IV)
        padded = pad(plaintext.encode("utf-8"), AES.block_size)
        encrypted = cipher.encrypt(padded)
        return base64.b64encode(encrypted).decode("utf-8")

    @staticmethod
    def decrypt(ciphertext_b64: str) -> str:
        cipher = AES.new(LRSACrypto.AES_KEY, AES.MODE_CBC, LRSACrypto.AES_IV)
        encrypted = base64.b64decode(ciphertext_b64)
        decrypted = unpad(cipher.decrypt(encrypted), AES.block_size)
        return decrypted.decode("utf-8")
