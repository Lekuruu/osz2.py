
from .simple_cryptor import SimpleCryptor
from . import crypto
from typing import List
import numpy as np
import struct

TEA_DELTA = 0x9E3779B9
TEA_ROUNDS = 32

class XTEA:
    """XTEA implements the Extended Tiny Encryption Algorithm"""

    def __init__(self, key: List[int]) -> None:
        self.key = np.array(key, dtype=np.uint32)
        self.cryptor = SimpleCryptor(key)

    def decrypt(self, buffer: bytearray, start: int, count: int) -> None:
        self._encrypt_decrypt(buffer, start, count, False)

    def encrypt(self, buffer: bytearray, start: int, count: int) -> None:
        self._encrypt_decrypt(buffer, start, count, True)

    def _encrypt_decrypt(self, buffer: bytearray, buf_start: int, count: int, encrypt: bool) -> None:
        full_word_count = count // 8
        left_over = count % 8

        # Process full 8-byte words
        for i in range(full_word_count):
            offset = buf_start + i * 8
            v0 = struct.unpack_from('<I', buffer, offset)[0]
            v1 = struct.unpack_from('<I', buffer, offset + 4)[0]

            if encrypt:
                v0, v1 = self._encrypt_word(v0, v1)
            else:
                v0, v1 = self._decrypt_word(v0, v1)

            struct.pack_into('<I', buffer, offset, v0)
            struct.pack_into('<I', buffer, offset + 4, v1)

        # Handle leftover bytes
        if left_over > 0:
            leftover_start = buf_start + full_word_count * 8
            leftover_buf = buffer[leftover_start:leftover_start + left_over]

            if encrypt:
                self.cryptor.encrypt_bytes(leftover_buf)
            else:
                self.cryptor.decrypt_bytes(leftover_buf)

            buffer[leftover_start:leftover_start + left_over] = leftover_buf

    def _encrypt_word(self, v0: int, v1: int) -> tuple:
        return crypto.xtea_encrypt_word(v0, v1, self.key)

    def _decrypt_word(self, v0: int, v1: int) -> tuple:
        return crypto.xtea_decrypt_word(v0, v1, self.key)
