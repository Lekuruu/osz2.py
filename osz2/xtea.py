
from .simple_cryptor import SimpleCryptor
from typing import List
import struct

TEA_DELTA = 0x9E3779B9
TEA_ROUNDS = 32

class XTEA:
    """XTEA implements the Extended Tiny Encryption Algorithm"""

    def __init__(self, key: List[int]) -> None:
        self.key = key
        self.simple_cryptor = SimpleCryptor(key)

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
                self.simple_cryptor.encrypt_bytes(leftover_buf)
            else:
                self.simple_cryptor.decrypt_bytes(leftover_buf)
            
            buffer[leftover_start:leftover_start + left_over] = leftover_buf

    def _encrypt_word(self, v0: int, v1: int) -> tuple:
        sum_val = 0
        for _ in range(TEA_ROUNDS):
            v0 = (v0 + ((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum_val + self.key[sum_val & 3]))) & 0xFFFFFFFF
            sum_val = (sum_val + TEA_DELTA) & 0xFFFFFFFF
            v1 = (v1 + ((((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum_val + self.key[(sum_val >> 11) & 3]))) & 0xFFFFFFFF
        return v0, v1

    def _decrypt_word(self, v0: int, v1: int) -> tuple:
        # Calculate sum with proper overflow handling
        sum_val = 0
        for _ in range(TEA_ROUNDS):
            sum_val = (sum_val + TEA_DELTA) & 0xFFFFFFFF

        for _ in range(TEA_ROUNDS):
            v1 = (v1 - ((((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum_val + self.key[(sum_val >> 11) & 3]))) & 0xFFFFFFFF
            sum_val = (sum_val - TEA_DELTA) & 0xFFFFFFFF
            v0 = (v0 - ((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum_val + self.key[sum_val & 3]))) & 0xFFFFFFFF
        return v0, v1
