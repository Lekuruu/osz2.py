
from .simple_cryptor import SimpleCryptor
from typing import List
import struct

MAX_WORDS = 16
MAX_BYTES = MAX_WORDS * 4
TEA_DELTA = 0x9E3779B9

class XXTEA:
    """XXTEA implements the Corrected Block TEA algorithm"""

    def __init__(self, key: List[int]) -> None:
        self.cryptor = SimpleCryptor(key)
        self.key = key
        self.n = 0

    def decrypt(self, buffer: bytearray, start: int, count: int) -> None:
        self.encrypt_decrypt(buffer, start, count, False)

    def encrypt(self, buffer: bytearray, start: int, count: int) -> None:
        self.encrypt_decrypt(buffer, start, count, True)

    def encrypt_decrypt(self, buffer: bytearray, buf_start: int, count: int, encrypt: bool) -> None:
        full_word_count = count // MAX_BYTES
        left_over = count % MAX_BYTES

        for i in range(full_word_count):
            offset = buf_start + i * MAX_BYTES
            if encrypt:
                self.encrypt_fixed_word_array(self.key, buffer, offset)
            else:
                self.decrypt_fixed_word_array(self.key, buffer, offset)

        if left_over == 0:
            return

        leftover_start = buf_start + full_word_count * MAX_BYTES
        self.n = left_over // 4

        if self.n > 1:
            if encrypt:
                self.encrypt_words(self.n, self.key, buffer, leftover_start)
            else:
                self.decrypt_words(self.n, self.key, buffer, leftover_start)

            left_over -= self.n * 4
            if left_over == 0:
                return

            leftover_start += self.n * 4

        remaining = buffer[leftover_start:leftover_start + left_over]

        if encrypt:
            self.cryptor.encrypt_bytes(remaining)
        else:
            self.cryptor.decrypt_bytes(remaining)

        buffer[leftover_start:leftover_start + left_over] = remaining

    @staticmethod
    def encrypt_words(n: int, key: List[int], data: bytearray, offset: int) -> None:
        v = [struct.unpack_from('<I', data, offset + i * 4)[0] for i in range(n)]

        rounds = 6 + 52 // n
        sum_val = 0
        z = v[n - 1]

        while rounds > 0:
            sum_val = (sum_val + TEA_DELTA) & 0xFFFFFFFF
            e = (sum_val >> 2) & 3

            # Pre-fetch all 4 possible keys for this round
            keys_e = [key[i ^ e] for i in range(4)]

            for p in range(n - 1):
                y = v[p + 1]
                v[p] = (v[p] + XXTEA.mx(y, z, sum_val, keys_e[p & 3])) & 0xFFFFFFFF
                z = v[p]

            y = v[0]
            p = n - 1
            v[n - 1] = (v[n - 1] + XXTEA.mx(y, z, sum_val, keys_e[p & 3])) & 0xFFFFFFFF
            z = v[n - 1]
            rounds -= 1

        # Batch write all values
        for i in range(n):
            struct.pack_into('<I', data, offset + i * 4, v[i])

    @staticmethod
    def decrypt_words(n: int, key: List[int], data: bytearray, offset: int) -> None:
        v = [struct.unpack_from('<I', data, offset + i * 4)[0] for i in range(n)]

        rounds = 6 + 52 // n
        sum_val = (rounds * TEA_DELTA) & 0xFFFFFFFF
        y = v[0]

        while True:
            e = (sum_val >> 2) & 3
            keys_e = [key[i ^ e] for i in range(4)]

            for p in range(n - 1, 0, -1):
                z = v[p - 1]
                v[p] = (v[p] - XXTEA.mx(y, z, sum_val, keys_e[p & 3])) & 0xFFFFFFFF
                y = v[p]

            z = v[n - 1]
            p = 0
            v[0] = (v[0] - XXTEA.mx(y, z, sum_val, keys_e[p & 3])) & 0xFFFFFFFF
            y = v[0]

            sum_val = (sum_val - TEA_DELTA) & 0xFFFFFFFF
            if sum_val == 0:
                break

        for i in range(n):
            struct.pack_into('<I', data, offset + i * 4, v[i])

    @staticmethod
    def encrypt_fixed_word_array(key: List[int], data: bytearray, offset: int) -> None:
        if len(data) - offset < MAX_BYTES:
            return

        v = [struct.unpack_from('<I', data, offset + i * 4)[0] for i in range(MAX_WORDS)]

        rounds = 6 + 52 // MAX_WORDS
        sum_val = 0
        z = v[MAX_WORDS - 1]

        while rounds > 0:
            sum_val = (sum_val + TEA_DELTA) & 0xFFFFFFFF
            e = (sum_val >> 2) & 3
            keys_e = [key[i ^ e] for i in range(4)]

            for p in range(MAX_WORDS - 1):
                y = v[p + 1]
                v[p] = (v[p] + XXTEA.mx(y, z, sum_val, keys_e[p & 3])) & 0xFFFFFFFF
                z = v[p]

            y = v[0]
            p = MAX_WORDS - 1
            v[MAX_WORDS - 1] = (v[MAX_WORDS - 1] + XXTEA.mx(y, z, sum_val, keys_e[p & 3])) & 0xFFFFFFFF
            z = v[MAX_WORDS - 1]
            rounds -= 1

        for i in range(MAX_WORDS):
            struct.pack_into('<I', data, offset + i * 4, v[i])

    @staticmethod
    def decrypt_fixed_word_array(key: List[int], data: bytearray, offset: int) -> None:
        if len(data) - offset < MAX_BYTES:
            return

        v = [struct.unpack_from('<I', data, offset + i * 4)[0] for i in range(MAX_WORDS)]

        rounds = 6 + 52 // MAX_WORDS
        sum_val = (rounds * TEA_DELTA) & 0xFFFFFFFF
        y = v[0]

        while True:
            e = (sum_val >> 2) & 3
            keys_e = [key[i ^ e] for i in range(4)]

            for p in range(MAX_WORDS - 1, 0, -1):
                z = v[p - 1]
                v[p] = (v[p] - XXTEA.mx(y, z, sum_val, keys_e[p & 3])) & 0xFFFFFFFF
                y = v[p]

            z = v[MAX_WORDS - 1]
            p = 0
            v[0] = (v[0] - XXTEA.mx(y, z, sum_val, keys_e[p & 3])) & 0xFFFFFFFF
            y = v[0]

            sum_val = (sum_val - TEA_DELTA) & 0xFFFFFFFF
            if sum_val == 0:
                break

        for i in range(MAX_WORDS):
            struct.pack_into('<I', data, offset + i * 4, v[i])

    @staticmethod
    def mx(y: int, z: int, sum_val: int, key_val: int) -> int:
        return ((((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ 
                ((sum_val ^ y) + (key_val ^ z))) & 0xFFFFFFFF
