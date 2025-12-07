
from .simple_cryptor import SimpleCryptor
from . import crypto

from typing import List
import numpy as np

MAX_WORDS = 16
MAX_BYTES = MAX_WORDS * 4

class XXTEA:
    """XXTEA implements the Corrected Block TEA algorithm"""

    def __init__(self, key: List[int]) -> None:
        self.cryptor = SimpleCryptor(key)
        self.key = np.array(key, dtype=np.uint32)

        # Pre-compute all possible key permutations for faster lookup
        self.key_table = np.array([[key[i ^ e] for i in range(4)] for e in range(4)], dtype=np.uint32)
        self.n = 0

    def decrypt(self, buffer: bytearray, start: int, count: int) -> None:
        self.encrypt_decrypt(buffer, start, count, False)

    def encrypt(self, buffer: bytearray, start: int, count: int) -> None:
        self.encrypt_decrypt(buffer, start, count, True)

    def encrypt_decrypt(self, buffer: bytearray, buf_start: int, count: int, encrypt: bool) -> None:
        full_word_count = count // MAX_BYTES
        left_over = count % MAX_BYTES

        # Process full blocks
        if full_word_count > 0:
            if encrypt:
                self.encrypt_full_blocks(buffer, buf_start, full_word_count)
            else:
                self.decrypt_full_blocks(buffer, buf_start, full_word_count)

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

    def encrypt_full_blocks(self, buffer: bytearray, buf_start: int, full_word_count: int) -> None:
        # Use parallel processing for multiple blocks
        if full_word_count >= 4:
            self.encrypt_full_blocks_parallel(buffer, buf_start, full_word_count)
            return

        # Sequential for small data
        for i in range(full_word_count):
            offset = buf_start + i * MAX_BYTES
            self.encrypt_fixed_word_array(self.key, buffer, offset)

    def decrypt_full_blocks(self, buffer: bytearray, buf_start: int, full_word_count: int) -> None:
        # Use parallel processing for multiple blocks
        if full_word_count >= 4:
            self.decrypt_full_blocks_parallel(buffer, buf_start, full_word_count)
            return

        # Sequential for small data
        for i in range(full_word_count):
            offset = buf_start + i * MAX_BYTES
            self.decrypt_fixed_word_array(self.key, buffer, offset)

    def encrypt_full_blocks_parallel(self, buffer: bytearray, buf_start: int, full_word_count: int) -> None:
        # Convert buffer slice to numpy array for parallel processing
        buffer_size = full_word_count * MAX_BYTES
        data = np.frombuffer(buffer[buf_start:buf_start + buffer_size], dtype=np.uint32).copy()
        crypto.xxtea_encrypt_blocks(data, self.key, full_word_count)
        buffer[buf_start:buf_start + buffer_size] = data.tobytes()

    def decrypt_full_blocks_parallel(self, buffer: bytearray, buf_start: int, full_word_count: int) -> None:
        # Convert buffer slice to numpy array for parallel processing
        buffer_size = full_word_count * MAX_BYTES
        data = np.frombuffer(buffer[buf_start:buf_start + buffer_size], dtype=np.uint32).copy()
        crypto.xxtea_decrypt_blocks(data, self.key, full_word_count)
        buffer[buf_start:buf_start + buffer_size] = data.tobytes()

    @staticmethod
    def encrypt_words(n: int, key: np.ndarray, data: bytearray, offset: int) -> None:
        v = np.frombuffer(data[offset:offset + n*4], dtype=np.uint32).copy()
        crypto.xxtea_encrypt_block(v, key, n)
        data[offset:offset + n*4] = v.tobytes()

    @staticmethod
    def decrypt_words(n: int, key: np.ndarray, data: bytearray, offset: int) -> None:
        v = np.frombuffer(data[offset:offset + n*4], dtype=np.uint32).copy()
        crypto.xxtea_decrypt_block(v, key, n)
        data[offset:offset + n*4] = v.tobytes()

    @staticmethod
    def encrypt_fixed_word_array(key: np.ndarray, data: bytearray, offset: int) -> None:
        if len(data) - offset < MAX_BYTES:
            return

        v = np.frombuffer(data[offset:offset + MAX_BYTES], dtype=np.uint32).copy()
        crypto.xxtea_encrypt_block_fixed(v, key)
        data[offset:offset + MAX_BYTES] = v.tobytes()

    @staticmethod
    def decrypt_fixed_word_array(key: np.ndarray, data: bytearray, offset: int) -> None:
        if len(data) - offset < MAX_BYTES:
            return

        v = np.frombuffer(data[offset:offset + MAX_BYTES], dtype=np.uint32).copy()
        crypto.xxtea_decrypt_block_fixed(v, key)
        data[offset:offset + MAX_BYTES] = v.tobytes()
