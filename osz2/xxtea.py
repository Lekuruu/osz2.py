
from .simple_cryptor import SimpleCryptor
from numba import njit, prange
from typing import List
import numpy as np

MAX_WORDS = 16
MAX_BYTES = MAX_WORDS * 4
TEA_DELTA = 0x9E3779B9

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
        data = _encrypt_blocks_parallel(data, self.key, full_word_count)
        buffer[buf_start:buf_start + buffer_size] = data.tobytes()

    def decrypt_full_blocks_parallel(self, buffer: bytearray, buf_start: int, full_word_count: int) -> None:
        # Convert buffer slice to numpy array for parallel processing
        buffer_size = full_word_count * MAX_BYTES
        data = np.frombuffer(buffer[buf_start:buf_start + buffer_size], dtype=np.uint32).copy()
        data = _decrypt_blocks_parallel(data, self.key, full_word_count)
        buffer[buf_start:buf_start + buffer_size] = data.tobytes()

    @staticmethod
    def encrypt_words(n: int, key: np.ndarray, data: bytearray, offset: int) -> None:
        v = np.frombuffer(data[offset:offset + n*4], dtype=np.uint32).copy()
        v = _encrypt_block(v, key, n)
        data[offset:offset + n*4] = v.tobytes()

    @staticmethod
    def decrypt_words(n: int, key: np.ndarray, data: bytearray, offset: int) -> None:
        v = np.frombuffer(data[offset:offset + n*4], dtype=np.uint32).copy()
        v = _decrypt_block(v, key, n)
        data[offset:offset + n*4] = v.tobytes()

    @staticmethod
    def encrypt_fixed_word_array(key: np.ndarray, data: bytearray, offset: int) -> None:
        if len(data) - offset < MAX_BYTES:
            return

        v = np.frombuffer(data[offset:offset + MAX_BYTES], dtype=np.uint32).copy()
        v = _encrypt_block_fixed(v, key)
        data[offset:offset + MAX_BYTES] = v.tobytes()

    @staticmethod
    def decrypt_fixed_word_array(key: np.ndarray, data: bytearray, offset: int) -> None:
        if len(data) - offset < MAX_BYTES:
            return

        v = np.frombuffer(data[offset:offset + MAX_BYTES], dtype=np.uint32).copy()
        v = _decrypt_block_fixed(v, key)
        data[offset:offset + MAX_BYTES] = v.tobytes()

@njit(cache=True, inline='always')
def _mx(y: int, z: int, sum_val: int, key_val: int) -> int:
    """The MX function used in XXTEA algorithm"""
    return ((((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ 
            ((sum_val ^ y) + (key_val ^ z))) & 0xFFFFFFFF

@njit(cache=True)
def _encrypt_block(v: np.ndarray, key: np.ndarray, n: int) -> np.ndarray:
    """JIT-compiled encryption logic for variable-size blocks"""
    rounds = 6 + 52 // n
    sum_val = np.uint32(0)
    z = v[n - 1]

    for _ in range(rounds):
        sum_val = (sum_val + TEA_DELTA) & 0xFFFFFFFF
        e = (sum_val >> 2) & 3

        for p in range(n - 1):
            y = v[p + 1]
            mx_val = _mx(y, z, sum_val, key[(p & 3) ^ e])
            v[p] = (v[p] + mx_val) & 0xFFFFFFFF
            z = v[p]

        y = v[0]
        mx_val = _mx(y, z, sum_val, key[((n - 1) & 3) ^ e])
        v[n - 1] = (v[n - 1] + mx_val) & 0xFFFFFFFF
        z = v[n - 1]

    return v

@njit(cache=True)
def _decrypt_block(v: np.ndarray, key: np.ndarray, n: int) -> np.ndarray:
    """JIT-compiled decryption logic for variable-size blocks"""
    rounds = 6 + 52 // n
    sum_val = (rounds * TEA_DELTA) & 0xFFFFFFFF
    y = v[0]

    while sum_val != 0:
        e = (sum_val >> 2) & 3

        for p in range(n - 1, 0, -1):
            z = v[p - 1]
            mx_val = _mx(y, z, sum_val, key[(p & 3) ^ e])
            v[p] = (v[p] - mx_val) & 0xFFFFFFFF
            y = v[p]

        z = v[n - 1]
        mx_val = _mx(y, z, sum_val, key[0 ^ e])
        v[0] = (v[0] - mx_val) & 0xFFFFFFFF
        y = v[0]

        sum_val = (sum_val - TEA_DELTA) & 0xFFFFFFFF

    return v

@njit(cache=True)
def _encrypt_block_fixed(v: np.ndarray, key: np.ndarray) -> np.ndarray:
    """JIT-compiled encryption logic for fixed 16-word blocks"""
    rounds = 6 + 52 // MAX_WORDS
    sum_val = np.uint32(0)
    z = v[MAX_WORDS - 1]

    for _ in range(rounds):
        sum_val = (sum_val + TEA_DELTA) & 0xFFFFFFFF
        e = (sum_val >> 2) & 3

        # Process all elements
        for p in range(MAX_WORDS - 1):
            y = v[p + 1]
            mx_val = _mx(y, z, sum_val, key[(p & 3) ^ e])
            v[p] = (v[p] + mx_val) & 0xFFFFFFFF
            z = v[p]

        y = v[0]
        mx_val = _mx(y, z, sum_val, key[((MAX_WORDS - 1) & 3) ^ e])
        v[MAX_WORDS - 1] = (v[MAX_WORDS - 1] + mx_val) & 0xFFFFFFFF
        z = v[MAX_WORDS - 1]

    return v

@njit(cache=True)
def _decrypt_block_fixed(v: np.ndarray, key: np.ndarray) -> np.ndarray:
    """JIT-compiled decryption logic for fixed 16-word blocks"""
    rounds = 6 + 52 // MAX_WORDS
    sum_val = (rounds * TEA_DELTA) & 0xFFFFFFFF
    y = v[0]

    while sum_val != 0:
        e = (sum_val >> 2) & 3

        # Process all elements
        for p in range(MAX_WORDS - 1, 0, -1):
            z = v[p - 1]
            mx_val = _mx(y, z, sum_val, key[(p & 3) ^ e])
            v[p] = (v[p] - mx_val) & 0xFFFFFFFF
            y = v[p]

        z = v[MAX_WORDS - 1]
        mx_val = _mx(y, z, sum_val, key[0 ^ e])
        v[0] = (v[0] - mx_val) & 0xFFFFFFFF
        y = v[0]

        sum_val = (sum_val - TEA_DELTA) & 0xFFFFFFFF

    return v

@njit(cache=True, parallel=True)
def _encrypt_blocks_parallel(data: np.ndarray, key: np.ndarray, block_count: int) -> np.ndarray:
    # Process blocks in parallel using prange
    for i in prange(block_count):
        # Extract block
        block_start = i * MAX_WORDS
        block_end = block_start + MAX_WORDS
        v = data[block_start:block_end].copy()
        
        # Encrypt block
        v = _encrypt_block_fixed(v, key)
        
        # Write back
        data[block_start:block_end] = v
    
    return data

@njit(cache=True, parallel=True)
def _decrypt_blocks_parallel(data: np.ndarray, key: np.ndarray, block_count: int) -> np.ndarray:
    # Process blocks in parallel using prange
    for i in prange(block_count):
        # Extract block
        block_start = i * MAX_WORDS
        block_end = block_start + MAX_WORDS
        v = data[block_start:block_end].copy()
        
        # Decrypt block
        v = _decrypt_block_fixed(v, key)
        
        # Write back
        data[block_start:block_end] = v
    
    return data
