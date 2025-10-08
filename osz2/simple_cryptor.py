
from .utils import uint32_slice_to_byte_slice
from typing import List
from numba import njit
import numpy as np

class SimpleCryptor:
    def __init__(self, key: List[int]) -> None:
        # Pre-compute byte key for better performance
        self.key = np.array(uint32_slice_to_byte_slice(key), dtype=np.uint8)

    def encrypt_bytes(self, buf: bytearray) -> None:
        buf_array = np.frombuffer(buf, dtype=np.uint8)
        _encrypt_bytes_jit(buf_array, self.key)
        buf[:] = buf_array.tobytes()

    def decrypt_bytes(self, buf: bytearray) -> None:
        buf_array = np.frombuffer(buf, dtype=np.uint8)
        _decrypt_bytes_jit(buf_array, self.key)
        buf[:] = buf_array.tobytes()

@njit(cache=True, inline='always')
def _rotate_left(val: int, n: int) -> int:
    val &= 0xFF
    n &= 0x07
    return ((val << n) | (val >> (8 - n))) & 0xFF

@njit(cache=True, inline='always')
def _rotate_right(val: int, n: int) -> int:
    val &= 0xFF
    n &= 0x07
    return ((val >> n) | (val << (8 - n))) & 0xFF

@njit(cache=True)
def _encrypt_bytes_jit(buf: np.ndarray, byte_key: np.ndarray) -> None:
    prev_encrypted = np.uint8(0)
    buf_len = len(buf)

    for i in range(buf_len):
        sum_val = buf[i] + (byte_key[i % 16] >> 2)
        buf[i] = ((sum_val % 256) + 256) % 256
        buf[i] ^= _rotate_left(byte_key[15 - i % 16], (prev_encrypted + buf_len - i) % 7)
        buf[i] = _rotate_right(buf[i], (~prev_encrypted & 0xFFFFFFFF) % 7)
        prev_encrypted = buf[i]

@njit(cache=True)
def _decrypt_bytes_jit(buf: np.ndarray, byte_key: np.ndarray) -> None:
    prev_encrypted = np.uint8(0)
    buf_len = len(buf)

    for i in range(buf_len):
        tmp_e = buf[i]
        buf[i] = _rotate_left(buf[i], (~prev_encrypted & 0xFFFFFFFF) % 7)
        buf[i] ^= _rotate_left(byte_key[15 - i % 16], (prev_encrypted + buf_len - i) % 7)
        diff = buf[i] - (byte_key[i % 16] >> 2)
        buf[i] = ((diff % 256) + 256) % 256
        prev_encrypted = tmp_e
