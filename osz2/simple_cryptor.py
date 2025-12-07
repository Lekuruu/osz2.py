
from .utils import uint32_slice_to_byte_slice
from . import crypto
from typing import List
import numpy as np

class SimpleCryptor:
    def __init__(self, key: List[int]) -> None:
        # Pre-compute byte key for better performance
        self.key = np.array(uint32_slice_to_byte_slice(key), dtype=np.uint8)

    def encrypt_bytes(self, buf: bytearray) -> None:
        crypto.simple_cryptor_encrypt_bytes(buf, self.key)

    def decrypt_bytes(self, buf: bytearray) -> None:
        crypto.simple_cryptor_decrypt_bytes(buf, self.key)
