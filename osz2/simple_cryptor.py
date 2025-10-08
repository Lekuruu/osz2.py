
from typing import List

class SimpleCryptor:
    def __init__(self, key: List[int]) -> None:
        self.key = key

    def encrypt_bytes(self, buf: bytearray) -> None:
        byte_key = self.uint32_slice_to_byte_slice(self.key)
        prev_encrypted = 0

        for i in range(len(buf)):
            sum_val = buf[i] + (byte_key[i % 16] >> 2)
            buf[i] = ((sum_val % 256) + 256) % 256
            buf[i] ^= self.rotate_left(byte_key[15 - i % 16], (prev_encrypted + len(buf) - i) % 7)
            buf[i] = self.rotate_right(buf[i], (~prev_encrypted & 0xFFFFFFFF) % 7)
            prev_encrypted = buf[i]

    def decrypt_bytes(self, buf: bytearray) -> None:
        byte_key = self.uint32_slice_to_byte_slice(self.key)
        prev_encrypted = 0

        for i in range(len(buf)):
            tmp_e = buf[i]
            buf[i] = self.rotate_left(buf[i], (~prev_encrypted & 0xFFFFFFFF) % 7)
            buf[i] ^= self.rotate_left(byte_key[15 - i % 16], (prev_encrypted + len(buf) - i) % 7)
            diff = buf[i] - (byte_key[i % 16] >> 2)
            buf[i] = ((diff % 256) + 256) % 256
            prev_encrypted = tmp_e

    @staticmethod
    def rotate_left(val: int, n: int) -> int:
        val &= 0xFF
        n &= 0x07
        return ((val << n) | (val >> (8 - n))) & 0xFF

    @staticmethod
    def rotate_right(val: int, n: int) -> int:
        val &= 0xFF
        n &= 0x07
        return ((val >> n) | (val << (8 - n))) & 0xFF

    @staticmethod
    def uint32_slice_to_byte_slice(u32s: List[int]) -> List[int]:
        bytes_list = []
        for u32 in u32s:
            bytes_list.append(u32 & 0xFF)
            bytes_list.append((u32 >> 8) & 0xFF)
            bytes_list.append((u32 >> 16) & 0xFF)
            bytes_list.append((u32 >> 24) & 0xFF)
        return bytes_list
