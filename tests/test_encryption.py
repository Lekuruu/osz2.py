
from osz2.utils import bytes_to_uint32_array
from osz2.constants import KNOWN_PLAIN
from pathlib import Path
from osz2 import *

import secrets
import pytest
import os

TESTS_DIR = Path(__file__).parent
FILES_DIR = TESTS_DIR / "files"
OSZ2_FILES = list(FILES_DIR.glob("*.osz2"))

class TestSimpleCryptor:
    @pytest.fixture
    def key(self) -> list:
        return bytes_to_uint32_array(secrets.token_bytes(16))

    def test_encrypt_decrypt_roundtrip(self, key: list) -> None:
        cryptor = SimpleCryptor(key)
        original = bytearray(b"plz enjoy game")
        data = bytearray(original)

        cryptor.encrypt_bytes(data)
        assert data != original

        cryptor.decrypt_bytes(data)
        assert data == original

    def test_encrypt_modifies_data(self, key: list) -> None:
        cryptor = SimpleCryptor(key)
        data = bytearray(b"test data")
        original = bytearray(data)

        cryptor.encrypt_bytes(data)
        assert data != original

    def test_empty_data(self, key: list) -> None:
        cryptor = SimpleCryptor(key)
        data = bytearray()
        cryptor.encrypt_bytes(data)
        cryptor.decrypt_bytes(data)
        assert len(data) == 0

class TestXXTEA:
    @pytest.fixture
    def key(self) -> list:
        return bytes_to_uint32_array(secrets.token_bytes(16))

    def test_encrypt_decrypt_roundtrip(self, key: list) -> None:
        xxtea = XXTEA(key)
        original = bytearray(KNOWN_PLAIN)
        data = bytearray(original)

        xxtea.encrypt(data, 0, len(data))
        assert data != original

        xxtea.decrypt(data, 0, len(data))
        assert data == original

    def test_encrypt_decrypt_large_data(self, key: list) -> None:
        xxtea = XXTEA(key)
        original = bytearray(os.urandom(1024))
        data = bytearray(original)

        xxtea.encrypt(data, 0, len(data))
        assert data != original

        xxtea.decrypt(data, 0, len(data))
        assert data == original

    def test_encrypt_partial_buffer(self, key: list) -> None:
        xxtea = XXTEA(key)
        original = bytearray(b"\x00" * 10 + os.urandom(64) + b"\x00" * 10)
        data = bytearray(original)

        # Encrypt only middle portion
        xxtea.encrypt(data, 10, 64)

        # Start and end should be unchanged
        assert data[:10] == original[:10]
        assert data[74:] == original[74:]

        # Middle should be different
        assert data[10:74] != original[10:74]

class TestXTEA:
    @pytest.fixture
    def key(self) -> list:
        return bytes_to_uint32_array(secrets.token_bytes(16))

    def test_encrypt_decrypt_roundtrip(self, key: list) -> None:
        xtea = XTEA(key)
        original = bytearray(os.urandom(64))
        data = bytearray(original)

        xtea.encrypt(data, 0, len(data))
        assert data != original

        xtea.decrypt(data, 0, len(data))
        assert data == original
