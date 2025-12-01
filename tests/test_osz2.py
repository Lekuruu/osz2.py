
from osz2.keys import generate_osf2_key, generate_osz2_key
from osz2.utils import bytes_to_uint32_array
from osz2.constants import KNOWN_PLAIN
from pathlib import Path
from osz2 import *

import hashlib
import secrets
import pytest
import os

TESTS_DIR = Path(__file__).parent
OSZ2_FILES = list(TESTS_DIR.glob("*.osz2"))

class TestOsz2Package:
    @pytest.fixture(params=OSZ2_FILES, ids=lambda p: p.stem)
    def osz2_path(self, request) -> Path:
        return request.param

    def test_from_file(self, osz2_path: Path) -> None:
        package = Osz2Package.from_file(str(osz2_path))
        assert package is not None
        assert len(package.files) > 0
        assert len(package.metadata) > 0

    def test_from_bytes(self, osz2_path: Path) -> None:
        data = osz2_path.read_bytes()
        package = Osz2Package.from_bytes(data)
        assert package is not None
        assert len(package.files) > 0

    def test_metadata_only(self, osz2_path: Path) -> None:
        package = Osz2Package.from_file(str(osz2_path), metadata_only=True)
        assert len(package.metadata) > 0
        assert len(package.files) == 0

    def test_metadata_contains_required_fields(self, osz2_path: Path) -> None:
        package = Osz2Package.from_file(str(osz2_path), metadata_only=True)
        # 'Creator' and 'BeatmapSetID' are required for osz2 key generation
        assert MetadataType.Creator in package.metadata
        assert MetadataType.BeatmapSetID in package.metadata

    def test_create_osz_package(self, osz2_path: Path) -> None:
        package = Osz2Package.from_file(str(osz2_path))
        osz_data = package.create_osz_package()
        assert len(osz_data) > 0
        assert osz_data[:2] == b"PK"

    def test_beatmap_content_is_valid(self, osz2_path: Path) -> None:
        package = Osz2Package.from_file(str(osz2_path))

        for beatmap in package.beatmap_files:
            # osu! beatmaps should start with "osu file format"
            content = beatmap.content.decode("utf-8-sig", errors="replace")
            assert "osu file format" in content

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

class TestKeyGeneration:
    def test_osz2_key_generation(self) -> None:
        metadata = {
            MetadataType.Creator: "TestCreator",
            MetadataType.BeatmapSetID: "12345",
        }
        key = generate_osz2_key(metadata)
        expected = hashlib.md5(b"TestCreatoryhxyfjo512345").digest()
        assert key == expected

    def test_osf2_key_generation(self) -> None:
        metadata = {
            MetadataType.Title: "TestTitle",
            MetadataType.Artist: "TestArtist",
        }
        key = generate_osf2_key(metadata)
        expected = hashlib.md5("\x08TestTitle4390gn8931iTestArtist".encode()).digest()
        assert key == expected

class TestExportRoundtrip:
    @pytest.fixture(params=OSZ2_FILES, ids=lambda p: p.stem)
    def osz2_path(self, request) -> Path:
        return request.param

    def test_export_and_reimport(self, osz2_path: Path) -> None:
        original = Osz2Package.from_file(str(osz2_path))
        exported = original.export()
        reimported = Osz2Package.from_bytes(exported)

        # Compare metadata & file count
        assert reimported.metadata == original.metadata
        assert len(reimported.files) == len(original.files)

        # Compare file contents
        for original_file in original.files:
            reimported_file = reimported.find_file_by_name(original_file.filename)
            assert reimported_file is not None
            assert reimported_file.content == original_file.content
