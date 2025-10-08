
from typing import Dict, List
from .metadata import MetadataType
from .keys import KeyType, Mapping as KeyMapping
from .xxtea_reader import XXTEAReader
from .xtea import XTEA
from .file import File
from .utils import *

import hashlib
import struct
import io

class Osz2Package:
    def __init__(
        self,
        reader: io.BufferedReader,
        metadata_only: bool = False,
        key_type: KeyType = KeyType.OSZ2
    ) -> None:
        self.metadata: Dict[MetadataType, str] = {}
        self.filenames: Dict[str, int] = {}
        self.files: List[File] = []
        self.key_type = key_type
        self.key: bytes = b""

        self.metadata_hash: bytes = b""
        self.file_info_hash: bytes = b""
        self.full_body_hash: bytes = b""

        # Always read the header when initializing
        self.read_header(reader)

        if not metadata_only:
            # Read the files if requested
            self.read_files(reader)

    @classmethod
    def from_file(cls, path: str, metadata_only=False, key_type=KeyType.OSZ2) -> "Osz2Package":
        with open(path, "rb") as f:
            return cls(f, metadata_only, key_type)

    @classmethod
    def from_bytes(cls, data: bytes, metadata_only=False, key_type=KeyType.OSZ2) -> "Osz2Package":
        with io.BytesIO(data) as f:
            return cls(f, metadata_only, key_type)

    def read_header(self, reader: io.BufferedReader) -> None:
        magic = reader.read(3)
        assert magic == b"\xECHO", "Not a valid osz2 package" # nice one echo

        # Seek 17 bytes from the current position
        # to skip unused version byte & IV data
        reader.seek(17, 1)

        self.metadata_hash = reader.read(16)
        self.file_info_hash = reader.read(16)
        self.full_body_hash = reader.read(16)

        self.read_metadata(reader)
        self.read_file_names(reader)

        # Generate key based on metadata and key type
        # Usually this is just the MD5 of "<creator>yhxyfjo5<beatmapsetID>"
        key_generator = KeyMapping[self.key_type]
        self.key = key_generator(self.metadata)

    def read_metadata(self, reader: io.BufferedReader) -> None:
        buffer = reader.read(4)
        count = struct.unpack("<I", buffer)[0]

        for _ in range(count):
            buf = reader.read(2)
            meta_type = struct.unpack("<H", buf)[0]
            meta_value = read_string(reader)

            self.metadata[MetadataType(meta_type)] = meta_value

            buffer += buf
            buffer += write_string(meta_value)

        hash = compute_osz_hash(buffer, count*3, 0xA7)
        assert hash == self.metadata_hash, f"Metadata hash mismatch, expected: {hash}, got: {self.metadata_hash}"

    def read_file_names(self, reader: io.BufferedReader) -> None:
        buffer = reader.read(4)
        count = struct.unpack("<I", buffer)[0]

        for _ in range(count):
            filename = read_string(reader)
            beatmap_id = struct.unpack("<I", reader.read(4))[0]
            self.filenames[filename] = beatmap_id

    def read_files(self, reader: io.BufferedReader) -> None:
        # Convert key to uint32 array for XTEA
        key = bytes_to_uint32_array(self.key)
        xtea = XTEA(key)

        # Read and decrypt magic encrypted bytes
        encrypted_magic = bytearray(reader.read(64))
        xtea.decrypt(encrypted_magic, 0, 64)
        # TODO: Compare decrypted stuff to expected value, where ever that is found

        # Read encrypted i32 length
        length = struct.unpack("<I", reader.read(4))[0]

        # Decode length by encrypted length
        for i in range(0, 16, 2):
            length -= self.file_info_hash[i] | (self.file_info_hash[i+1] << 17)

        file_info = reader.read(length)
        file_data = reader.read()
        file_offset = reader.seek(0, 1)
        total_size = reader.seek(0, 2)
        reader.seek(file_offset, 0)

        # Combine file info and data for reading
        file_reader = io.BytesIO(file_info + file_data)

        # Parse files using xxtea stream
        with XXTEAReader(file_reader, key) as xxtea_reader:
            self.parse_files(xxtea_reader, file_info, file_offset, total_size)

    def parse_files(self, reader: XXTEAReader, file_info: bytes, file_offset: int, total_size: int) -> None:
        count = struct.unpack("<I", reader.read(4))[0]
        curr_offset = struct.unpack("<I", reader.read(4))[0]

        # Verify file info hash
        file_info_hash = compute_osz_hash(file_info, count*4, 0xd1)
        assert file_info_hash == self.file_info_hash, f"File info hash mismatch, expected: {file_info_hash}, got: {self.file_info_hash}"

        for i in range(count):
            filename = read_string(reader)
            file_hash = reader.read(16)

            date_created_binary = struct.unpack("<Q", reader.read(8))[0]
            date_modified_binary = struct.unpack("<Q", reader.read(8))[0]

            # Convert from .NET DateTime.ToBinary() format
            date_created = datetime_from_binary(date_created_binary)
            date_modified = datetime_from_binary(date_modified_binary)

            next_offset = total_size - file_offset
            if count > i + 1:
                next_offset = struct.unpack("<I", reader.read(4))[0]

            file_length = next_offset - curr_offset
            file = File(
                filename,
                curr_offset,
                file_length,
                file_hash,
                date_created,
                date_modified,
                content=bytes(),
            )
            self.files.append(file)
            curr_offset = next_offset

        # After reading the file info, read the actual file contents
        for i in range(len(self.files)):
            length = struct.unpack("<I", reader.read(4))[0]
            self.files[i].content = reader.read(length)
