
from typing import Any, Dict, List, Iterable, Optional, BinaryIO

from .keys import KeyType, Mapping as KeyMapping
from .xxtea_writer import XXTEAWriter
from .xxtea_reader import XXTEAReader
from .constants import KNOWN_PLAIN
from .metadata import MetadataType
from .file import File
from .xtea import XTEA
from .utils import *

import zipfile
import secrets
import struct
import os
import io

class Osz2Package:
    def __init__(
        self,
        reader: Optional[BinaryIO] = None,
        metadata_only: bool = False,
        key_type: KeyType = KeyType.OSZ2
    ) -> None:
        self.metadata: Dict[MetadataType, str] = {}
        self.beatmap_ids: Dict[str, int] = {}
        self.files: List[File] = []
        self.key_type = key_type
        self.key: bytes = b""
        self.version: int = 0

        self.data_offset: int = 0
        self.file_info_offset: int = 0

        self.iv: bytes = secrets.token_bytes(16)
        self.metadata_hash: bytes = b""
        self.file_info_hash: bytes = b""
        self.full_body_hash: bytes = b""

        if reader is not None:
            self.read(reader, metadata_only)

    def __repr__(self) -> str:
        return f"<Osz2Package files={self.files} metadata={self.metadata}>"

    @classmethod
    def from_file(cls, path: str, metadata_only=False, key_type=KeyType.OSZ2) -> "Osz2Package":
        """Read an osz2 package from a file path"""
        with open(path, "rb") as f:
            return cls(f, metadata_only, key_type)

    @classmethod
    def from_bytes(cls, data: bytes, metadata_only=False, key_type=KeyType.OSZ2) -> "Osz2Package":
        """Read an osz2 package from raw bytes"""
        with io.BytesIO(data) as f:
            return cls(f, metadata_only, key_type)

    @classmethod
    def from_directory(
        cls,
        directory: str,
        key_type: KeyType = KeyType.OSZ2
    ) -> "Osz2Package":
        """Initialize an osz2 package object from a directory, useful for exporting packages"""
        package = cls(key_type=key_type)
        package.add_directory(directory, recursive=True)
        return package

    @property
    def video_files(self) -> Iterable[File]:
        for file in self.files:
            if file.is_video:
                yield file

    @property
    def beatmap_files(self) -> Iterable[File]:
        for file in self.files:
            if file.is_beatmap:
                yield file

    @property
    def combined_beatmap_files(self) -> Iterable[File]:
        for file in self.files:
            if file.is_combined_beatmap:
                yield file

    @property
    def osz_filename(self, extension: str = ".osz") -> str:
        return sanitize_filename(
            f'{self.metadata.get(MetadataType.BeatmapSetID, "")} '
            f'{self.metadata.get(MetadataType.Artist, "Unknown")} - '
            f'{self.metadata.get(MetadataType.Title, "Unknown")} '
            f'({self.metadata.get(MetadataType.Creator, "Unknown")})'
        ).strip() + extension

    def read(self, reader: BinaryIO, metadata_only: bool = False) -> None:
        """Read osz2 package data from a reader & apply it to this object"""
        self._read_header(reader)

        if metadata_only:
            return

        self._read_files(reader)

    def export(self) -> bytes:
        """Export the current package as an osz2 file"""
        # Ensure we're ready for export
        assert len(self.files) > 0, "Cannot create an empty package"

        if self.key_type == KeyType.OSZ2:
            assert MetadataType.Creator in self.metadata, "Missing required metadata: 'Creator'"
            assert MetadataType.BeatmapSetID in self.metadata, "Missing required metadata: 'BeatmapSetID'"

        elif self.key_type == KeyType.OSF2:
            assert MetadataType.Title in self.metadata, "Missing required metadata: 'Title'"
            assert MetadataType.Artist in self.metadata, "Missing required metadata: 'Artist'"

        # Generate encryption key
        key_generator = KeyMapping[self.key_type]
        key = key_generator(self.metadata)
        key_array = bytes_to_uint32_array(key)
        self.key = key

        output = io.BytesIO()
        self._process_video_files()
        self._update_file_offsets()
        self._write_package_contents(output, key_array)
        return output.getvalue()

    def save(self, path: str) -> int:
        """Save the current package to a file"""
        data = self.export()
        with open(path, "wb") as f:
            return f.write(data)

    def create_osz_package(
        self,
        compression: int = zipfile.ZIP_DEFLATED,
        exclude_disallowed_files: bool = True
    ) -> bytes:
        """Create a regular .osz package from the current files"""
        with io.BytesIO() as buffer:
            osz = zipfile.ZipFile(buffer, 'w', compression)

            for file in self.files:
                if exclude_disallowed_files and not file.is_allowed_extension:
                    # See `constants.ALLOWED_FILE_EXTENSIONS` for allowed file extensions
                    continue

                # Create ZipInfo to set file metadata
                zip_info = zipfile.ZipInfo(filename=file.filename_sanitized)
                zip_info.compress_type = compression
                zip_info.date_time = file.date_modified.timetuple()[:6]

                # Check if date_time is valid for zip format
                if zip_info.date_time[0] < 1980:
                    zip_info.date_time = (1980, 1, 1, 0, 0, 0)

                osz.writestr(zip_info, file.content)

            osz.close()
            return buffer.getvalue()

    def calculate_osz_filesize(
        self,
        compression: int = zipfile.ZIP_DEFLATED,
        exclude_disallowed_files: bool = True
    ) -> int:
        """Calculate the size of the .osz package if it were to be created"""
        return len(self.create_osz_package(compression, exclude_disallowed_files))

    def find_file_by_name(self, name: str) -> Optional[File]:
        """Get a file by its filename"""
        return next((file for file in self.files if file.filename == name), None)

    def find_file_by_beatmap_id(self, beatmap_id: int) -> Optional[File]:
        """Get a file by its beatmap ID"""
        return next((file for file in self.files if self.beatmap_ids.get(file.filename, -1) == beatmap_id), None)

    def add_file(
        self,
        filename: str,
        content: bytes,
        date_created: Optional[datetime.datetime] = None,
        date_modified: Optional[datetime.datetime] = None
    ) -> None:
        """Add or replace a file in this package"""
        date_created = date_created or datetime.datetime.now()
        date_modified = date_modified or datetime.datetime.now()

        # Remove existing file if present
        if existing := self.find_file_by_name(filename):
            self.files.remove(existing)

        # Create new file
        file = File(
            filename=filename,
            offset=0,
            size=len(content),
            hash=hashlib.md5(content).digest(),
            date_created=date_created,
            date_modified=date_modified,
            content=content
        )
        self.files.append(file)

        # Auto-assign beatmap ID if it's a beatmap file
        if file.is_beatmap and filename not in self.beatmap_ids:
            self.beatmap_ids[filename] = -1

    def add_file_from_disk(self, filename: str, path: str) -> None:
        """Add a file from disk to this package"""
        with open(path, 'rb') as f:
            content = f.read()

        stat = os.stat(path)
        created = datetime.datetime.fromtimestamp(stat.st_ctime)
        modified = datetime.datetime.fromtimestamp(stat.st_mtime)

        self.add_file(filename, content, created, modified)

    def add_directory(self, path: str, recursive: bool = True) -> None:
        """Add all the files in a directory to this package"""
        if not os.path.isdir(path):
            raise ValueError(f"Path is not a directory: {path}")

        path = os.path.abspath(path)

        if not recursive:
            # Only add files in the immediate directory
            for filename in os.listdir(path):
                filepath = os.path.join(path, filename)

                if not os.path.isfile(filepath):
                    continue

                self.add_file_from_disk(filename, filepath)
        else:
            # Recursively add all files
            for root, _, filenames in os.walk(path):
                for filename in filenames:
                    filepath = os.path.join(root, filename)

                    # Preserve directory structure relative to base path
                    rel_path = os.path.relpath(filepath, path)
                    self.add_file_from_disk(rel_path, filepath)

    def remove_file(self, filename: str) -> bool:
        """Remove a file from this package"""
        if not (file := self.find_file_by_name(filename)):
            return False

        self.files.remove(file)

        # Remove beatmap ID mapping if present
        if filename in self.beatmap_ids:
            del self.beatmap_ids[filename]

        return True

    def add_metadata(self, meta_type: MetadataType, value: Any) -> None:
        """Add or replace a new metadata item"""
        self.metadata[meta_type] = str(value)

    def remove_metadata(self, meta_type: MetadataType) -> bool:
        """Remove the specified metadata item"""
        if meta_type in self.metadata:
            del self.metadata[meta_type]
            return True
        return False

    def get_metadata(self, meta_type: MetadataType, default: Any = None) -> Optional[str]:
        """Get the value of the specified metadata type"""
        return self.metadata.get(meta_type, default)

    def set_beatmap_id(self, filename: str, beatmap_id: int) -> None:
        """Set the beatmap ID for a specific beatmap file"""
        file = self.find_file_by_name(filename)
        assert file is not None, f"File not found: {filename}"
        assert file.is_beatmap, f"File is not a beatmap: {filename}"
        self.beatmap_ids[filename] = beatmap_id

    def set_beatmapset_id(self, beatmapset_id: int) -> None:
        """Set the BeatmapSetID metadata for this package"""
        self.add_metadata(
            MetadataType.BeatmapSetID,
            beatmapset_id
         )

    def _read_header(self, reader: BinaryIO) -> None:
        magic = reader.read(3)
        assert magic == b"\xECHO", "Not a valid osz2 package" # nice one echo

        self.version = struct.unpack("B", reader.read(1))[0]
        self.iv = reader.read(16)

        self.metadata_hash = reader.read(16)
        self.file_info_hash = reader.read(16)
        self.full_body_hash = reader.read(16)

        self._read_metadata(reader)
        self._read_file_names(reader)

        # Generate key based on metadata and key type
        # Usually this is just the MD5 of "<creator>yhxyfjo5<beatmapsetID>"
        key_generator = KeyMapping[self.key_type]
        self.key = key_generator(self.metadata)

    def _read_metadata(self, reader: BinaryIO) -> None:
        buffer = reader.read(4)
        count = struct.unpack("<I", buffer)[0]

        for _ in range(count):
            buf = reader.read(2)
            meta_type = struct.unpack("<H", buf)[0]
            meta_value = read_string(reader)

            self.metadata[MetadataType(meta_type)] = meta_value

            buffer += buf
            buffer += write_string(meta_value)

        metadata_hash = compute_osz_hash(buffer, count*3, 0xA7)
        assert metadata_hash == self.metadata_hash, f"Metadata hash mismatch, expected: {metadata_hash.hex()}, got: {self.metadata_hash.hex()}"

    def _read_file_names(self, reader: BinaryIO) -> None:
        buffer = reader.read(4)
        count = struct.unpack("<I", buffer)[0]

        for _ in range(count):
            filename = read_string(reader)
            beatmap_id = struct.unpack("<I", reader.read(4))[0]
            self.beatmap_ids[filename] = beatmap_id

    def _read_files(self, reader: BinaryIO) -> None:
        # Convert key to uint32 array for XXTEA
        key = bytes_to_uint32_array(self.key)

        # Verify encrypted magic
        encrypted_magic = bytearray(reader.read(64))
        xtea = XTEA(key)
        xtea.decrypt(encrypted_magic, 0, 64)
        assert encrypted_magic == KNOWN_PLAIN, "Invalid encryption key"

        # Store file info offset
        self.file_info_offset = reader.tell()

        # Read encrypted i32 length
        length = struct.unpack("<I", reader.read(4))[0]

        # Decode length by encrypted length
        for i in range(0, 16, 2):
            length -= self.file_info_hash[i] | (self.file_info_hash[i+1] << 17)

        file_info = reader.read(length)

        # Store data offset
        self.data_offset = reader.tell()
        
        file_data = reader.read()
        file_offset = reader.seek(0, 1)
        total_size = reader.seek(0, 2)
        reader.seek(file_offset, 0)

        # Parse file infos using xxtea stream
        with XXTEAReader(io.BytesIO(file_info), key) as xxtea:
            count = struct.unpack("<I", xxtea.read(4))[0]
            curr_offset = struct.unpack("<I", xxtea.read(4))[0]

            # Verify file info hash
            file_info_hash = compute_osz_hash(file_info, count*4, 0xd1)
            assert file_info_hash == self.file_info_hash, f"File info hash mismatch, expected: {file_info_hash.hex()}, got: {self.file_info_hash.hex()}"

            for i in range(count):
                filename = read_string(xxtea)
                file_hash = xxtea.read(16)

                date_created_binary = struct.unpack("<Q", xxtea.read(8))[0]
                date_modified_binary = struct.unpack("<Q", xxtea.read(8))[0]

                # Convert from .NET DateTime.ToBinary() format
                date_created = datetime_from_binary(date_created_binary)
                date_modified = datetime_from_binary(date_modified_binary)

                next_offset = total_size - file_offset
                if count > i + 1:
                    next_offset = struct.unpack("<I", xxtea.read(4))[0]

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
        with XXTEAReader(io.BytesIO(file_data), key) as xxtea:
            for i in range(len(self.files)):
                length = struct.unpack("<I", xxtea.read(4))[0]
                self.files[i].content = xxtea.read(length)

    def _write_package_contents(self, writer: BinaryIO, key: List[int]) -> None:
        # Sort files before writing
        self._sort_files_for_export()

        # Prepare file data & info
        file_data = self._write_file_data(self.files, key)
        file_info = self._write_file_info(self.files, key)

        # Calculate hashes
        hash_info = compute_osz_hash(
            file_info,
            len(self.files) * 4, 0xD1
        )
        hash_body = compute_body_hash(
            file_data,
            int(self.metadata.get(MetadataType.VideoDataOffset, -1)) if MetadataType.VideoDataOffset in self.metadata else None,
            int(self.metadata.get(MetadataType.VideoDataLength, -1)) if MetadataType.VideoDataLength in self.metadata else None
        )

        # Prepare metadata
        meta_data = self._write_metadata()
        hash_meta = compute_osz_hash(meta_data, len(self.metadata) * 3, 0xA7)

        # Create & encode IV by XORing with body hash
        encoded_iv = bytes(a ^ b for a, b in zip(self.iv, hash_body))

        writer.write(b'\xECHO')
        writer.write(struct.pack("B", self.version))
        writer.write(encoded_iv)
        writer.write(hash_meta)
        writer.write(hash_info)
        writer.write(hash_body)
        writer.write(meta_data)

        # Store hashes in object
        self.file_info_hash = hash_info
        self.full_body_hash = hash_body
        self.metadata_hash = hash_meta

        beatmap_files = {
            f.filename: self.beatmap_ids.get(f.filename, -1) 
            for f in self.files if f.is_beatmap
        }
        writer.write(struct.pack("<I", len(beatmap_files)))

        for filename, beatmap_id in beatmap_files.items():
            writer.write(write_string(filename))
            writer.write(struct.pack("<I", beatmap_id & 0xFFFFFFFF))

        known_plain = bytearray(KNOWN_PLAIN)
        xtea = XTEA(key)
        xtea.encrypt(known_plain, 0, 64)
        writer.write(bytes(known_plain))

        # Obfuscate file_info length
        encoded_length = len(file_info)
        for i in range(0, 16, 2):
            encoded_length += hash_info[i] | (hash_info[i + 1] << 17)

        # File info & data with obfuscated length
        writer.write(struct.pack("<I", encoded_length & 0xFFFFFFFF))
        writer.write(file_info)
        writer.write(file_data)

    def _sort_files_for_export(self) -> None:
        # Sort files using the same logic as C# FileComparer
        # https://github.com/ppy/osu-stream/blob/master/osu!stream/Helpers/osu!common/MapPackage.cs#L1478
        def file_sort_key(file: File):
            if file.is_video:
                # Videos go last
                return (1, file.filename)

            # Other files go first, sorted by filename
            return (0, file.filename)

        self.files.sort(key=file_sort_key)

    def _write_file_data(self, files: List[File], key: List[int]) -> bytes:
        with XXTEAWriter(key) as writer:
            for file in files:
                writer.write(struct.pack("<I", len(file.content)))
                writer.write(file.content)
            return writer.getvalue()

    def _write_file_info(self, files: List[File], key: List[int]) -> bytes:
        with XXTEAWriter(key) as writer:
            # Write file count
            writer.write(struct.pack("<I", len(files)))

            # Calculate all offsets first
            offsets = []
            offset = 0

            for file in files:
                offsets.append(offset)
                offset += 4 + len(file.content)

            # Write first offset (always 0)
            writer.write(struct.pack("<I", offsets[0]))

            for i, file in enumerate(files):
                # Write filename & hash
                writer.write_string(file.filename)
                writer.write(file.hash)

                # Write timestamps
                writer.write(struct.pack("<Q", datetime_to_binary(file.date_created)))
                writer.write(struct.pack("<Q", datetime_to_binary(file.date_modified)))

                # Write next offset (except for last file)
                if i < len(files) - 1:
                    writer.write(struct.pack("<I", offsets[i + 1]))

            return writer.getvalue()

    def _write_metadata(self) -> bytes:
        buffer = io.BytesIO()
        buffer.write(struct.pack("<I", len(self.metadata)))

        for meta_type, value in self.metadata.items():
            buffer.write(struct.pack("<H", meta_type.value))
            buffer.write(write_string(value or ""))

        return buffer.getvalue()

    def _update_file_offsets(self) -> None:
        offset = 0

        for file in self.files:
            file.offset = offset
            offset += 4 + len(file.content)

    def _process_video_files(self) -> None:
        offset = 0

        for file in self.files:
            if not file.is_video:
                offset += 4 + len(file.content)
                continue

            assert len(file.content) >= 1024, "Video needs to be at least 1024 bytes big"

            # Calculate video hash from middle section of the file
            data_length = len(file.content)
            foot_start = (data_length // 2) - ((data_length // 2) % 16) - 512 + 16
            foot_data = file.content[foot_start:foot_start + 1024]
            video_hash = hashlib.md5(foot_data).hexdigest().upper()

            self.metadata[MetadataType.VideoDataOffset] = str(offset)
            self.metadata[MetadataType.VideoDataLength] = str(data_length)
            self.metadata[MetadataType.VideoHash] = video_hash
            break
