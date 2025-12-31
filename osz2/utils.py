
import datetime
import hashlib
import struct
import typing
import re

unsafe_characters_pattern = re.compile(r'[<>:"|?*\x00-\x1F]')
traversal_pattern = re.compile(r'\.\.[\\/]+')

def sanitize_filename(filename: str) -> str:
    filename = re.sub(unsafe_characters_pattern, "", filename)
    filename = re.sub(traversal_pattern, "", filename)
    return filename

def bytes_to_uint32_array(data: bytes) -> typing.List[int]:
    return [x[0] for x in struct.iter_unpack("<I", data)]

def uint32_slice_to_byte_slice(u32s: typing.List[int]) -> typing.List[int]:
    bytes_list = []
    for u32 in u32s:
        bytes_list.append(u32 & 0xFF)
        bytes_list.append((u32 >> 8) & 0xFF)
        bytes_list.append((u32 >> 16) & 0xFF)
        bytes_list.append((u32 >> 24) & 0xFF)
    return bytes_list

def read_string(reader: typing.BinaryIO) -> str:
    length = read_uleb128(reader)
    if length == 0:
        return ""
    return reader.read(length).decode("utf-8")

def write_string(string: str) -> bytes:
    encoded = string.encode("utf-8")
    buf = write_uleb128(len(encoded))
    return buf + encoded

def read_uleb128(reader: typing.BinaryIO) -> int:
    result = 0
    shift = 0

    while True:
        b = reader.read(1)
        if not b:
            raise EOFError("Unexpected end of file while reading ULEB128")

        byte = b[0]
        result |= (byte & 0x7F) << shift

        if (byte & 0x80) == 0:
            break

        shift += 7

    return result

def write_uleb128(value: int) -> bytes:
    buf = bytearray()

    while True:
        byte = value & 0x7F
        value >>= 7
        if value != 0:
            byte |= 0x80

        buf.append(byte)
        if value == 0:
            break

    return bytes(buf)

def compute_osz_hash(buffer: bytes, pos: int, swap: int) -> bytes:
    buf = bytearray(buffer)

    if pos < 0 or pos >= len(buf):
        # If pos is out of bounds, just compute hash without swapping
        hash_bytes = bytearray(hashlib.md5(buf).digest())
    else:
        buf[pos] ^= swap
        hash_bytes = bytearray(hashlib.md5(buf).digest())
        buf[pos] ^= swap # restore original

    # Swap bytes as in C# implementation
    for i in range(8):
        hash_bytes[i], hash_bytes[i+8] = hash_bytes[i+8], hash_bytes[i]

    hash_bytes[5] ^= 0x2D
    return bytes(hash_bytes)

def compute_body_hash(
    data: bytes,
    video_offset: typing.Optional[int] = None,
    video_length: typing.Optional[int] = None
) -> bytes:
    to_hash = data
    pos = len(data) // 2

    if video_offset is not None and video_length is not None:
        # Exclude video data from the hash calculation
        before_video = data[:video_offset]
        after_video = data[video_offset + video_length:]
        to_hash = before_video + after_video
        pos = len(to_hash) // 2

    return compute_osz_hash(to_hash, pos, 0x9F)

def datetime_from_binary(time: int) -> datetime.datetime:
    n_ticks = time & 0x3FFFFFFFFFFFFFFF
    secs = n_ticks / 1e7
    d1 = datetime.datetime(1, 1, 1)
    t1 = datetime.timedelta(seconds=secs)
    return d1 + t1

def datetime_to_binary(dt: datetime.datetime) -> int:
    d1 = datetime.datetime(1, 1, 1)
    delta = dt - d1
    ticks = int(delta.total_seconds() * 1e7)
    return ticks & 0x3FFFFFFFFFFFFFFF
