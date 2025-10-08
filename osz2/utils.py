
import datetime
import hashlib
import struct
import typing
import io

def bytes_to_uint32_array(data: bytes) -> typing.List[int]:
    return [x[0] for x in struct.iter_unpack("<I", data)]

def read_string(reader: io.BufferedReader) -> str:
    length = read_uleb128(reader)
    if length == 0:
        return ""
    return reader.read(length).decode("utf-8")

def write_string(string: str) -> bytes:
    encoded = string.encode("utf-8")
    buf = write_uleb128(len(encoded))
    return buf + encoded

def read_uleb128(reader: io.BufferedReader) -> int:
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
    buf = buffer
    if pos >= 0 and pos < len(buffer):
        buf = bytearray(buffer)
        buf[pos] ^= swap

    hash = bytearray(hashlib.md5(buf).digest())
    for i in range(8):
        hash[i], hash[i+8] = hash[i+8], hash[i]

    hash[5] ^= 0x2D
    return bytes(hash)

def datetime_from_binary(time: int) -> datetime.datetime:
    n_ticks = time & 0x3FFFFFFFFFFFFFFF
    secs = n_ticks / 1e7
    d1 = datetime.datetime(1, 1, 1)
    t1 = datetime.timedelta(seconds=secs)
    return d1 + t1
