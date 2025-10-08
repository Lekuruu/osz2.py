
from osz2.xxtea import XXTEA
from typing import List
from io import BytesIO

class XXTEAReader:
    def __init__(self, reader: BytesIO, key: List[int]) -> None:
        self.reader: BytesIO = reader
        self.xxtea: XXTEA = XXTEA(key)

    @property
    def encrypted_data(self) -> bytes:
        return self.reader.getvalue()

    def __enter__(self) -> "XXTEAReader":
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.reader.close()

    def read(self, n: int) -> bytes:
        read = bytearray(self.reader.read(n))
        self.xxtea.decrypt(read, 0, n)
        return bytes(read)
