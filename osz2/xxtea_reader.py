
from osz2.xxtea import XXTEA
from io import BytesIO

class XXTeaReader:
    def __init__(self, reader: BytesIO, key: list[int]) -> None:
        self.reader: BytesIO = reader
        self.xxtea: XXTEA = XXTEA(key)

    def read(self, n: int) -> bytes:
        read = bytearray(self.reader.read(n))
        self.xxtea.decrypt(read, 0, n)
        return bytes(read)
