
from .utils import write_uleb128
from .xxtea import XXTEA
from typing import List
from io import BytesIO

class XXTEAWriter:
    """XXTEA encryption writer that encrypts data in chunks"""

    def __init__(self, key: List[int]) -> None:
        self.buffer: BytesIO = BytesIO()
        self.xxtea: XXTEA = XXTEA(key)

    def __enter__(self) -> "XXTEAWriter":
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.buffer.close()

    def write(self, data: bytes) -> None:
        if len(data) <= 0:
            return

        buf = bytearray(data)
        self.xxtea.encrypt(buf, 0, len(buf))
        self.buffer.write(bytes(buf))

    def write_string(self, s: str) -> None:
        encoded = s.encode('utf-8')
        length = len(encoded)
        self.write(write_uleb128(length))
        self.write(encoded)

    def getvalue(self) -> bytes:
        return self.buffer.getvalue()
