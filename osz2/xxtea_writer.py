
from .utils import write_uleb128
from .xxtea import XXTEA
from io import BytesIO
from typing import (
    BinaryIO,
    Iterable,
    Optional,
    Iterator,
    List
)

class XXTEAWriter(BinaryIO):
    """XXTEA encryption writer that encrypts data in chunks"""

    def __init__(self, key: List[int]) -> None:
        self.buffer: BytesIO = BytesIO()
        self.xxtea: XXTEA = XXTEA(key)

    def __enter__(self) -> "XXTEAWriter":
        return self

    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> None:
        self.buffer.close()

    def __iter__(self) -> Iterator[bytes]:
        return self

    def __next__(self) -> bytes:
        line = self.readline()
        if not line:
            raise StopIteration
        return line

    @property
    def closed(self) -> bool:
        return self.buffer.closed

    @property
    def mode(self) -> str:
        return "wb"

    @property
    def name(self) -> str:
        return getattr(self.buffer, 'name', '<xxtea_stream>')

    def readable(self) -> bool:
        return False

    def writable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return self.buffer.seekable()

    def write(self, data: bytes) -> int:  # type: ignore[override]
        if len(data) <= 0:
            return 0

        buf = bytearray(data)
        self.xxtea.encrypt(buf, 0, len(buf))
        return self.buffer.write(bytes(buf))

    def write_string(self, s: str) -> None:
        encoded = s.encode('utf-8')
        length = len(encoded)
        self.write(write_uleb128(length))
        self.write(encoded)

    def writelines(self, lines: Iterable[bytes]) -> None:  # type: ignore[override]
        for line in lines:
            self.write(line)

    def seek(self, offset: int, whence: int = 0) -> int:
        return self.buffer.seek(offset, whence)

    def tell(self) -> int:
        return self.buffer.tell()

    def flush(self) -> None:
        self.buffer.flush()

    def close(self) -> None:
        self.buffer.close()

    def fileno(self) -> int:
        return self.buffer.fileno()

    def isatty(self) -> bool:
        return self.buffer.isatty()

    def read(self, n: int = -1) -> bytes:
        raise NotImplementedError("XXTEAWriter is write-only")

    def readline(self, limit: int = -1) -> bytes:
        raise NotImplementedError("XXTEAWriter is write-only")

    def readlines(self, hint: int = -1) -> List[bytes]:
        raise NotImplementedError("XXTEAWriter is write-only")

    def truncate(self, size: Optional[int] = None) -> int:
        return self.buffer.truncate(size)

    def getvalue(self) -> bytes:
        return self.buffer.getvalue()
