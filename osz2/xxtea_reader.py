
from .xxtea import XXTEA
from io import BytesIO
from typing import (
    BinaryIO,
    Iterable,
    Optional,
    Iterator,
    List
)

class XXTEAReader(BinaryIO):
    """XXTEA decryption reader that decrypts data in chunks"""

    def __init__(self, reader: BytesIO, key: List[int]) -> None:
        self.reader: BytesIO = reader
        self.xxtea: XXTEA = XXTEA(key)

    def __enter__(self) -> "XXTEAReader":
        return self

    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> None:
        self.reader.close()

    def __iter__(self) -> Iterator[bytes]:
        return self

    def __next__(self) -> bytes:
        line = self.readline()
        if not line:
            raise StopIteration
        return line

    @property
    def closed(self) -> bool:
        return self.reader.closed

    @property
    def mode(self) -> str:
        return "rb"

    @property
    def name(self) -> str:
        return getattr(self.reader, 'name', '<xxtea_stream>')

    def readable(self) -> bool:
        return True

    def writable(self) -> bool:
        return False

    def seekable(self) -> bool:
        return self.reader.seekable()

    def read(self, n: int = -1) -> bytes:
        read = bytearray(self.reader.read(n))
        if len(read) > 0:
            self.xxtea.decrypt(read, 0, len(read))
        return bytes(read)

    def seek(self, offset: int, whence: int = 0) -> int:
        return self.reader.seek(offset, whence)

    def tell(self) -> int:
        return self.reader.tell()

    def flush(self) -> None:
        self.reader.flush()

    def close(self) -> None:
        self.reader.close()

    def fileno(self) -> int:
        return self.reader.fileno()

    def isatty(self) -> bool:
        return self.reader.isatty()

    def readline(self, limit: int = -1) -> bytes:
        raise NotImplementedError("readline is not supported for encrypted streams")

    def readlines(self, hint: int = -1) -> List[bytes]:
        raise NotImplementedError("readlines is not supported for encrypted streams")

    def write(self, s: bytes) -> int:  # type: ignore[override]
        raise NotImplementedError("XXTEAReader is read-only")

    def writelines(self, lines: Iterable[bytes]) -> None:  # type: ignore[override]
        raise NotImplementedError("XXTEAReader is read-only")

    def truncate(self, size: Optional[int] = None) -> int:
        raise NotImplementedError("XXTEAReader is read-only")
