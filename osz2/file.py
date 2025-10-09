
from .constants import ALLOWED_FILE_EXTENSIONS
from dataclasses import dataclass
from datetime import datetime

@dataclass
class File:
    filename: str
    offset: int
    size: int
    hash: bytes
    date_created: datetime
    date_modified: datetime
    content: bytes

    @property
    def is_beatmap(self) -> bool:
        return self.filename.endswith('.osu')

    @property
    def file_extension(self) -> str:
        return (
            self.filename.split('.')[-1].lower()
            if '.' in self.filename else ''
        )

    @property
    def is_allowed_extension(self) -> bool:
        return self.file_extension in ALLOWED_FILE_EXTENSIONS
