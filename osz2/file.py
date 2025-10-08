
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
