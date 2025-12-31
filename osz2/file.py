
from .constants import ALLOWED_FILE_EXTENSIONS, VIDEO_FILE_EXTENSIONS
from .utils import sanitize_filename
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

    def __repr__(self) -> str:
        return f"<File '{self.filename}' ({self.size} bytes)>"

    @property
    def file_extension(self) -> str:
        name = self.filename.strip().lower()
        name_parts = name.rsplit('.', 1)
        return name_parts[1] if len(name_parts) == 2 else ''

    @property
    def filename_sanitized(self) -> str:
        return sanitize_filename(self.filename)

    @property
    def is_allowed_extension(self) -> bool:
        return self.file_extension in ALLOWED_FILE_EXTENSIONS

    @property
    def is_video(self) -> bool:
        return self.file_extension in VIDEO_FILE_EXTENSIONS

    @property
    def is_beatmap(self) -> bool:
        return self.file_extension == 'osu'
    
    @property
    def is_combined_beatmap(self) -> bool:
        # NOTE: This is an osu!stream specific file format
        # https://github.com/ppy/osu-stream/blob/master/BeatmapCombinator/Program.cs#L31
        return self.file_extension == 'osc'
