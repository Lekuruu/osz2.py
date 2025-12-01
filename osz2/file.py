
from .constants import ALLOWED_FILE_EXTENSIONS, VIDEO_FILE_EXTENSIONS
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
    def file_extension(self) -> str:
        return (
            self.filename.split('.')[-1].lower()
            if '.' in self.filename else ''
        )

    @property
    def is_allowed_extension(self) -> bool:
        return self.file_extension in ALLOWED_FILE_EXTENSIONS

    @property
    def is_video(self) -> bool:
        return self.file_extension in VIDEO_FILE_EXTENSIONS

    @property
    def is_beatmap(self) -> bool:
        return self.filename.endswith('.osu')
    
    @property
    def is_combined_beatmap(self) -> bool:
        # NOTE: This is an osu!stream specific file format
        # https://github.com/ppy/osu-stream/blob/master/BeatmapCombinator/Program.cs#L31
        return self.filename.endswith('.osc')
