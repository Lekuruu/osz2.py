
from enum import IntEnum

class MetadataType(IntEnum):
    Title = 0
    Artist = 1
    Creator = 2
    Version = 3
    Source = 4
    Tags = 5
    VideoDataOffset = 6
    VideoDataLength = 7
    VideoHash = 8
    BeatmapSetID = 9
    Genre = 10
    Language = 11
    TitleUnicode = 12
    ArtistUnicode = 13
    Unknown = 9999
    Difficulty = 10000
    PreviewTime = 10001
    ArtistFullName = 10002
    ArtistTwitter = 10003
    SourceUnicode = 10004
    ArtistURL = 10005
    Revision = 10006
    PackID = 10007
