
from .metadata import MetadataType
from typing import Callable, Dict
from hashlib import md5
from enum import Enum

# NOTE: osu!stream and osu! have different key generation methods, which can be found here:
#       https://github.com/ppy/osu-stream/blob/master/osu!stream/Helpers/osu!common/MapPackage.cs#L244

class KeyType(Enum):
    OSZ2 = "osz2"
    OSF2 = "osf2"

def generate_osz2_key(metadata: Dict[MetadataType, str]) -> bytes:
    assert MetadataType.Creator in metadata, "Metadata is missing creator"
    assert MetadataType.BeatmapSetID in metadata, "Metadata is missing beatmapset ID"

    creator = metadata[MetadataType.Creator]
    beatmapset_id = metadata[MetadataType.BeatmapSetID]
    seed = f"{creator}yhxyfjo5{beatmapset_id}"
    return md5(seed.encode("utf-8")).digest()

def generate_osf2_key(metadata: Dict[MetadataType, str]) -> bytes:
    assert MetadataType.Title in metadata, "Metadata is missing title"
    assert MetadataType.Artist in metadata, "Metadata is missing artist"
    
    title = metadata[MetadataType.Title]
    artist = metadata[MetadataType.Artist]
    seed = f"\x08{title}4390gn8931i{artist}"
    return md5(seed.encode("utf-8")).digest()

KeyGenerator = Callable[[Dict[MetadataType, str]], bytes]
Mapping: Dict[KeyType, KeyGenerator] = {
    KeyType.OSZ2: generate_osz2_key,
    KeyType.OSF2: generate_osf2_key,
}
