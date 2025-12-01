
from osz2.keys import generate_osf2_key, generate_osz2_key
from osz2 import MetadataType
from hashlib import md5

class TestKeyGeneration:
    def test_osz2_key_generation(self) -> None:
        metadata = {
            MetadataType.Creator: "TestCreator",
            MetadataType.BeatmapSetID: "12345",
        }
        key = generate_osz2_key(metadata)
        expected = md5(b"TestCreatoryhxyfjo512345").digest()
        assert key == expected

    def test_osf2_key_generation(self) -> None:
        metadata = {
            MetadataType.Title: "TestTitle",
            MetadataType.Artist: "TestArtist",
        }
        key = generate_osf2_key(metadata)
        expected = md5("\x08TestTitle4390gn8931iTestArtist".encode()).digest()
        assert key == expected
