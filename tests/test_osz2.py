
from osz2 import Osz2Package, MetadataType
from pytest import fixture
from pathlib import Path

TESTS_DIR = Path(__file__).parent
FILES_DIR = TESTS_DIR / "files"
OSZ2_FILES = list(FILES_DIR.glob("*.osz2"))

class TestOsz2Package:
    @fixture(params=OSZ2_FILES, ids=lambda p: p.stem)
    def osz2_path(self, request) -> Path:
        return request.param

    def test_from_file(self, osz2_path: Path) -> None:
        package = Osz2Package.from_file(str(osz2_path))
        assert package is not None
        assert len(package.files) > 0
        assert len(package.metadata) > 0

    def test_from_bytes(self, osz2_path: Path) -> None:
        data = osz2_path.read_bytes()
        package = Osz2Package.from_bytes(data)
        assert package is not None
        assert len(package.files) > 0

    def test_metadata_only(self, osz2_path: Path) -> None:
        package = Osz2Package.from_file(str(osz2_path), metadata_only=True)
        assert len(package.metadata) > 0
        assert len(package.files) == 0

    def test_metadata_contains_required_fields(self, osz2_path: Path) -> None:
        package = Osz2Package.from_file(str(osz2_path), metadata_only=True)
        # 'Creator' and 'BeatmapSetID' are required for osz2 key generation
        assert MetadataType.Creator in package.metadata
        assert MetadataType.BeatmapSetID in package.metadata

    def test_create_osz_package(self, osz2_path: Path) -> None:
        package = Osz2Package.from_file(str(osz2_path))
        osz_data = package.create_osz_package()
        assert len(osz_data) > 0
        assert osz_data[:2] == b"PK"

    def test_beatmap_content_is_valid(self, osz2_path: Path) -> None:
        package = Osz2Package.from_file(str(osz2_path))

        for beatmap in package.beatmap_files:
            # osu! beatmaps should start with "osu file format"
            content = beatmap.content.decode("utf-8-sig", errors="replace")
            assert "osu file format" in content

class TestOsz2ExportRoundtrip:
    @fixture(params=OSZ2_FILES, ids=lambda p: p.stem)
    def osz2_path(self, request) -> Path:
        return request.param

    def test_export_and_reimport(self, osz2_path: Path) -> None:
        original = Osz2Package.from_file(str(osz2_path))
        exported = original.export()
        reimported = Osz2Package.from_bytes(exported)

        # Compare metadata & file count
        assert reimported.metadata == original.metadata
        assert len(reimported.files) == len(original.files)

        # Compare file contents
        for original_file in original.files:
            reimported_file = reimported.find_file_by_name(original_file.filename)
            assert reimported_file is not None
            assert reimported_file.content == original_file.content
