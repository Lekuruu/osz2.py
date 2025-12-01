
from osz2 import Osz2Package, MetadataType, KeyType
from pytest import fixture
from pathlib import Path

TESTS_DIR = Path(__file__).parent
FILES_DIR = TESTS_DIR / "files"
OSF2_FILES = list(FILES_DIR.glob("*.osf2"))

class TestOsf2Package:
    @fixture(params=OSF2_FILES, ids=lambda p: p.stem)
    def osf2_path(self, request) -> Path:
        return request.param

    def test_from_file(self, osf2_path: Path) -> None:
        package = Osz2Package.from_file(str(osf2_path), key_type=KeyType.OSF2)
        assert package is not None
        assert len(package.files) > 0
        assert len(package.metadata) > 0

    def test_from_bytes(self, osf2_path: Path) -> None:
        data = osf2_path.read_bytes()
        package = Osz2Package.from_bytes(data, key_type=KeyType.OSF2)
        assert package is not None
        assert len(package.files) > 0

    def test_metadata_only(self, osf2_path: Path) -> None:
        package = Osz2Package.from_file(str(osf2_path), metadata_only=True, key_type=KeyType.OSF2)
        assert len(package.metadata) > 0
        assert len(package.files) == 0

    def test_metadata_contains_required_fields(self, osf2_path: Path) -> None:
        package = Osz2Package.from_file(str(osf2_path), metadata_only=True, key_type=KeyType.OSF2)
        # 'Title' and 'Artist' are required for osf2 key generation
        assert MetadataType.Title in package.metadata
        assert MetadataType.Artist in package.metadata
