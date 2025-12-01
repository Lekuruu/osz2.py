
from pytest import fixture
from pathlib import Path

TESTS_DIR = Path(__file__).parent

@fixture
def tests_dir() -> Path:
    """Return the tests directory path"""
    return TESTS_DIR

@fixture
def osz2_files() -> list:
    """Return all osz2 files in the tests directory"""
    return list(TESTS_DIR.glob("*.osz2"))
