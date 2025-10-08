# osz2.py

[![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)
[![GitHub License](https://img.shields.io/github/license/Lekuruu/osz2.py)](https://github.com/Lekuruu/osz2.py/blob/main/LICENSE)

osz2.py is a Python library for reading osz2 files. It's a direct port of the existing [Osz2Decryptor](https://github.com/xxCherry/Osz2Decryptor) project by [xxCherry](https://github.com/xxCherry) and [osz2-go](https://github.com/Lekuruu/osz2-go) by me. The Python port itself was done by [@ascenttree](https://github.com/ascenttree); all credit goes to them.

## Installation

```bash
pip install git+https://github.com/Lekuruu/osz2.py@main
```

Or install from source:

```bash
git clone https://github.com/Lekuruu/osz2.py
cd osz2.py
pip install -e .
```

## Usage

This repository provides a command-line interface for easy testing:

```bash
python cli.py <input.osz2> <output_directory>
```

But that's not all!  
Here is an example of how to use osz2.py as a library:

```python
from osz2 import Osz2Package, MetadataType

# Parse package from file
package = Osz2Package.from_file("beatmap.osz2")

# Access metadata
print("Title:", package.metadata.get(MetadataType.Title))
print("Artist:", package.metadata.get(MetadataType.Artist))
print("Creator:", package.metadata.get(MetadataType.Creator))
print("Difficulty:", package.metadata.get(MetadataType.Difficulty))

# Access files
for file in package.files:
    print(f"File: {file.filename}, Size: {len(file.content)} bytes")

# Extract specific files
for file in package.files:
    if not file.filename.endswith(".osu"):
        continue

    with open(file.filename, "wb") as f:
        f.write(file.content)
```

### Metadata-only Mode

If you only need to read metadata without extracting files, you can use the `metadata_only` parameter:

```python
# Only parse metadata
package = Osz2Package.from_file("beatmap.osz2", metadata_only=True)

# Access metadata
print("Title:", package.metadata.get(MetadataType.Title))
print("BeatmapSet ID:", package.metadata.get(MetadataType.BeatmapSetID))
```

### Alternative Constructors

```python
# From file path
package = Osz2Package.from_file("beatmap.osz2")

# From bytes
with open("beatmap.osz2", "rb") as f:
    data = f.read()
    package = Osz2Package.from_bytes(data)

# From an io.BufferedReader-like object, e.g. a file stream
with open("beatmap.osz2", "rb") as f:
    package = Osz2Package(f)
```
