# osz2.py

[![Python Version](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/)
[![GitHub License](https://img.shields.io/github/license/Lekuruu/osz2.py)](https://github.com/Lekuruu/osz2.py/blob/main/LICENSE)
[![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/Lekuruu/osz2.py/.github%2Fworkflows%2Fbuild.yml)](https://github.com/Lekuruu/osz2.py/actions/workflows/build.yml)

osz2.py is a Python library for reading osz2 files. It's a direct port of the existing [Osz2Decryptor](https://github.com/xxCherry/Osz2Decryptor) project by [xxCherry](https://github.com/xxCherry) and [osz2-go](https://github.com/Lekuruu/osz2-go) by me. The Python port itself was done by [@ascenttree](https://github.com/ascenttree); all credit goes to them. I took part in code refactoring and optimizing the performance by moving the heavy crypto primitives into a native C extension (`osz2.crypto`) on top of [NumPy](https://numpy.org/), bringing encryption time down to ~100 ms  instead of 25 seconds.

This project *won't* provide beatmap parsing support. You will have to implement that by yourself, if you decide to use this library for implementing the beatmap submission system.

## Installation

```bash
pip install osz2
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
python -m osz2 decrypt <input.osz2> <output_directory>
```

```bash
python -m osz2 encrypt <target_directory> <output.osz2>
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

# Create a regular .osz package
with open("beatmap.osz", "wb") as f:
    f.write(package.create_osz_package())
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

### Exporting an osz2 package

You can initialize and export osz2 packages from a directory:

```python
from osz2 import Osz2Package, MetadataType

# Initialize package from a directory containing beatmap files
package = Osz2Package.from_directory("./my_beatmap_folder")

# Export to osz2 format
osz2_data = package.export()

with open("output.osz2", "wb") as f:
    f.write(osz2_data)

# Or save directly to a file
package.save("./output.osz2")
```

### Managing Files

You can add, remove, and modify files within a package:

```python
from osz2 import Osz2Package, MetadataType

# Create a new package
package = Osz2Package()

# Add metadata (required for export)
package.add_metadata(MetadataType.Title, "My Beatmap")
package.add_metadata(MetadataType.Artist, "Artist Name")
package.add_metadata(MetadataType.Creator, "Mapper Name")
package.add_metadata(MetadataType.BeatmapSetID, 123456)

# Add a file from memory
beatmap_content = b"osu file format v14\n..."
package.add_file("my_beatmap.osu", beatmap_content)

# Add a file from disk
package.add_file_from_disk("audio.mp3", "./path/to/audio.mp3")

# Add an entire directory (non-recursive)
package.add_directory("./beatmap_files", recursive=False)

# Add an entire directory (recursive, preserves folder structure)
package.add_directory("./beatmap_folder", recursive=True)

# Remove a file
package.remove_file("old_file.osu")

# Find a file by name
file = package.find_file_by_name("audio.mp3")
if file:
    print(f"Found: {file.filename}, size: {file.size}")

# Set beatmap IDs
package.set_beatmap_id("my_beatmap.osu", 789012)

# Export the package
package.save("my_beatmap.osz2")
```

### Managing Metadata

Metadata can be added, retrieved, and removed:

```python
from osz2 import Osz2Package, MetadataType

package = Osz2Package.from_file("beatmap.osz2")

# Add or update metadata
package.add_metadata(MetadataType.Title, "New Title")
package.add_metadata(MetadataType.Artist, "New Artist")

# Get metadata
title = package.get_metadata(MetadataType.Title)
print(f"Title: {title}")

# Remove metadata
package.remove_metadata(MetadataType.Difficulty)

# Convenience method for setting beatmapset ID
package.set_beatmapset_id(999999)

# Save changes
package.save("modified.osz2")
```

### Applying a patch

When developing an implementation of the beatmap submission system, this could come in handy:

```python
# Assuming you have a source osz2 file and a patch file
osz2_file = b"..."
patch_file = b"..."

updated_osz2 = osz2.apply_bsdiff_patch(osz2_file, patch_file)
osz2 = Osz2Package.from_bytes(updated_osz2)
```

### Using osu!stream .osf2 files

I have not tested this, but in theory this should work by passing in `KeyType.OSF2` when initializing the osz2 package:

```python
osf2 = Osz2Package.from_file("beatmap.osf2", key_type=KeyType.OSF2)
```

You can also specify this when using the command-line interface:

```bash
python -m osz2 <input.osz2> <output_directory> --key-type osf2
```

## Building the crypto.c extension

If you change any code under `osz2/crypto.c`, rebuild the module in place before running tests:

```bash
python -m venv venv
source venv/bin/activate
pip install -e .
```

Or, if you only need the extension locally:

```bash
python setup.py build_ext --inplace
```

The resulting shared object is picked up automatically by the package import system.
