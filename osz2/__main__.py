
from typing import Tuple, Dict, Union, Optional
from osz2.metadata import MetadataType
from osz2.package import Osz2Package
from osz2.keys import KeyType
from pathlib import Path

import argparse
import typing
import sys
import os

def main() -> None:
    parser = argparse.ArgumentParser(prog="osz2", description="A tool to decrypt, extract, and create osz2 files")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt and extract an osz2 file")
    decrypt_parser.add_argument("input", help="The path to the osz2 file to decrypt")
    decrypt_parser.add_argument("output", help="The path to put the extracted files")
    decrypt_parser.add_argument("--key-type", choices=["osz2", "osf2"], default="osz2", help="The key generation method")
    decrypt_parser.add_argument("--create-osz", action="store_true", help="Also create a regular .osz package")

    encrypt_parser = subparsers.add_parser("encrypt", help="Create an osz2 package from a directory")
    encrypt_parser.add_argument("input", help="The path to the directory containing files")
    encrypt_parser.add_argument("output", help="The output path for the osz2 file")
    encrypt_parser.add_argument("--key-type", choices=["osz2", "osf2"], default="osz2", help="The key generation method")

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        return

    key_type = KeyType(args.key_type)

    if args.command == "decrypt":
        osz2 = decrypt_osz2(args.input, key_type)
        save_osz2(osz2, args.output)

        if not args.create_osz:
            return

        with open(f"{args.output}/{osz2.osz_filename}", "wb") as f:
            osz_data = osz2.create_osz_package(exclude_disallowed_files=False)
            f.write(osz_data)

    elif args.command == "encrypt":
        encrypt_directory(
            args.input,
            args.output,
            key_type
        )

def decrypt_osz2(filepath: str, key_type: KeyType) -> Osz2Package:
    if not os.path.exists(filepath):
        print(f"Error: Input file does not exist: {filepath}", file=sys.stderr)
        sys.exit(1)

    print("Reading osz2 package...")
    return Osz2Package.from_file(filepath, key_type=key_type)

def save_osz2(package: Osz2Package, output: str) -> None:
    Path(output).mkdir(exist_ok=True)
    print(f"Extracting {len(package.files)} files to {output}")

    for file in package.files:
        output_path = os.path.join(output, file.filename_sanitized)

        if (directory := Path(output_path).parent) != ".":
            directory.mkdir(parents=True, exist_ok=True)

        with open(output_path, "wb") as f:
            f.write(file.content)

        print(f"  -> {file.filename} ({len(file.content)} bytes)")

def encrypt_directory(
    directory: str,
    output: str,
    key_type: KeyType
) -> None:
    if not os.path.exists(directory):
        print(f"Error: Input directory does not exist: {directory}", file=sys.stderr)
        sys.exit(1)

    print(f"Creating osz2 package from directory: {directory}")
    package = Osz2Package.from_directory(directory, key_type)

    # Try to parse beatmap metadata and apply it to package
    for beatmap in package.beatmap_files:
        _, content = parse_beatmap(beatmap.content.decode("utf-8-sig"))
        beatmap_id = content.get('Metadata', {}).get('BeatmapID', None)

        if beatmap_id is not None:
            package.set_beatmap_id(beatmap.filename, int(beatmap_id))

        apply_metadata(package, content)

    print(f"Exporting package with {len(package.files)} files...")
    bytes_written = package.save(output)
    print(f"Saved to: {output} ({bytes_written} bytes)")

def apply_metadata(package: Osz2Package, beatmap: Dict[str, dict]) -> None:
    if 'Metadata' not in beatmap:
        print("Error: No 'Metadata' section found in beatmap")
        sys.exit(1)

    metadata_section = beatmap['Metadata']
    title = metadata_section.get('Title', '')
    artist = metadata_section.get('Artist', '')
    title_unicode = metadata_section.get('TitleUnicode', '')
    artist_unicode = metadata_section.get('ArtistUnicode', '')
    creator = metadata_section.get('Creator', '')
    source = metadata_section.get('Source', '')
    tags = metadata_section.get('Tags', '')
    beatmapset_id = metadata_section.get('BeatmapSetID', -1)

    package.add_metadata(MetadataType.BeatmapSetID, beatmapset_id)
    package.add_metadata(MetadataType.Artist, artist)
    package.add_metadata(MetadataType.Creator, creator)
    package.add_metadata(MetadataType.Source, source)
    package.add_metadata(MetadataType.Title, title)
    package.add_metadata(MetadataType.TitleUnicode, title_unicode)
    package.add_metadata(MetadataType.ArtistUnicode, artist_unicode)
    package.add_metadata(MetadataType.Tags, tags)

@typing.no_type_check
def parse_beatmap(content: str) -> Tuple[int, Dict[str, dict]]:
    sections: Dict[str, Union[dict, list]] = {}
    current_section = None
    beatmap_version = 0

    for line in content.splitlines():
        if line.startswith('osu file format'):
            beatmap_version = int(line.removeprefix('osu file format v'))
            continue

        if line.startswith('[') and line.endswith(']'):
            # New section
            current_section = line.removeprefix('[').removesuffix(']')
            continue

        if current_section is None:
            continue

        if not line:
            continue

        if current_section in ('General', 'Editor', 'Metadata', 'Difficulty'):
            if current_section not in sections:
                sections[current_section] = {}

            # Parse key, value pair
            key, raw_value = (
                split.strip() for split in line.split(':', maxsplit=1)
            )

            # Try to parse float/int
            parsed_value = parse_number(raw_value) or raw_value
            section_dict: dict = sections[current_section]
            section_dict[key] = parsed_value
            continue

        if current_section not in sections:
            sections[current_section] = []

        # Append to list
        section_list: list = sections[current_section]
        section_list.append(line)

    return beatmap_version, sections

def parse_number(value: str) -> Optional[Union[int, float]]:
    for cast in (int, float):
        try:
            return cast(value.strip())
        except ValueError:
            continue
    return None

if __name__ == "__main__":
    main()
