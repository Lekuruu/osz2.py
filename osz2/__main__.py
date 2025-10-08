
from osz2.package import Osz2Package, KeyType
from pathlib import Path

import argparse
import sys
import os

def decrypt_osz2(filepath: str, key_type: KeyType) -> Osz2Package:
    if not os.path.exists(filepath):
        print(f"Error: Input file does not exist: {filepath}", file=sys.stderr)

    print("Reading osz2 package...")
    return Osz2Package.from_file(filepath, key_type=key_type)

def save_osz2(package: Osz2Package, output: str) -> None:
    Path(output).mkdir(exist_ok=True)
    print(f"Extracting {len(package.files)} files to {output}")

    for file in package.files:
        output_path = os.path.join(output, file.filename)

        if (dir := Path(output_path).parent) != ".":
            dir.mkdir(parents=True, exist_ok=True)

        with open(output_path, "wb") as f:
            f.write(file.content)

        print(f"  -> {file.filename} ({len(file.content)} bytes)")

def main() -> None:
    parser = argparse.ArgumentParser(prog="osz2", description="A tool to decrypt and extract osz2 files")
    parser.add_argument("input", help="The path to the osz2 file to decrypt (required)")
    parser.add_argument("output", help="The path to put the extracted osz2 files (required)")
    parser.add_argument("--key-type", choices=["osz2", "osf2"], default="osz2", help="The key generation method to use (default: osz2)")
    args = parser.parse_args()
    key_type = KeyType(args.key_type)

    osz2 = decrypt_osz2(args.input, key_type)
    save_osz2(osz2, args.output)

if __name__ == "__main__":
    main()
