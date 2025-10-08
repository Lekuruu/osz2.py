
from osz2.package import Osz2Package
from pathlib import Path

import argparse
import sys
import os

def decrypt_osz2(filepath: str) -> Osz2Package:
    if not os.path.exists(filepath):
        print(f"Error: Input file does not exist: {filepath}", file=sys.stderr)

    print("Reading osz2 package...")
    return Osz2Package.from_file(filepath)

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

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("input", help="The path to the osz2 file to decrypt (required)")
    parser.add_argument("output", help="The path to put the extracted osz2 files (required)")
    args = parser.parse_args()

    osz2 = decrypt_osz2(args.input)
    save_osz2(osz2, args.output)

if __name__ == "__main__":
    main()
