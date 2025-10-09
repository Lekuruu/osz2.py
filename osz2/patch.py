
import bsdiff4
import gzip
import io

def apply_osz2_patch(source_osz2: bytes, patch_bytes: bytes) -> bytes:
    """Apply a BSDIFF4-format patch to an osz2 package."""
    return bsdiff4.core.patch(
        source_osz2,
        *read_gzip_patch(patch_bytes)
    )

def read_gzip_patch(patch_bytes: bytes, compressor=gzip) -> tuple:
    """
    Read a BSDIFF4-format patch from bytes 'patch_bytes'
    with control over the compression algorithm.
    (osu! uses gzip compression for its patches)
    """
    fi = io.BytesIO(patch_bytes)
    magic = fi.read(8)

    if magic[:7] != b'BSDIFF40'[:7]:
        raise ValueError("incorrect magic bsdiff4 header")

    # length headers
    len_control = bsdiff4.core.decode_int64(fi.read(8))
    len_diff = bsdiff4.core.decode_int64(fi.read(8))
    len_dst = bsdiff4.core.decode_int64(fi.read(8))

    # read the control header
    bcontrol = compressor.decompress(fi.read(len_control))
    tcontrol = [
        (bsdiff4.core.decode_int64(bcontrol[i:i + 8]),
         bsdiff4.core.decode_int64(bcontrol[i + 8:i + 16]),
         bsdiff4.core.decode_int64(bcontrol[i + 16:i + 24]))
         for i in range(0, len(bcontrol), 24)
    ]

    # read the diff and extra blocks
    bdiff = compressor.decompress(fi.read(len_diff))
    bextra = compressor.decompress(fi.read())
    return len_dst, tcontrol, bdiff, bextra
