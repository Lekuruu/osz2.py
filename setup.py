from setuptools import Extension, setup  # type: ignore[import-untyped]

setup(
    ext_modules=[
        Extension(
            name="osz2.crypto",
            sources=["osz2/crypto.c"],
        )
    ]
)
