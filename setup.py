
import setuptools
import osz2
import os

current_directory = os.path.dirname(os.path.abspath(__file__))

with open(os.path.join(current_directory, "README.md"), "r") as f:
    long_description = f.read()

with open(os.path.join(current_directory, "requirements.txt"), "r") as f:
    requirements = f.read().splitlines()

setuptools.setup(
    name="osz2",
    version=osz2.__version__,
    author=osz2.__author__,
    author_email=osz2.__email__,
    install_requires=requirements,
    description="A python library for reading osz2 files",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=setuptools.find_packages(),
    keywords=["osu", "osz2", "python", "bancho"],
    python_requires=">=3.7",
)
