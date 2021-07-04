from setuptools import setup, find_packages

setup(
    name="decompress_dispatch",
    version="0.0.1",
    author="Aaron Gee-Clough (@gclef_)",
    url="https://github.com/g-clef/stoq_transformer/decompress_dispatch",
    description="dispatch files to decompressor if the file is an archive, to workers if not.",
    packages=find_packages(),
    package_data={'decompress_dispatch': ['decompress_dispatch.stoq']},
)