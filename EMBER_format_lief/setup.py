from setuptools import setup, find_packages

setup(
    name="EMBER_format_lief",
    version="0.0.1",
    author="Aaron Gee-Clough (@gclef_)",
    url="https://github.com/g-clef/stoq_transformer/EMBER_format_lief",
    description="Parse and abstract PE, ELF and MachO files using LIEF, and return them in EMBER dataset format",
    packages=find_packages(),
    package_data={'EMBER_format_lief': ['EMBER_format_lief.stoq']},
)