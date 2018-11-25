#!/usr/bin/env python
# coding=utf-8

from setuptools import setup, find_packages
import sys, os

try:
    import triton
except Exception as e:
    print("Running emulator needs Triton")
    print("More information, please refer to https://github.com/JonathanSalwan/Triton")
    sys.exit(-1)

os.system("tar -xvf peda.tar.gz -C /usr/share/")
open('/root/.pwntools-cache/update', 'wb').write('never')

setup(
    name="symbolfuzz",
    version="1.0",
    author="bluecake",
    author_email="bluekezhou@qq.com",
    description="A symbolic execution fuzz tool for linux x86 program",
    license="BSD",
    keywords="fuzzer",
    url="https://github.com/Bluekezhou/SymbolFuzz",
    packages=find_packages("src"),
    package_dir={"": "src"},
    package_data={"": ["type"]},
    install_requires=[
        'pwntools',
        'termcolor',
        'nose'
    ],
)
