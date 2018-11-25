#!/usr/bin/env python
# coding=utf-8

import os
from symbolfuzz import Fuzzer
binary_dir = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../example/binary/'))


def test_atoi():
    atoi_binary = os.path.join(binary_dir, 'atoi3')
    fuzzer = Fuzzer(atoi_binary)
    fuzzer.fuzz()


def test_strlen():
    atoi_binary = os.path.join(binary_dir, 'strlen')
    fuzzer = Fuzzer(atoi_binary)
    fuzzer.fuzz()


def test_one_byte_read():
    atoi_binary = os.path.join(binary_dir, 'one_byte_read')
    fuzzer = Fuzzer(atoi_binary)
    fuzzer.fuzz()


def test_sprintf_overflow():
    atoi_binary = os.path.join(binary_dir, 'sprintf_overflow')
    fuzzer = Fuzzer(atoi_binary)
    fuzzer.fuzz()


if __name__ == '__main__':
    test_atoi()
    # test_strlen()
