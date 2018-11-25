#!/usr/bin/env python
# coding=utf-8

import os
from symbolfuzz import Debugger
from symbolfuzz import EmuConstant


binary_dir = str(os.path.join(os.path.dirname(__file__), '../example/binary/'))
library_dir = str(os.path.join(os.path.dirname(__file__), '../src/symbolfuzz/libhook/'))


def test_libhook():
    binary = os.path.join(binary_dir, "atoi")
    hooklib = os.path.join(library_dir, "libhook_x86.so")
    debugger = Debugger(EmuConstant.MODE_ELF, binary=binary, hook_library=hooklib)
    debugger.set_input("127")
    debugger.debug()


if __name__ == "__main__":
    test_libhook()