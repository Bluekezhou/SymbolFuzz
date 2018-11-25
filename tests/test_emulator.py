#!/usr/bin/env python
# coding=utf-8
import os
import nose
from symbolfuzz import *

# context.log_level = "DEBUG" 
binary_dir = str(os.path.join(os.path.dirname(__file__), '../example/binary/'))
library_dir = str(os.path.join(os.path.dirname(__file__), '../src/symbolfuzz/libhook/'))


def test_emulator():
    binary = os.path.join(binary_dir, "atoi")
    hooklib = os.path.join(library_dir, "libhook_x86.so")
    nose.tools.assert_equals(os.path.exists(binary), True)
    
    emu = Debugger(EmuConstant.MODE_ELF, binary=binary, hook_library=hooklib)
    emu.set_input("AAAAAAAA")
    emu.show_inst = True
    emu.debug()
    while emu.running:
        emu.process()


if __name__ == '__main__':
    test_emulator()
