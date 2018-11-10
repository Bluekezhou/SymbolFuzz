#!/usr/bin/env python
# coding=utf-8

""" For unknown reason, triton didn't work properly when meets
instruction like "rep mov". So I create this script to check
whether this bug is fixed. """


from symbolfuzz import Emulator, EmuConstant, Debugger
from triton import ARCH


def test_rep_movsd_x86():
    insts = "mov ecx, 5; mov edi, 0x1000; mov esi, 0x2000; rep movsd [edi], [esi]; mov eax, 0"
    emulator = Emulator(EmuConstant.MODE_CODE, arch=ARCH.X86, code=insts, assembly=True, code_start=0x3000)
    emulator.set_memory(0x1000, "a" * 50)
    emulator.set_memory(0x2000, "b" * 50)



def test_rep_movsd_x64():
     insts = "mov rcx, 5; mov rdi, 0x1000; mov rsi, 0x2000; rep movsd [rdi], [rsi]; mov rax, 0"
     emu = Debugger(EmuConstant.MODE_CODE, arch=ARCH.X86_64, code=insts, assembly=True, code_start=0x3000)
     emu.set_memory(0x1000, "a" * 50)
     emu.set_memory(0x2000, "b" * 50)
     emu.debug()


if __name__ == "__main__":
    test_rep_movsd_x64()