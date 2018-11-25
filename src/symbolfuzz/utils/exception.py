#!/usr/bin/env python
# coding=utf-8

from symbolfuzz.utils.static import EmuConstant


# Define basic exception class
class UnsupportedArchException(Exception):
    def __init__(self, arch):
        Exception.__init__(self, "Architecture %s is not supported yet" % str(arch))


class NotImplementedException(Exception):
    def __init__(self):
        Exception.__init__(self, "Sorry, this part is not implemented yet")


class UnknownEmulatorMode(Exception):
    def __init__(self, arch):
        Exception.__init__(self, "Unknown emulator mode " + str(arch))


class IllegalPcException(Exception):
    def __init__(self, arch, pc):
        if arch in EmuConstant.SUPPORT_ARCH:
            Exception.__init__(self, "PC address [0x%x] is illegal" % pc)
        else:
            raise UnsupportedArchException(arch)


class IllegalInstException(Exception):
    def __init__(self, arch, pc):
        if arch == 'x86':
            Exception.__init__(self, "Instruction at [0x%x] is illegal" % pc)
        else:
            raise UnsupportedArchException(arch)


class InfinityLoopException(Exception):
    def __init__(self, pc):
        Exception.__init__(self, "Encounter inifinity instruction at 0x%x" % pc)


class MemoryAccessException(Exception):
    def __init__(self, pc, addr):
        Exception.__init__(self, "Invalid memory [0x%x] access instruction at 0x%x" % (addr, pc))
