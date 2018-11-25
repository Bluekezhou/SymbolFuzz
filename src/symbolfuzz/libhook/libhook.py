#!/usr/bin/env python
# coding=utf-8


class LibHook(object):
    """This class is create to accelerate the emulation
    of a program. Two types of library function will be
    replaced. Type 1: Simple functions like puts, even
    removed, make no difference to security. Type 2:
    complex functions like atoi need a simpler way to
    emulate because symbolic execution is really slow.
    """
    def __init__(self, emulator, hook_library):
        self.emulator = emulator
        self.arch = emulator.arch
        self.hook_library = hook_library

    def process(self, *args):
        """Subclass should overwrite this function
        """
        print("Non-implemented library function")

    def exit(self):
        self.emulator.instrument("ret")


class AtoiHook(LibHook):
    """Library hooker for function atoi

    """
    def __init__(self, emulator, hook_library):
        super(AtoiHook, self).__init__(emulator, hook_library)

    def process(self):
        self.emulator.setpc(self.hook_library.symbols['atoi_hook'])


class PutsHook(LibHook):
    """Library hooker for function puts

    """
    def __init__(self, emulator, hook_library):
        super(PutsHook, self).__init__(emulator, hook_library)

    def process(self, address):
        data = self.emulator.get_memory_string(address)
        print(data)
        self.exit()


class PrintfHook(LibHook):
    """Library hooker for function puts

    """
    def __init__(self, emulator, hook_library):
        super(PrintfHook, self).__init__(emulator, hook_library)

    def process(self, format_str):
        pass


class StackCheckFailHook(LibHook):
    """Library hooker for function puts

    """
    def __init__(self, emulator, hook_library):
        super(StackCheckFailHook, self).__init__(emulator, hook_library)

    def process(self):
        self.emulator.setpc(0xdeadbeaf)


class StrcmpHook(LibHook):
    """Library hooker for function puts

    """
    def __init__(self, emulator, hook_library):
        super(StrcmpHook, self).__init__(emulator, hook_library)

    def process(self):
        self.emulator.setpc(self.hook_library.symbols['strcmp_hook'])
