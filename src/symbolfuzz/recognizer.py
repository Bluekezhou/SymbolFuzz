#!/usr/bin/env python
# coding=utf-8

"""
Module Name: Recognizer.py
Create by: Bluecake
Description: A class to recognize library function
"""

from pwn import ELF
from emulator import Emulator, EmuConstant


class Recognizer(object):

    def __init__(self, binary, seed=""):
        self.binary = binary
        self.emulator = Emulator(EmuConstant.MODE_ELF, binary=binary)
        self.elf = ELF(binary)
        self.address_info = {}
        for k in self.elf.plt:
            self.address_info[self.elf.plt[k]] = {
                "type": "plt",
                "name": k
            }

    def is_static_compiled(self):
        """ Check whether target program is compiled statically

        Returns:
            boolean, True or False
        """
        if not self.elf.got:
            return True
        else:
            return False

    def is_pie(self):
        """ Check whether target program is compiled with PIE

        Returns:
            boolean, True or False
        """
        return self.elf.pie

    def is_plt_entry(self, address):
        """ Check whether target address is plt entrypoint

        Args:
            address: target pc address

        Returns:
            boolean, True or False
        """
        if address in self.address_info and \
                self.address_info[address]['type'] == "plt":
            return True
        else:
            return False

    def get_label(self, entry):
        """ Label function with given function entry, not matter jmp_plt
            or real function body

        Args:
            entry: address of first instruction after call instruction or
                   start of function

        Returns:
            name of function, if recognized, otherwise None
        """
        pass

    def get_call_func(self, pc):
        """ Get called function name, like call 0x8048020, actually
        it's calling atoi()

        Args:
            pc: address of call instruction

        Returns:
            name of called function if recognized, otherwise None
        """

        pass
