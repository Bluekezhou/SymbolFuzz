#!/usr/bin/env python
# coding=utf-8

"""
Module Name: Recognizer.py
Create by: Bluecake
Description: A class to recognize library function
"""

from pwn import ELF
import os
from symbolfuzz.utils.signature import Signature


class Recognizer(object):

    def __init__(self, binary):
        self.binary = binary
        self.elf = ELF(binary)
        self.address_info = {}
        if self.is_static():
            self.lib_sign = None
            self.target_sign = None

        self.prepare()

    def prepare(self):
        if not self.is_static():
            for k in self.elf.plt:
                self.address_info[self.elf.plt[k]] = {
                    "type": "plt",
                    "name": k
                }
        else:
            work_dir = os.path.dirname(__file__)
            sign_file = os.path.join(work_dir, "signature/signature")
            self.lib_sign = Signature(sign_file)
            self.target_sign = Signature(self.binary)

    def is_static(self):
        """ Check whether target program is compiled statically

        Returns:
            boolean, True or False
        """
        if not self.elf.plt:
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
        if entry in self.address_info:
            return self.address_info[entry]["name"]

        elif self.is_static():
            func_sign = self.target_sign.get_sign(entry)
            name = self.lib_sign.match_sign(func_sign)

            result = {
                "type": "func",
                "name": name
            }
            self.address_info[entry] = result
            return name

        result = {
            "type": "func",
            "name": None
        }
        self.address_info[entry] = result
        return None
