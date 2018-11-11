#!/usr/bin/env python
# coding=utf-8

"""
Module Name: Signature.py
Create by: Bluecake
Description: A class to get function signature
"""

from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
import os
import json
from pwn import ELF
from triton import ARCH
from utils import get_arch, UnsupportedArchException, md5, LogUtil
import subprocess
import re
import copy
import time


class Signature:

    def __init__(self, executable):
        """ init function

        Args:
            executable: target executable file path
        """
        self.logger = LogUtil.get_logger()
        self.executable = executable
        self.elf = ELF(executable)
        self.arch = get_arch(self.elf)

        self.functions = {}
        self.addr2func = {}
        self.get_func()

        self.signs = {}
        self.explored_addr = []

        self.matched = {}

        self.sign_cache_file = "/tmp/" + md5(executable) + "_sign.cache"
        if os.path.exists(self.sign_cache_file):
            with open(self.sign_cache_file) as f:
                data = f.read()
                try:
                    self.signs = json.loads(data)
                except Exception as e:
                    self.logger.error(str(e))

    def save_sign(self):
        with open(self.sign_cache_file, 'w') as f:
            f.write(json.dumps(self.signs))

    def get_func(self):
        """ get executable exported function list

        Return:
            a dict, like {"function", offset}
        """
        if not self.functions:
            cmd = ["readelf", "--syms", self.executable]
            result = subprocess.check_output(cmd)
            lines = result.splitlines()
            lines = [l for l in lines if ' FUNC ' in l]
            for l in lines:
                """
                   889: 0804f0b0    30 FUNC    GLOBAL DEFAULT    6 __printf
                   959: 080ecd38     4 OBJECT  GLOBAL DEFAULT   24 __printf_modifier_table
                  1029: 08083df0     5 FUNC    GLOBAL DEFAULT    6 __register_printf_functio
                """
                match = re.findall(r".*:\s+(\w+).*\s+(\w+)", l)
                if not match:
                    continue

                offset = int(match[0][0], 16)
                name = match[0][1]
                self.functions[name] = offset
                self.addr2func[offset] = name

        return self.functions

    def disasm(self, base, code):
        """disassemble binary code

        Args:
            base: base address of code
            code: binary code

        Returns:
            list of instruction
        """
        result = []
        if self.arch == ARCH.X86:
            md = Cs(CS_ARCH_X86, CS_MODE_32)
            for i in md.disasm(code, base):
                result.append(i)

        elif self.arch == ARCH.X86_64:
            md = Cs(CS_ARCH_X86, CS_MODE_64)
            for i in md.disasm(code, base):
                result.append(i)

        else:
            raise UnsupportedArchException(self.arch)

        return result

    def search(self, offset, old_blocks):
        """Search new code blocks

        Args:
            offset: entrypoint of target block
            old_blocks: block list which has already been explored

        Return:
            a list, new found blocks

        """
        condition_jmp = ["jc", "jnc", "jz", "jnz", "js", "jns", "jo", "jno",
                         "jp", "jpe", "jnp", "jpo", "ja", "jnbe", "jae", "jnb",
                         "jb", "jnae", "jbe", "jna", "je", "jne", "jg", "jnle",
                         "jge", "jnl", "jnge", "jle", "jng"]

        ptr = offset
        new_blocks = []
        finished = False
        while not finished:
            code = self.elf.read(ptr, 64)
            body = self.disasm(ptr, code)
            if not body:
                break

            last_inst = body[-1]
            ptr = last_inst.address + last_inst.size

            for inst in body:
                if inst.address not in self.explored_addr:
                    self.inst_count += 1
                    self.explored_addr.append(inst.address)

                # print("0x%x:\t%s\t%s" % (inst.address, inst.mnemonic, inst.op_str))
                if inst.mnemonic in condition_jmp:
                    self.edge_count += 2
                    if inst.op_str.startswith("0x"):
                        branch1 = int(inst.op_str, 16)
                        if branch1 not in old_blocks:
                            new_blocks.append(branch1)

                    branch2 = inst.address + inst.size
                    if branch2 not in old_blocks:
                        new_blocks.append(branch2)

                    finished = True
                    break

                elif inst.mnemonic in ['jmp']:
                    # we can only deal with absolute jmp
                    if inst.op_str.startswith("0x"):
                        block = int(inst.op_str, 16)
                        if block not in old_blocks:
                            new_blocks.append(block)

                        self.edge_count += 1

                    finished = True
                    break

                elif inst.mnemonic in ['call']:
                    # print inst.op_str
                    if inst.op_str.startswith("0x"):
                        address = int(inst.op_str, 16)
                        if address not in self.call_func:
                            self.call_func.append(address)

                elif inst.mnemonic in ['ret']:
                    finished = True
                    break

        return new_blocks

    def _get_sign(self, entry):
        """get one-level signature

        Args:
            entry: entrypoint of target function

        Returns:
            a dict, function signature
        """
        if entry in self.signs:
            return self.signs[entry]

        unanalyzed = [entry]
        analyzed = []

        self.inst_count = 0
        self.call_func = []
        self.edge_count = 0

        while unanalyzed:
            new_block = unanalyzed.pop(0)
            if new_block in analyzed:
                continue

            analyzed.append(new_block)
            new_blocks = self.search(new_block, analyzed)
            unanalyzed.extend(new_blocks)

        result = {
            # "entrypoint": entry,
            "block_count": len(analyzed),
            "edge_count": self.edge_count,
            "inst_count": self.inst_count,
            "call_func": self.call_func
        }

        self.signs[entry] = result

        return result

    def get_sign(self, entry, level=5):
        """get n-level signature

        Args:
            entry: entrypoint of targeted function
            level: depth of function call

        Returns:
            a dict, function signature
        """
        sign = copy.deepcopy(self._get_sign(entry))

        callee_sign = []
        if level > 0 and len(sign['call_func']) > 0:
            for f in sign['call_func']:
                callee_sign.append(self.get_sign(f, level - 1))

        sign['callee_sign'] = callee_sign
        return sign

    @staticmethod
    def big_small(a1, a2):
        if a1 < a2:
            return a2, a1
        else:
            return a1, a2

    @staticmethod
    def int_similarity(a1, a2):
        big, small = Signature.big_small(a1, a2)
        if small == 0 and big == 0:
            return 1

        return (small / float(big)) ** 2

    @staticmethod
    def similarity(sign1, sign2):
        """Get similarity degree of two function signatures

        Args:
            sign1: signature one
            sign2: signature two

        Returns:
            a float, the bigger the result is, the higher the similarity is.
        """
        p1 = Signature.int_similarity(sign1['block_count'], sign2['block_count'])
        p2 = Signature.int_similarity(sign1['inst_count'], sign2['inst_count'])
        p3 = Signature.int_similarity(sign1['edge_count'], sign2['edge_count'])

        callee_sign1 = sign1['callee_sign']
        callee_sign2 = sign2['callee_sign']
        if abs(len(callee_sign1) - len(callee_sign2)) > 3:
            return p1 + p2 + p3

        p4 = 0
        i, j = 0, 0
        while i < len(callee_sign1) and j < len(callee_sign2):
            p = Signature.similarity(callee_sign1[i], callee_sign2[j])
            if p < 1:
                if len(callee_sign1) < len(callee_sign2):
                    j += 1
                elif len(callee_sign1) > len(callee_sign2):
                    i += 1
                else:
                    p4 += p
                    i += 1
                    j += 1
            else:
                p4 += p
                i += 1
                j += 1

        return p1 + p2 + p3 + p4

    @staticmethod
    def hash(sign):
        """get hash value of target signature

        Args:
            sign: target function signature

        Returns:
            a integer, hash value
        """
        def _hash(_base, _sign):
            return _base * _sign['block_count'] * 2 + _base * _sign['inst_count'] \
                   + _sign['edge_count']

        p1 = _hash(0xdeadbeaf, sign)
        for s in sign['callee_sign']:
            p1 ^= Signature.hash(s)

        return p1

    def match_sign(self, sign):
        """find the best-matched function from given signature symbol file

        Args:
            sign: target function signature

        Returns:
            name of best-matched function
        """
        t1 = time.time()
        sign_hash = Signature.hash(sign)
        t2 = time.time()
        print("time1 is ", t2 - t1)
        if sign_hash in self.matched:
            return self.matched[sign_hash]

        score = 0
        name = None

        for i, func in enumerate(self.functions):
            print("Searching %s, Process: %%%f" % (func, float(i)/len(self.functions)*100))
            # t3 = time.time()
            func_sign = self.get_sign(self.functions[func])
            # t4 = time.time()
            # print("get_sign time is ", t4 - t3)
            # t5 = time.time()
            s = Signature.similarity(func_sign, sign)
            # t6 = time.time()
            # print("similarity time is ", t6 - t5)
            if s > score:
                print('name', func, 'score is', s)
                score = s
                name = func

        self.matched[sign_hash] = name
        return name
