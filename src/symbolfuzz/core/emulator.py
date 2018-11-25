#!/usr/bin/env python
# coding=utf-8

"""
Module Name: Emulator.py
Create by  : Bluecake
Description: Kernel class for x86 and x86_64 program emulate
"""

from triton import *
from pwn import asm, context, ELF, process
# from symbolfuzz.utils.static import EmuConstant
from symbolfuzz.utils.utils import LogUtil, get_arch, getELF, md5, memorize
from symbolfuzz.libhook.libhook import *
from symbolfuzz.utils.recognizer import Recognizer
from symbolfuzz.utils.exception import *
from syscall import Syscall
from basic import Basic
import time
import subprocess
import json
import tempfile
import lief
import os


class Emulator(Basic):
    """Basic program interpreter

    This is the basic program interpreter. It provides interfaces
    to emulate program running

    Attributes:
        binary: A string, stores the path of binary. It can be 
                absolute path or relative path.

        dumpfile: A string, stores the path of memory snapshot 
                file. It can be absolute path or relative path.
        
        show_inst: A boolean, switch to show every executed instruction 

        show_output: A boolean, switch to show program output
        
        root_dir: A string, source file root directory.

        arch: A number defined in ARCH

        read_count: Total bytes which is read from any file descriptor.

        last_pc: Pc address of last executed instruction.

        inst_count: Total number of executed instructions.
        
        syshook: A Syscall instance, syscall call filter. 

        callbacks: A dict, callback functions for syscalls,

        assembly_cache: A dict, stores the the map of assembly code
                and binary code.  Format is like 
                {
                    arch:
                        {   
                            'mov eax, 0x1': '\xde\xad\xbe\xef'
                            'mov ebx, 0x1': '\xde\xaa\xbe\xef'
                        }
                }

        assembly_cache_file: A string, stores the path of assembly_cache dict.

        running: A boolean value, true means the program is active.

        syscall_fail: A boolean value, false means last syscall failed.
    """

    def __init__(self, mode, name="default", arch=EmuConstant.UNKNOWN_ARCH, code="", assembly=None,
                 code_start=-1, register=None, binary=None, dumpfile=None, seed="", hook_library=None):
        """ Emulator Constructor Method
            Here we support two mode.
            MODE_ELF:  load code from .text segment of ELF binary file.
            MODE_CODE: load binary code from argument(a string)

        Args:
            mode:       initialize mode
            code:       when mode is MODE_CODE, it's a string which stores
                        assembly code or binary code
            assembly:   a boolean value, indicating code mode
                        if true, code should be assembly code like "mov eax, 1"
                        if false, binary code should be passed
            code_start:   an integer, stores address of code
            register:   a dict, stores the value of needed register
            binary:     when mode is MODE_ELF, it's path of executable binary
            dumpfile:   path of memory snapshot file
        """
        self.mode = mode
        self.name = name
        self.seed = seed
        self.triton = TritonContext()
        self.base = 0
        self.instruction = Instruction()
        self.last_inst_type = OPCODE.JMP
        self.memory_cache = list()
        self.memAccessCheck = False
        self.stdin = ""
        self.logger = LogUtil.get_logger()
        self.before_process_callbacks = []
        self.after_process_callbacks = []

        self.add_before_process_callback(self.check_dead_loop)

        if mode == EmuConstant.MODE_CODE:
            self.arch = arch
            if self.arch == EmuConstant.UNKNOWN_ARCH:
                raise Exception("Unknown exception")

            if assembly:
                self.code = self.asm(code)
            else:
                self.code = code

            self.code_start = code_start
            self.register = register
            self.init_with_code()

        elif mode == EmuConstant.MODE_ELF:
            self.binary = binary
            self.dumpfile = dumpfile
            self.show_inst = True
            self.show_output = True
            self.memoryAccessError = False

            self.root_dir = os.path.dirname(__file__)

            self.elf = getELF(binary)
            self.arch = get_arch(self.elf)
            self.assembly_cache_file = None
            self.assembly_cache = None
            self.init_assembly_cache()
            self.init_with_binary()
            if hook_library:
                self.library_hook = {}
                self.recognizer = Recognizer(self.binary)
                self.load_hook_library(hook_library)
        else:
            raise UnknownEmulatorMode()

        self.read_count = 0
        self.last_pc = 0
        self.inst_count = 0
        self.inst_loop = 0

        self.running = True
        self.syscall_fail = False
        self.callbacks = {}

        self.syshook = Syscall(self.arch)
        self.syshook.add_callback("read", self.callback_read)
        self.syshook.add_callback("write", self.callback_write)
        self.syshook.add_callback("exit", self.callback_exit)
        self.syshook.add_callback("exit_group", self.callback_exit)
        self.syshook.add_callback("unsupported", self.callback_unsupported)

    def copy(self):
        pass

    def is_supported(self, arch):
        if arch not in self.supported_arch:
            return False
        return True

    def is_running(self):
        return self.running

    def snapshot(self):
        """Automatically take memory snapshot on the entry of main()
            or other point
        """
        if os.path.exists(self.dumpfile):
            return 

        # Make the binary file executable
        os.chmod(self.binary, 0o777)
        _, debug_file = tempfile.mkstemp()
        peda_path = "/usr/share/peda/peda.py"

        with open(debug_file, 'w') as f:
            content = "source %s\n" \
                    "set $eax=3\n" \
                    "set $eip=$eip-2\n" \
                    "fulldump %s\n" \
                    "quit\n" % (peda_path, self.dumpfile)

            f.write(content)

        try:
            p = process(self.binary)
            self.logger.info('try to dump memory with seed ' + repr(self.seed))
            if self.seed:
                p.send(self.seed)

            time.sleep(0.5)
            cmd = "gdb -nx -command=%s --pid=%d" % (debug_file, p.pid)
            self.logger.info(cmd)

            # Run gdb and dump memory with patched peda
            subprocess.check_output(cmd, shell=True, stderr=None)
            p.close()

        except Exception as e:
            print e

    def setreg(self, reg, value):
        """Set targeted register

        Args:
            reg: Register name
            value: If arch is x86, it should be a uint32 value.
                    If arch is x64, it should be a uint64 value.
        """
        Triton = self.triton
        return eval('Triton.setConcreteRegisterValue(Triton.registers.%s, %d)' % (reg, value))

    def getreg(self, reg):
        """Retrieve target register
        
        Args:
            reg: Register name

        Return:
            If arch is x86, it should return a uint32 value.
            If arch is x64, it should return a uint64 value.

        """
        return eval('self.triton.getConcreteRegisterValue(self.triton.registers.%s)' % (reg,))

    def setpc(self, address):
        """ Set new pc address

        Args:
            address: new pc address
        """

        if self.arch in EmuConstant.SUPPORT_ARCH:
            return self.setreg(EmuConstant.RegisterTable[self.arch]["pc"], address)
        else:
            raise UnsupportedArchException(self.arch)

    def getpc(self):
        """Retrieve current PC address

        Return:
            current pc address
        """
        if self.arch in EmuConstant.SUPPORT_ARCH:
            return self.getreg(EmuConstant.RegisterTable[self.arch]['pc'])

        else:
            raise UnsupportedArchException(self.arch)

    def get_memory_string(self, address):
        """Retrieve string terminated with null byte
        
        Args:
            address: memory address

        Return:
            A string, stored in targeted memory
        """
        s = ""
        index = 0
        while True:
            c = chr(self.triton.getConcreteMemoryValue(address + index))
            s += c
            if c == '\x00':
                break
            index += 1
        return s

    def get_memory(self, address, size):
        """ Retrieve a block of data 
        
        Args:
            address: memory address you want to read from
            size: size of bytes you want to read

        Return:
            A string, memory content of target address
        """
        return self.triton.getConcreteMemoryAreaValue(address, size)
    
    def set_memory(self, address, content):
        """Write data into memory

        Args:
            address: memory address to write
            content: content to be written into memory
        """

        # Write content into virtual memory
        self.triton.setConcreteMemoryAreaValue(address, content)

    def get_uint32(self, addr):
        """Retrieve uint32 value of target address

        Args:
            addr: memory address

        Return:
            An uint32 value
        """
        mem = MemoryAccess(addr, 4)
        return self.triton.getConcreteMemoryValue(mem)

    def get_uint64(self, addr):
        """Retrieve uint64 value of target address
        
        Args:
            addr: memory address

        Return:
            An uint64 value
        """
        mem = MemoryAccess(addr, 8)
        return self.triton.getConcreteMemoryValue(mem)

    def get_machine_word(self, addr):
        if self.arch == ARCH.X86:
            return self.get_uint32(addr)
        elif self.arch == ARCH.X86_64:
            return self.get_uint64(addr)

    @memorize(isclazz=True)
    def assemble(self, code):
        """Return binary code

        Args:
            code: A string, assembly code like 'mov eax, ebx'

        Return:
            A String, binary code compiled with pwn.asm()
        """
        if self.arch in EmuConstant.SUPPORT_ARCH:
            return asm(code, arch=EmuConstant.SUPPORT_ARCH[self.arch])
        else:
            raise UnsupportedArchException(EmuConstant.SUPPORT_ARCH[self.arch])

    def instrument(self, code):
        asm_code = self.assemble(code)
        instruction = Instruction()
        instruction.setOpcode(asm_code)
        instruction.setAddress(0)
        self.triton.processing(instruction)

    def load_dump(self):
        """Recover memory, registers with dumpfile"""

        # Open the dump
        fd = open(self.dumpfile)
        self.logger.debug('load memory dumpfile ' + self.dumpfile)
        data = eval(fd.read())
        fd.close()

        # Extract registers and memory
        regs = data[0]
        mems = data[1]
        gs_8 = data[2]

        # Load memory into memory_cache
        self.logger.debug('Define memory areas')
        for mem in mems:
            start = mem['start']
            end = mem['end']
            name = mem['name']
            self.logger.debug('Memory caching %x-%x' %(start, end))
            if mem['memory']:
                if os.path.abspath(self.binary) in mem['name'] \
                        and 'x' in mem['permissions'] and self.elf.pie:
                    self.base = start

                self.memory_cache.append({
                    'start':  start,
                    'size':   end - start,
                    'memory': mem['memory'],
                    'name': name
                })

        if self.arch == ARCH.X86:
            context.arch = 'i386'

            # Make sure to restore gs register first
            self.setreg('gs', regs['gs'])
            for i in range(7):
                self.logger.debug('Restore gs[0x%x]' % (i*4))
                v = self.get_uint32(gs_8 + i*4)
                write_gs = ['mov eax, %s' % hex(v), 'mov gs:[%d], eax' % (i*4)]
                for inst in write_gs:
                    self.instrument(inst)

        elif self.arch == ARCH.X86_64:
            context.arch = 'amd64'

            # Make sure to restore gs register first
            self.setreg('gs', regs['gs'])
            for i in range(7):
                self.logger.debug('Restore gs[0x%x]' % (i*8))
                v = self.get_uint64(gs_8 + i*8)
                write_gs = ['mov rax, %s' % hex(v), 'mov gs:[%d], rax' % (i*8)]
                for inst in write_gs:
                    self.instrument(inst)

        # Load registers into the triton
        self.logger.debug('Define registers')
        for reg, value in regs.items():
            self.logger.debug('Load register ' + reg)
            self.setreg(reg, value)

    def load_hook_library(self, library, base=0):
        """load library to memory cache

        Args:
            library: path of target library
            base: forced base address of library
        """
        self.logger.debug("loading hooking library")
        binary = lief.parse(library)
        for s in binary.sections:
            start = base + s.virtual_address
            end = base + s.virtual_address + s.size
            name = s.name
            self.logger.debug('Memory caching %x-%x' % (start, end))
            self.memory_cache.append({
                'start':  start,
                'size':   end - start,
                'memory': "".join([chr(c) for c in s.content]),
                'name': name
            })

        library_elf = getELF(library)
        library_elf.address = base
        self.add_library_call_hook("atoi", AtoiHook(self, library_elf))
        self.add_library_call_hook("puts", PutsHook(self, library_elf))
        self.add_library_call_hook("__stack_chk_fail", StackCheckFailHook(self, library_elf))
        self.add_library_call_hook("strcmp", StrcmpHook(self, library_elf))

    def memory_caching(self, triton, mem):
        """Callback: Speed up the procedure of load_dump"""

        addr = mem.getAddress()
        size = mem.getSize()
        # print "memory_cache is called", hex(addr), hex(size)
        if not triton.isMemoryMapped(addr, size):
            for m in self.memory_cache:
                if addr >= m['start'] and addr + size < m['start'] + m['size']:
                    # print 'memory check successful'
                    offset = addr - m['start']
                    value = m['memory'][offset: offset + size]
                    triton.setConcreteMemoryAreaValue(addr, value)
                    return

        # if self.memAccessCheck and not self.is_address(addr):
        #     self.logger.warn("Not stable, be careful to use memAccessCheck")
        #     pc = self.getpc()
        #     self.memoryAccessError = (pc, addr)
        #     self.running = False
        return

    def check_access(self, switch):
        """Switch to checking memory access address

        Args:
            switch: boolean, if True, do memory access check
        """
        self.memAccessCheck = switch

    @memorize(isclazz=True)
    def is_address(self, pc):
        """Check whether a specific address is a valid address
        
        Args:
            pc: instruction address

        Return:
            boolean, true is valid, false is invalid.
        """

        for m in self.memory_cache:
            if m['start'] < pc < m['start'] + m['size']:
                return True
        return False 

    def is_code(self, pc):
        """Check whether specific address has execute privilege

        Args:
            pc: instruction address

        Returns:
            boolean, true is executable, false is non-executable.

        """
        for m in self.memory_cache:
            if m['start'] < pc < m['start'] + m['size'] and m['executable']:
                return True
        return False

    def callback_read(self, fd, addr, length):
        """Callback for syscall read"""
        
        self.logger.debug('[callback_read] fd: %d, addr: %s, length: %d' % (fd, hex(addr), length))
        if 'read_before' in self.callbacks:
            self.callbacks['read_before'](self, fd, addr, length)
            if not self.running:
                return 0
        
        if length > 0x100000:
            length = 0x100000

        if not self.is_address(addr):
            self.running = False
            return 0

        if fd == 0:

            # hijack standard input
            if hasattr(self, 'stdin'):

                # input buffer defualt to be filled with 'A'
                if len(self.stdin) < length:
                    content = self.stdin.ljust(length, 'A')
                    self.stdin = ''

                # # read() is gonna finish reading when encounters '\n'
                # elif 0 <= self.stdin.find('\n') < length:
                #     content = self.stdin[:self.stdin.find('\n')+1]
                #     self.stdin = self.stdin[self.stdin.find('\n')+1:]

                else:
                    content = self.stdin[:length]
                    self.stdin = self.stdin[length:]

            # read from standard input
            else:
                content = raw_input()
                if len(content) < length and not content.endswith('\n'):
                    content += '\n'
                else:
                    content = content[:length]

        # read data from existed file descriptor
        else:
            content = os.read(fd,  length)
        
        self.set_memory(addr, content)
        self.setreg(EmuConstant.RegisterTable[self.arch]['ret_value'], len(content))
        
        if 'symbolize_check' in self.callbacks:
            check = self.callbacks['symbolize_check']
            for offset in range(len(content)):
                if check(self, self.read_count + offset):
                    self.logger.debug("try to symbolize 0x%x, offset is %d" % (addr + offset, offset))
                    mem = MemoryAccess(addr + offset, 1)
                    self.triton.convertMemoryToSymbolicVariable(mem)

        if 'taint_check' in self.callbacks:
            check = self.callbacks['taint_check']
            for offset in range(len(content)):
                if check(self, self.read_count + offset):
                    self.logger.debug("try to taint 0x%x, offset is %d" % (addr + offset, offset))
                    mem = MemoryAccess(addr + offset, 1)
                    self.triton.setTaintMemory(mem, True)

        if 'read_after' in self.callbacks:
            self.callbacks['read_after'](self, content)
        
        self.read_count += len(content)
        return len(content)

    def callback_write(self, fd, addr, length):
        """Callback for syscall write"""

        if 'write_before' in self.callbacks:
            self.callbacks['write_before'](self, fd, addr, length)

        if not self.is_address(addr):
            self.logger.warn('[callback_write] Invalid target memory address ' + hex(addr))
        
        # Check fd, may cause other problem, but just do it.
        # Just because file-related syscalls are not supported yet.
        if fd > 3:
            self.running = False
            return 0

        if length > 0x1000000:
            self.running = False
            return 0

        content = self.get_memory(addr, length)

        if self.show_output:
            os.write(fd, content)

        self.setreg(EmuConstant.RegisterTable[self.arch]['ret_value'], len(content))

        if 'write_after' in self.callbacks:
            self.callbacks['write_after'](self, fd, addr, length)
        return len(content)

    def callback_exit(self, exit_value):
        """Callback for syscall exit and exit_group"""

        if 'syscall_exit' in self.callbacks:
            self.callbacks['syscall_exit'](self, exit_value)

        self.running = False
        self.setpc(0)
        return 0

    def callback_unsupported(self, *args):
        if 'NotImplementSys' in self.callbacks:
            self.callbacks['NotImplementSys'](self, *args)

    def init_with_code(self):
        self.triton.setArchitecture(self.arch)

        # Define symbolic optimizations
        self.triton.enableMode(MODE.ALIGNED_MEMORY, True)
        self.triton.enableMode(MODE.ONLY_ON_SYMBOLIZED, True)

        # Define internal callbacks.
        self.triton.addCallback(self.memory_caching, CALLBACK.GET_CONCRETE_MEMORY_VALUE)

        self.memory_cache.append({
                    'start':  self.code_start,
                    'size':   len(self.code),
                    'memory': self.code,
                    'name': "CODE",
                    'executable': True
                })

        self.last_inst_type = OPCODE.JMP
        self.setpc(self.code_start)

    def init_assembly_cache(self):
        self.assembly_cache_file = "/tmp/AssemblyCache.txt"
        if os.path.exists(self.assembly_cache_file):
            try:
                f = open(self.assembly_cache_file)
                self.assembly_cache = json.loads(f.read())

            except Exception as e:
                self.logger.debug(e)
                self.assembly_cache = {self.arch: {}}
        else:
            self.assembly_cache = {self.arch: {}}

    def init_with_binary(self):
        """Prepare everything before starting emulator"""

        self.triton.setArchitecture(self.arch)

        # Define symbolic optimizations
        self.triton.enableMode(MODE.ALIGNED_MEMORY, True)
        self.triton.enableMode(MODE.ONLY_ON_SYMBOLIZED, True)

        # Define internal callbacks.
        self.triton.addCallback(self.memory_caching, CALLBACK.GET_CONCRETE_MEMORY_VALUE)
        
        if not self.dumpfile:
            file_hash = md5(self.binary)            
            # Get dumpfile from entry of main()
            self.dumpfile = '/tmp/%s_%s_dump.bin' % (os.path.basename(self.binary), file_hash)

        if not os.path.exists(self.dumpfile):
            self.snapshot()

        self.load_dump()

    def get_syscall_regs(self):
        """Retrieve args for syscall instruction

         Return:
            If arch is x86, return eax, ebx, ecx, edx, esi, edi
            If arch is x86_64, return rax, rbx, rcx, rdx, esi, edi
        """
        if self.arch == ARCH.X86:
            reg_list = ["eax", "ebx", "ecx", "edx", "esi", "edi"]
        elif self.arch == ARCH.X86_64:
            reg_list = ["rax", "rbx", "rcx", "rdx", "rsi" "rdi"]

        result = []
        for reg in reg_list:
            result.append(self.getreg(reg))

        sysnum = result[0]
        args = result[1:]
        return sysnum, args

    def set_input(self, data):
        """Set input buffer
            
        Args:
            data: A string, input data that added to input buffer
        """

        if hasattr(self, 'stdin'):
            self.stdin += data
        else:
            self.stdin = data
            
    def symbolize_reg(self, reg):
        """ Symbolizing target register """

        self.logger.debug("try to symbolize " + reg)
        treg = eval("self.triton.registers." + reg)
        self.triton.convertRegisterToSymbolicVariable(treg)
    
    def is_register_symbolized(self, reg):
        """ Check whether target register is symbolized

        Args:
            reg: A string, register name

        Return:
            true, if target register is symbolized
        """
        _reg = eval("self.triton.registers." + reg)
        return self.triton.isRegisterSymbolized(_reg)

    def get_symbolized_memory(self):
        """ Get tainted memory

        Returns:
            tainted memory address list
        """
        return self.triton.getSymbolicMemory()

    def is_memory_symbolized(self, addr):
        """ Check whether target memory is symbolized

        Args:
            addr: Memory address

        Return:
            true, if target memory is symbolized
        """
        return self.triton.isMemorySymbolized(addr)

    def taint_memory(self, target):
        """ Taint target memory

        Args:
            target: memory address

        Return:
            taint result
        """
        return self.triton.taintMemory(target)

    def get_tainted_memory(self):
        """ Get tainted memory

        Returns:
            tainted memory address list
        """
        return self.triton.getTaintedMemory()

    def is_memory_tainted(self, target):
        """ Check whether target memory is tainted

        Args:
            target: memory address list

        Return:
            boolean list, whether any byte of target memory is tainted
        """

        result = []
        for aByte in target:
            result.append(self.triton.isMemoryTainted(aByte))

        return result

    def is_register_tainted(self, target):
        """ Check whether target register is tainted

        Args:
            target: register name

        Return:
            true, if target register is tainted
        """

        target = eval("self.triton.registers." + target)
        return self.triton.isRegisterTainted(target)

    def is_branch_tainted(self):
        """ Check whether current register eflags, which will
         influence jmp instruction, is tainted

        Returns:
            True, tainted
        """
        return self.is_register_tainted("eflags")

    def check_dead_loop(self, *args):
        if self.getpc() == self.last_pc:
            self.inst_loop += 1
            """When encounter unsupported instruction except for "REP MOV", 
            the program might get stuck in one instruction. """
            if self.inst_loop >= 1024:
                raise InfinityLoopException(self.last_pc)
        else:
            self.inst_loop = 0

    def add_before_process_callback(self, handler):
        self.before_process_callbacks.append(handler)

    def add_after_process_callback(self, handler):
        self.after_process_callbacks.append(handler)

    def add_library_call_hook(self, name, handler):
        self.library_hook[name] = handler

    def process(self):
        """Emulate executing an instruction

        Returns:
            next instruction address
        """

        if not self.running:
            if self.memoryAccessError:
                pc, addr = self.memoryAccessError
                self.memoryAccessError = False
                raise MemoryAccessException(pc, addr)
            return 0

        pc = self.getpc()
        if self.last_inst_type == OPCODE.CALL:
            offset = pc - self.base
            label = self.recognizer.get_label(offset)
            if label is not None and label in self.library_hook:
                self.logger.debug("function %s is called" % label)
                self.library_hook[label].process()
            pc = self.getpc()

        opcode = self.get_memory(pc, 16)
        self.instruction.setOpcode(bytes(opcode))
        self.instruction.setAddress(pc)
        
        self.triton.disassembly(self.instruction)
        for handler in self.before_process_callbacks:
            handler(self, self.instruction)

        self.triton.processing(self.instruction)

        if self.show_inst:
            print(self.instruction)

        if self.instruction.getType() in [OPCODE.SYSENTER, OPCODE.INT]:

            if self.last_inst_type not in [OPCODE.SYSENTER, OPCODE.INT] \
                    and self.instruction.getType() in [OPCODE.SYSENTER, OPCODE.INT]:

                sysnum, args = self.get_syscall_regs()
                
                if 'syscall_before' in self.callbacks:
                    self.callbacks['syscall_before'](self, sysnum, *args)

                ret = self.syshook.syscall(sysnum, *args)

                if 'syscall_after' in self.callbacks:
                    self.callbacks['syscall_after'](ret)

            self.setpc(pc + self.instruction.getSize())

        elif self.instruction.getType() == OPCODE.HLT:
            self.logger.debug("Program stopped [call hlt]")
            self.running = False
            self.setpc(0)

        # Deal with instruction exception
        # elif instruction.getType() == OPCODE.RET \
        #         or instruction.getType() == OPCODE.CALL\
        #         or instruction.getType() == OPCODE.JMP:

            # new_pc = self.getpc()
            # text_start = self.memory_cache[0]['start']
            # text_end = self.memory_cache[0]['start'] + self.memory_cache[0]['size']
            #
            # for m in self.memory_cache:
            #     if 'vdso' in m['name']:
            #         vdso_start = m['start']
            #         vdso_end = m['start'] + m['size']
            #         break
            #
            # if not self.is_address(new_pc):
            #     raise IllegalPcException(self.arch, new_pc)

            # if not ((text_start <= new_pc <= text_end) or (vdso_start <= new_pc <= vdso_end)):
            #     log.info('.text [%s-%s], vdso [%s-%s], new_pc is %s' %
            #              (hex(text_start), hex(text_end), hex(vdso_start), hex(vdso_end), hex(new_pc)))
            #
            #     raise IllegalInstException(self.arch, new_pc)

        self.last_inst_type = self.instruction.getType()
        self.last_pc = pc
        pc = self.getpc()
        if not self.is_address(pc):
            raise IllegalPcException(self.arch, pc)

        return pc

    def process_n_instruction(self, steps):
        result = None
        for i in range(steps):
            result = self.process()
        return result
