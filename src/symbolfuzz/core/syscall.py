#!/bin/python

"""
Module Name: Syscall Helper
Create by  : Bluecake
"""

from triton import ARCH
from basic import Basic
from symbolfuzz.utils.exception import *
from symbolfuzz.utils.utils import LogUtil


class Syscall(Basic):
    """Program syscall interface

    This module doesn't actually implement any real syscall
    but works as a filter. Real work is done by callback handlers.
    If no callback handler is set(through add_callback() function), 
    nothing will be done after the syscall instruction is executed.

    Attributes:    
        systable: a dict map of syscall number and related handler.
    """

    def __init__(self, arch):
        """Class contructor

        Args:
            arch: Program architecture. Right now, only x86 is supported.
        """
        super(Syscall, self).__init__()
        self.logger = LogUtil.get_logger()

        if arch == ARCH.X86:
            from symbolfuzz.core import i386_syscall as SYS
        elif arch == ARCH.X86_64:
            from symbolfuzz.core import amd64_syscall as SYS
        else:
            raise UnsupportedArchException(arch)

        self.systable = {}

        hook_syscall = ['exit', 'exit_group', 'read', 'write', ]
        for aSyscall in hook_syscall:
            constant = getattr(SYS, 'SYS_' + aSyscall)
            handler = getattr(self, 'syscall_' + aSyscall)
            self.systable[int(constant)] = {"handler": handler, "name": str(constant)}

        for SYSCALL, value in SYS.__dict__.items():
            if SYSCALL.startswith('SYS_') and not self.systable.has_key(int(value)):
                self.systable[int(value)] = {"handler": None, "name": str(value)}

    def syscall_exit(self, exit_value, *args):
        self.logger.debug('[SYS_exit] exit(%d)' % exit_value)
        if 'exit' in self.callbacks:
            return self.callbacks['exit'](exit_value)
        else:
            return 0

    def syscall_exit_group(self, exit_value, *args):
        self.logger.debug('[SYS_exit] exit_group(%d)' % exit_value)
        if 'exit_group' in self.callbacks:
            return self.callbacks['exit'](exit_value)
        else:
            return 0

    def syscall_read(self, fd, addr, length, *args): 

        self.logger.debug('[SYS_read] fd: %d, addr: 0x%x, length: %x' % (fd, addr, length))
        if 'read' in self.callbacks:
            return self.callbacks['read'](fd, addr, length)
        else:
            return 0

    def syscall_write(self, fd, addr, length, *args):

        self.logger.debug('[SYS_write] fd: %d, addr: 0x%x, length: %x' % (fd, addr, length))
        if 'write' in self.callbacks:
            return self.callbacks['write'](fd, addr, length)
        else:
            return 0

    def syscall_fstat64(self, fd, stat_buf, *args):
        self.logger.debug('[SYS_fstat64] fd: %d, stat_buf: 0x%x' % (fd, stat_buf))
        if 'fstat64' in self.callbacks:
            return self.callbacks['fstat64'](fd, stat_buf)
        else:
            return 0
        
    def syscall(self, sysnum, *args):

        if self.systable.has_key(sysnum):
            if self.systable[sysnum]["handler"] is not None:
                self.logger.debug('Emulate syscall ' + self.systable[sysnum]["name"])
                return self.systable[sysnum]["handler"](*args) 
            else:
                self.logger.debug('No support for syscall ' + self.systable[sysnum]["name"])
                if 'unsupported' in self.callbacks:
                    return self.callbacks['unsupported'](*args)
                else:
                    return 0
        else:
            self.logger.debug('Unknown syscall ' + str(sysnum))
            if 'unknown' in self.callbacks:
                return self.callbacks['unknown'](*args)
            else:
                return 0
