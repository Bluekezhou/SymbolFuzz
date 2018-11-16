#!/usr/bin/env python
# coding=utf-8

"""
Module Name: Debugger.py
Create by  : Bluecake
Description: A debug tool for program emulator
"""

from symbolfuzz.core.emulator import Emulator
from symbolfuzz.utils.static import EmuConstant
from symbolfuzz.utils.exception import UnsupportedArchException
from symbolfuzz.utils.utils import str2int
from triton import ARCH, OPCODE
from pwn import disasm, log


class Command(object):
    """Debug command class

    Attributes:
        min_arg:    count of minimum command arguments
        max_arg:    count of maximum command arguments
        debugger:   Debugger instance
        cmd_name:   command full name
    """

    def __init__(self, debugger, cmd_name, min_args=-1, max_args=-1):
        """Constructor function

        Args:
            debugger: Debugger instance
            cmd_name: Command full name
            min_args: Minimum arguments number, if equals -1, no limit
            max_args: Maximum arguments number, if equals -1, no limit
        """
        self.min_arg = min_args
        self.max_arg = max_args
        self.debugger = debugger
        self.cmd_name = cmd_name
        self._description = "No Description"

    @property
    def description(self):
        return self._description

    @staticmethod
    def split_cmdline(cmdline):
        WHITE_WORD = 0
        WORD_START = 1
        QUOTATION_START = 2

        args = list()
        state = WHITE_WORD
        word_start = -1
        i = 0
        while i < len(cmdline):
            if state == WHITE_WORD:
                if cmdline[i] == "\"":
                    state = QUOTATION_START
                    word_start = i
                else:
                    state = WORD_START
                    word_start = i
                i += 1
            elif state == QUOTATION_START:
                if cmdline[i] == "\"":
                    new_arg = cmdline[word_start+1:i]
                    args.append(new_arg)
                    state = WHITE_WORD
                i += 1

            elif state == WORD_START:
                if cmdline[i] == " ":
                    new_arg = cmdline[word_start:i]
                    args.append(new_arg)
                    state = WHITE_WORD
                i += 1

        if state == QUOTATION_START:
            log.error("Wrong quotation in cmdline")
            return None

        elif state == WORD_START:
            args.append(cmdline[word_start:])

        return args

    def execute(self, *args):
        """ subclass need to overwrite this method """
        pass

    def command_help(self):
        print("not enough argument")

    def run(self, cmdline):
        args = ()
        if self.max_arg > 0 or self.max_arg == -1:
            args = Command.split_cmdline(cmdline)
            if args is None:
                return False

        # remove command start string
        args = args[1:]
        if self.min_arg > 0 and len(args) < self.min_arg \
                or len(args) > self.max_arg:
            self.command_help()
            return True

        self.execute(*args)

    def get_name(self):
        return self.cmd_name

    def has_alias(self):
        return hasattr(self, "alias")

    def get_alias(self):
        return self.alias


class Help(Command):
    """command help
    """
    def __init__(self, debugger):
        super(Help, self).__init__(debugger, "help", max_args=1)
        self._description = "help command"

    def command_help(self):
        msg = "Usage:\n"
        msg += "    help\n"
        msg += "    help command"
        print(msg)

    def execute(self, cmd=None):
        if cmd is not None:
            if cmd in self.debugger.support_command:
                cmd_info = self.debugger.support_command[cmd]
                cmd_handler = cmd_info['available'][0]
                cmd_handler.command_help()
            else:
                print("unknown command " + cmd)
        else:
            for cmd in self.debugger.support_command['cmd_list']:
                cmd_info = self.debugger.support_command[cmd]
                cmd_handler = cmd_info['available'][0]
                print("%s%s" % (cmd.ljust(15, " "), cmd_handler.description))


class Breakpoint(Command):
    """command break

    Function: set breakpoint
    """
    def __init__(self, debugger):
        super(Breakpoint, self).__init__(debugger, "break", min_args=1, max_args=1)
        self._description = "set breakpoint"

    def command_help(self):
        msg = "Usage:\n"
        msg += "    break address"
        print(msg)

    def execute(self, address):
        addr = str2int(address)
        self.debugger.breakpoints[addr] = True


class NextInstruction(Command):
    """command nexti

    Function: run a single instruction, works like gdb command "nexti"
    """
    def __init__(self, debugger):
        super(NextInstruction, self).__init__(debugger, "nexti", max_args=1)
        self.alias = "ni"
        self._description = "run a single instruction, works like gdb command \"nexti\""

    def command_help(self):
        msg = "Usage:\n" \
              "    next\n" \
              "    next n[times]\n" \
              "Alias:\n" \
              "    ni"
        print(msg)

    def execute(self, steps=1):
        for i in range(steps):
            pc = self.debugger.process()
            if self.debugger.last_inst_type == OPCODE.CALL:
                stack_top_reg = EmuConstant.RegisterTable[self.debugger.arch]['stack_top']
                stack_top = self.debugger.getreg(stack_top_reg)
                ret_addr = self.debugger.get_machine_word(stack_top)
                self.debugger.breakpoints[ret_addr] = True
                self.debugger.run()
                del self.debugger.breakpoints[ret_addr]

        return pc


class StepInstruction(Command):
    """command stepi

    Function: run a single instruction, works like gdb command "stepi"
    """
    def __init__(self, debugger):
        super(StepInstruction, self).__init__(debugger, "stepi", max_args=1)
        self.alias = "si"
        self._description = "run a single instruction, works like gdb command \"stepi\""

    def command_help(self):
        msg = "Usage:\n" \
              "    stepi\n" \
              "    steps n[times]\n" \
              "Alias:\n" \
              "    si"
        print(msg)

    def execute(self, steps=-1):
        if steps > 0:
            result = None
            for i in range(steps):
                result = self.debugger.process()
        else:
            result = self.debugger.process()

        return result


class ListInfo(Command):
    """command list

    Function: list target information
    """
    def __init__(self, debugger):
        super(ListInfo, self).__init__(debugger, "list", min_args=1, max_args=1)
        self._description = "list breakpoints information"

    def command_help(self):
        msg = "Usage:\n" \
              "    list break"
        print(msg)

    def list_breakpoint(self):
        for addr, enabled in self.debugger.breakpoints.items():
            if enabled:
                print 'breakpoint at %s is enabled' % hex(addr).strip('L')
            else:
                print 'breakpoint at %s is disabled' % hex(addr).strip('L')

    def execute(self, target):
        if target == "break":
            self.list_breakpoint()
            return True


class ContinueRun(Command):
    """command continue

    Function: resume program running
    """
    def __init__(self, debugger):
        super(ContinueRun, self).__init__(debugger, "continue", max_args=0)
        self.alias = "c"
        self._description = "resume program running"

    def command_help(self):
        msg = "Usage: \n" \
              "    continue\n" \
              "Alias:\n" \
              "    c"
        print(msg)

    def execute(self):
        self.debugger.stopped = False
        return True


class Show(Command):
    """command show

    Function: show information for register, stack, code
    """
    def __init__(self, debugger):
        super(Show, self).__init__(debugger, "show", min_args=1, max_args=1)
        self._description = "show information for register, stack, code"

    def command_help(self):
        msg = "Usage:\n" \
              "    show register\n" \
              "    show stack\n" \
              "    show code\n" \
              "    show all"
        print(msg)

    def execute(self, target, *args):
        if target == "register":
            self.debugger.show_register()
        elif target == "stack":
            self.debugger.show_stack()
        elif target == "code":
            self.debugger.show_code(args[0])
        elif target == "all":
            self.debugger.show_all(self.debugger.getpc())
        return True


class Register(Command):
    """command register

    Function: show information for register, equal to command "show register"
    """
    def __init__(self, debugger):
        super(Register, self).__init__(debugger, "register", min_args=0, max_args=1)
        self.alias = "reg"
        self._description = "show register information"

    def command_help(self):
        msg = "Usage:\n"
        msg += "    register [name]"
        print(msg)

    def execute(self):
        self.debugger.show_register()
        return True


class Disasm(Command):
    """command disasm

    Function: show information for code
    """
    def __init__(self, debugger):
        super(Disasm, self).__init__(debugger, "disasm", min_args=0, max_args=1)
        self._description = "show disassembly code"

    def command_help(self):
        msg = 'Usage:\n'
        msg += "    disasm [address]"
        print(msg)

    def execute(self):
        self.debugger.show_code()
        return True


class Stack(Command):
    """command disasm

    Function: show information for stack
    """
    def __init__(self, debugger):
        super(Stack, self).__init__(debugger, "stack", max_args=1)
        self._description = "show stack information"

    def command_help(self):
        msg = "Usage:\n"
        msg += "    stack"
        print(msg)

    def execute(self):
        self.debugger.show_stack()
        return True


class Xinfo(Command):
    """command xinfo

    Function: examine data of target address
    """
    def __init__(self, debugger):
        super(Xinfo, self).__init__(debugger, "xinfo", min_args=1, max_args=3)
        self.alias = "x"
        self._description = "examine data of target address"

    def command_help(self):
        msg = "Usage:\n"
        msg += "    xinfo [address] [format]"
        print(msg)

    """ self-defined function for command xinfo """
    def xinfo(self, address, show_format, length=1):
        if show_format == 'hex':
            if self.debugger.arch == ARCH.X86:
                for i in range(length):
                    addr = address + i * 4
                    print('0x%x:  0x%x' % (addr, self.debugger.get_uint32(addr)))
            elif self.debugger.arch == ARCH.X86_64:
                for i in range(length):
                    addr = address + i * 8
                    print('0x%x:  0x%x' % (addr, self.debugger.get_uint64(addr)))
            else:
                raise UnsupportedArchException(self.debugger.arch)

        elif show_format == 'string':
            content = self.debugger.get_memory_string(address)
            print('0x%x: "%s"' % (address, content))

    def execute(self, address, option='-hex', length=1):
        address = str2int(address)
        if option in ['-s', '-string']:
            self.xinfo(address, 'string')
        elif option in ['-h', '-hex']:
            self.xinfo(address, "hex", length)
        else:
            print("Unknown option")
            return False

        return True


class Debugger(Emulator):
    """Debug class for Emulator

    Attributes:
        show_inst:       boolean, whether to print executed instruction
        show_output:     boolean, whether to print program console output

        breakpoints:     a dict, store breakpoints information
        nextpc:          a integer, stores address of next instruction
        stopped:         boolean, whether to  stopped at next instruction
        last_cmd:        a string, last executed command
    """

    def __init__(self, *args, **kwargs):

        super(Debugger, self).__init__(*args, **kwargs)
        
        self.show_inst = False
        self.show_output = True
        
        self.breakpoints = {}
        self.nextpc = None
        self.stopped = True
        self.last_cmd = ''

        self.support_command = {}
        self.register_command(Breakpoint(self))
        self.register_command(NextInstruction(self))
        self.register_command(StepInstruction(self))
        self.register_command(ListInfo(self))
        self.register_command(ContinueRun(self))
        self.register_command(Show(self))
        self.register_command(Xinfo(self))
        self.register_command(Register(self))
        self.register_command(Stack(self))
        self.register_command(Disasm(self))
        self.register_command(Help(self))

    def _check_breakpoint(self, pc):
        """ check breakpoint status
        """
        if pc not in self.breakpoints:
            return False
        elif self.breakpoints[pc] is True:
            return True
        return False

    # register a command
    def register_command(self, command):
        name = command.get_name()
        if 'cmd_list' in self.support_command:
            self.support_command['cmd_list'].append(name)
        else:
            self.support_command['cmd_list'] = [name]

        for i in range(len(name)):
            cmd_abbr = name[:i+1]
            if cmd_abbr not in self.support_command:
                self.support_command[cmd_abbr] = {}

            cmd_info = self.support_command[cmd_abbr]
            if 'available' not in cmd_info:
                cmd_info['available'] = []

            cmd_info['available'].append(command)

        if command.has_alias():
            alias = command.get_alias()
            if alias not in self.support_command:
                self.support_command[alias] = {}

            cmd_info = self.support_command[alias]
            if 'available' not in cmd_info:
                cmd_info['available'] = []

            if command not in cmd_info['available']:
                cmd_info['available'].append(command)

    """ self-defined function for command show register """
    def show_register(self):
        print '-'* 25 + ' register ' + '-'*25
        reg_list = EmuConstant.RegisterList[self.arch]
        for reg in reg_list:
            value = self.getreg(reg)
            print '%s: %s' % (reg.rjust(3, ' '), hex(value).strip('L'))

    """ self-defined function for command show stack """
    def show_stack(self, size=10):
        print('-'* 25 + '   stack  ' + '-'*25)
        if self.arch == ARCH.X86:
            esp = self.getreg('esp')
            for i in range(size):
                value = self.get_uint32(esp+i*4)
                print '0x%x:  ' % (esp+i*4) + hex(value).strip('L')

        elif self.arch == ARCH.X86_64:
            rsp = self.getreg('rsp')
            for i in range(size):
                value = self.get_uint64(rsp+i*8)
                print '0x%x:  ' % (rsp+i*8) + hex(value).strip('L')

        else:
            raise UnsupportedArchException(self.arch)

    """ self-defined function for command show code """
    def show_code(self, pc, lines=5):
        print '-'* 25 + '   code   ' + '-'*25
        opcode = self.get_memory(pc, 1024)
        lines = disasm(opcode, arch=EmuConstant.SUPPORT_ARCH[self.arch]).splitlines()[:lines]
        for line in lines:
            if line.find(":") != -1:
                pos = line.find(":")
                addr, disasm_code = line[:pos], line[pos:]
                reloc_addr = pc + int(addr, 16)
                print(hex(reloc_addr) + disasm_code)

    def show_all(self, pc):
        self.show_register()
        self.show_code(pc)
        self.show_stack()

    @staticmethod
    def info_unknown_cmd():
        print("Unknown command, check it")

    def info_uncertain_cmd(self, cmd):
        msg = "Are you typing:\n"
        for command in self.support_command[cmd]:
            msg += command + " "
        print(msg)

    """
    Parse user_input command and stop at breakpoints
    Probably like a debugger
    """
    def parse_command(self):
        """
        Arguments
            pc: current pc address
            handler: process an instruction, argument is pc address.
        """
        pc = self.getpc()

        if self.stopped or self._check_breakpoint(pc):
            if self.last_cmd in ['ni', 'nexti', 'c', 'continue', 'stepi', 'si']:
                self.show_all(pc)

            if self._check_breakpoint(pc):
                print 'Breakpoint at ' + hex(pc).strip('L')
                self.stopped = True

            cmd = raw_input("> ").strip('\n')
            if not cmd:
                if self.last_cmd:
                    cmd = self.last_cmd
                else:
                    while not cmd:
                        cmd = raw_input("> ").strip('\n')

            self.last_cmd = cmd.split(' ')[0]
            if self.last_cmd in self.support_command:
                if len(self.support_command[self.last_cmd]) > 1:
                    self.info_uncertain_cmd(self.last_cmd)
                else:
                    cmd_info = self.support_command[self.last_cmd]
                    cmd_handler = cmd_info['available'][0]
                    return cmd_handler.run(cmd)

            else:
                Debugger.info_unknown_cmd()
                return pc

        else:
            return self.process()

    def run(self):
        """ Run program until encounters breakpoints or stops

        Arguments
            pc: current pc address
        """
        pc = self.getpc()
        while self.running and not self._check_breakpoint(pc):
            pc = self.process()
        return pc

    def debug(self):
        """ Ok, everything is prepared, start debugging """
        log.info("Start debugging")
        while self.is_running():
            self.parse_command()
        log.info("Debugging done")