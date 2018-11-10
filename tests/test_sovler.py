#!/usr/bin/env python
# coding=utf-8

import nose
from emulator import *
import os

binary_dir = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../binary/')) 
binpath = os.path.join(binary_dir, 'read_execute')

def test_memorySolver():
    emu = Emulator(binpath)
    emu.initialize()
    emu.set_input('A')
    emu.show_inst = False
    emu.show_output = False

    while emu.getpc() != 0x08048967:
        emu.process()

    state = (emu.getpc(), emu.inst_count)

    esp = emu.getreg('esp')
    buf = emu.getuint32(esp)

    dst = range(buf, buf + 4)
    value = map(ord, "123a")

    solver = InputSolver(binpath)
    solver.set_input('A', emu.read_count)
    solver.set_breakpoint(state)

    answer = solver.solveMemory(dst, value)
    nose.tools.assert_equal(answer, {0: '\x9b', 1: '\x9f', 2: '\xfc', 3: 'p'})
    seed = solver.createInput(answer)
    nose.tools.assert_equal(seed, '\x9b\x9f\xfcpAAAA')
    open('input1', 'wb').write(seed)


def test_registerSolver():
    emu = Emulator(binpath)
    emu.show_inst = False
    emu.show_output = False
    emu.initialize()
    
    seed = open('input1').read()
    emu.set_input(seed)

    while emu.getpc() != 0x0804896C:
        emu.process()

    state = (emu.getpc(), emu.inst_count)

    solver = InputSolver(binpath)
    solver.set_input(seed, emu.read_count)
    solver.set_breakpoint(state)
    
    answer = solver.solveRegister('eax', 110)
    nose.tools.assert_equal(answer, {0: '\x9b', 1: '\x9c', 2: '\xff'})
    seed = solver.createInput(answer)
    nose.tools.assert_equal(seed, '\x9b\x9c\xffpAAAA')


if __name__ == '__main__':
    test_memorySolver()
    test_registerSolver()
