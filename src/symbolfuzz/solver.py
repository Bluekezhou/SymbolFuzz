#!/usr/bin/env python
# coding=utf-8

"""
Module Name: InputSolver.py
Create By  : Bluecake
Description: A class for symbolic solving
"""

from pwn import *
from symbolfuzz.core.emulator import *
from symbolfuzz.core.debugger import *
from copy import deepcopy


class InputSolver(object):

    """
    Arguments:
        @param binary: path of binary file
        @param src: memory address list of input
        @param initInput: input data for program
    """
    def __init__(self, binary):

        self.binary = binary
        self.dumpfile = ''
        self.good_symbolize_byte = 0x20

        bin_root = os.path.dirname(os.path.abspath(binary))
        self.config_file = bin_root + '/track_record.txt'
        self.load_state()

    def __del__(self):
        try:
            open(self.config_file, 'wb').write(repr(self.track_record))
        except Exception as e:
            log.debug(e)

    def setGoodSYMbyte(self,size):
        self.good_symbolize_byte = size 
        
    def save_state(self):
        log.info('InputSolver save_state called')
        self.__del__()

    def load_state(self):
        log.info('InputSolver load_state called')
        if os.path.exists(self.config_file):
            data = open(self.config_file).read()
            self.track_record = eval(data)
        else:
            self.track_record = {}

    def set_input(self, seed, read_count):
        self.read_count = read_count
        self.seed = seed
    
    def set_breakpoint(self, breakpoint):
        self.breakpoint = breakpoint
    
    def set_dumpfile(self, dumpfile):
        self.dumpfile = dumpfile

    """
    New and init an emulator
    """
    def initEmulator(self):

        if self.dumpfile:
            # log.info('load dumpfile from ' + self.dumpfile)
            emulator = Debugger(self.binary, self.dumpfile)
        else:
            emulator = Emulator(self.binary)

        emulator.initialize()
        emulator.show_inst = False
        emulator.show_output = False

        if self.seed:
            emulator.set_input(self.seed)
        
        return emulator

    def run2breakpoint(self, emulator):
        
        pc = emulator.getpc()
        breakaddr, inst_count = self.breakpoint
        while emulator.running:
            if emulator.getpc() == breakaddr and emulator.inst_count == inst_count:
                return True
            emulator.process()

        log.warn('breakpoint has not been triggered')
        return False

    def checkTainted(self, src, dst):
        emulator = self.initEmulator()

        def isTaintable(emulator, offset):
            if offset in src:
                return True
            else:
                return False

        def clearTaintData(emulator, fd, addr, length):
            for i in range(length):
                emulator.triton.untaintMemory(addr + i)

        emulator.add_callback('taint_check', isTaintable)
        emulator.add_callback('read_before', clearTaintData)
        self.run2breakpoint(emulator) 

        if emulator.isTainted(dst):
            return True
        else:
            return False

    """
    Inner method for traceMemory
    Parameters:
        @param src: input offset list 
        @param dst: target memory address list or register name that we need to control 
    """
    def _traceMemory(self, src, dst):
        log.info('src is ' + repr(src))
        log.debug('confirmed' + repr(self.confirmed))
        log.debug('unconfirmed' + repr(self.unconfirmed))
        if len(src) == 1:
            self.confirmed.append(src[0])
            self.unconfirmed.remove(src[0])
            return src
        
        if len(self.confirmed) + len(self.unconfirmed) <= self.good_symbolize_byte:
            return src

        left = src[ : len(src)/2]
        right = src[len(src)/2 : ]
        
        if not self.checkTainted(left, dst): 
            for o in left:
                self.unconfirmed.remove(o)
            left = []
       
        if not self.checkTainted(right, dst):
            for o in right:
                self.unconfirmed.remove(o)
            right = []

        if left:
            new_left = self._traceMemory(left, dst)
        else:
            new_left = []

        if right:
            new_right = self._traceMemory(right, dst)
        else:
            new_right = []

        return new_left + new_right


    """
    Track source input of memory content
    """
    def traceMemory(self, dst):
        log.info('traceMemory is ' + repr(dst))
        src = range(self.read_count)
        self.confirmed = []
        self.unconfirmed = deepcopy(src)
        source = self._traceMemory(src, dst)
        return source

    def getSrcInput(self, mem):
        """Track source data of target memory
        
        Args:
            mem: target memory address list or register you want to track

        Return:
            input offset list  
        """
        if type(mem) == list:
            mem = tuple(mem)

        if self.breakpoint in self.track_record and \
                mem in self.track_record[self.breakpoint]:
            symbolize_list = self.track_record[self.breakpoint][mem]

        else:
            symbolize_list = self.traceMemory(mem)
            if not symbolize_list:
                return []
            self.track_record[self.breakpoint] = {mem: symbolize_list}

        return symbolize_list

    def _solveConstraints(self, emulator, astCtxt, symbolize_list, constraints):
        cstr  = astCtxt.land(constraints)
        log.debug('Asking for a model, please wait...')
        model = emulator.triton.getModel(cstr)
        new_input = {}
        for k, v in model.items():
            log.debug(v)
            index = int(v.getName().replace('SymVar_', ''))
            new_input[symbolize_list[index]] = chr(v.getValue())
        
        return new_input

    """
    Get input data with memory constraints
    """ 
    def solveMemory(self, mem, value):
        """
        Arguments:
            mem, address list of target memory we want to solve
            value, value list of target memory we expect to be
                or a uint32 or uint64 number
        """
        if type(value) == int:
            value = map(ord, p32(value)) 
        
        elif type(value) == str:
            value = map(ord, value)


        if len(mem) != len(value):
            print len(mem) , len(value)
            log.warn("Mem and value length is not equal, please checkout")
            return False
        
        
        symbolize_list = self.getSrcInput(mem)
        if not symbolize_list:
            return {}
        
        emulator = self.initEmulator()
        log.info('symbolize_list is ' + str(symbolize_list))
        def isSymbolizable(emulator, offset):
            if offset in symbolize_list:
                return True
            else:
                return False
        
        emulator.add_callback('symbolize_check', isSymbolizable)

        self.run2breakpoint(emulator)
        Triton = emulator.triton
        astCtxt = Triton.getAstContext()
        constraints = [Triton.getPathConstraintsAst()]
        
        for i, v in enumerate(value):
            mem_id = Triton.getSymbolicMemoryId(mem[i])          
            mem_sym = Triton.getSymbolicExpressionFromId(mem_id)
            mem_ast = mem_sym.getAst()
            constraints.append(astCtxt.equal(mem_ast, astCtxt.bv(value[i], 8)))

        return self._solveConstraints(emulator, astCtxt, symbolize_list, constraints) 


    def solveMemoryList(self, mem, value_list):
        """ Get input data with memory constraints

        Args:
            mem: address list of target memory we want to solve
            value_list: list of target memory value we expect to be
        """
        symbolize_list = self.getSrcInput(mem)
        if not symbolize_list:
            return {}
        
        log.info('symbolize_list is ' + str(symbolize_list))
        emulator = self.initEmulator()

        def isSymbolizable(emulator, offset):
            if offset in symbolize_list:
                return True
            else:
                return False
        
        emulator.add_callback('symbolize_check', isSymbolizable)
        self.run2breakpoint(emulator)
         
        Triton = emulator.triton
        astCtxt = Triton.getAstContext()
       
        log.debug('value_list ' + repr(value_list))
        result = []

        for value in value_list:

            if type(value) == int:
                value = map(ord, p32(value)) 
            
            elif type(value) == str:
                value = map(ord, value)

            constraints = [Triton.getPathConstraintsAst()]
            for i, v in enumerate(value):
                mem_id = Triton.getSymbolicMemoryId(mem[i])
                mem_sym = Triton.getSymbolicExpressionFromId(mem_id)
                mem_ast = mem_sym.getAst()
                constraints.append(astCtxt.equal(mem_ast, astCtxt.bv(value[i], 8)))

            new_input = self._solveConstraints(emulator, astCtxt, symbolize_list, constraints)
            if new_input:
                result.append(new_input)

        return result

    def solveRegister(self, reg, value):
        """Get input data with register constraints

        Args:
            reg: A string, register name we want to solve
            value: An uint32 or uint64 value 

        Return：
            A dict, map of offset and related value 
        """ 
        
        symbolize_list = self.getSrcInput(reg)
        if not symbolize_list:
            return {}

        emulator = self.initEmulator()
        emulator.symbolize_list = symbolize_list

        def isSymbolizable(emulator, offset):
            if offset in symbolize_list:
                return True
            else:
                return False

        emulator.add_callback('symbolize_check', isSymbolizable)
        self.run2breakpoint(emulator)

        Triton = emulator.triton
        treg = eval('Triton.registers.' + reg)
        astCtxt = Triton.getAstContext()
        constraints = [Triton.getPathConstraintsAst()]
        
        reg_id = Triton.getSymbolicRegisterId(treg)
        reg_sym = Triton.getSymbolicExpressionFromId(reg_id)
        reg_ast = reg_sym.getAst()
        constraints.append(astCtxt.equal(reg_ast, astCtxt.bv(value, 32)))

        new_input = self._solveConstraints(emulator, astCtxt, symbolize_list, constraints)
        return new_input

    """
    Create input stream with solve answer
    """
    def createInput(self, answer, blank='A'):
        
        inputBuffer = ''
        for offset in range(self.read_count):
            if offset in answer:
                inputBuffer += answer[offset]

            elif offset < len(self.seed):
                inputBuffer += self.seed[offset]

            else:
                inputBuffer += blank

        return inputBuffer
