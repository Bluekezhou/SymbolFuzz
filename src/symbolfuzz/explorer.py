#!/usr/bin/env python
# coding=utf-8 """

"""
Module Name: Server.py
Create By  : Bluecake 
"""

from multiprocessing import Process, Queue, Semaphore
from termcolor import colored
from guesser import *
from solver import *
from triton import *
import re
import os

# context.log_level = 'DEBUG'

class Explorer(object):
    """ Branch Explore module

    This module is designed to speed up the the fuzzing process.
    As we know, a lot of seeds share somme common running state. 
    We simply distinguish different state with its input length
    and the initial seed. So we can get some thing like below:

                            s0('A', (0,1))
                              /     \ 
                             /       \
                            /         \
                           /           \
                  s1('AB', (1,2))  s2('AC', (1,2))
                       /     \
                      /       \  
                     /         \
                    /           \
            s3('ABC', (2,3)) s4('ABD', '2,3')     

    As we can see, we can swich from s0 to s1, and from s1 to s3 just
    by adding one more byte. So if we want to explore s3 and s4, we 
    can use a same initial state s1, which means when we get to s1, 
    just hold on, call fork() and input 'C' or 'D' to get into s3 or
    s4. 

    Another problem might be from branch solving. Think about such 
    a situation: When we are exploring s4, we get a new state which 
    at level one:

                            s0('A', (0,1))
                              /     \      \
                             /       \         \
                            /         \            \
                           /           \               \
                  s1('AB', (1,2))  s2('AC', (1,2))  s5('AD', (1,2))
                       /     \
                      /       \  
                     /         \
                    /           \
            s3('ABC', (2,3)) s4('ABD', '2,3')     

    How to track the father state of s5?
        It's simple. As we can known which byte is modified, we can 
    compare it with current state's input range. If same, they share 
    the same father state. If not, compare it with father's fahter.
    Repeat this process until root state, which doesn't seed any input, 
    is compared, and of course, now its fasther state is root state.

    Attributes:
        
    """

    def __init__(self, binary, seed=''):
        self.main_queue = Queue()  # Communication bridge between process
        self.arg_bridge = Queue()
        self.result_bridge = Queue()
        self.lock = Semaphore()
        self.binary = binary

        self.emulator = Emulator(binary)
        self.emulator.initialize()
        self.emulator.show_inst = False
        self.emulator.show_output = False

        bin_root = os.path.dirname(os.path.abspath(binary))
        self.config_file = os.path.join(bin_root, 'fuzz_record.txt')

        self.seed = seed

    def save_state(self):
        log.info('Explorer save_state called')

        data1 = (self.solve_record, self.tried_seeds, self.left_seeds)
        data2 = (self.atoi_solve, self.crash_seeds)
        open(self.config_file, 'wb').write(repr((data1, data2)))

    def load_state(self):
        log.info("Explorer load_state called")

        if os.path.exists(self.config_file):
            data = open(self.config_file).read()
            data1, data2 = eval(data)
            self.solve_record, self.tried_seeds, self.left_seeds = data1
            self.atoi_solve, self.crash_seeds = data2

        else:
            # data1
            self.solve_record = {}
            self.tried_seeds = []
            self.left_seeds = []
            # data2
            self.atoi_solve = {}
            self.crash_seeds = []

    def run2nextState(self):
        """ Keep running until program exit or stdin buffer is null """
        def hook_read(emulator, fd, addr, length):
            if emulator.stdin == '':
                emulator.running = False
                emulator.stop_at_read = True
        
        self.add_callback('read_before', hook_read)
        while self.emulator.running:
            self.emulator.process()
        
        # Now the program stopped at reading syscall
        # Restore program state
        self.emulator.setpc(self.emulator.last_pc)
        self.emulator.running = True
        self.emulator.stop_at_read = False
        
    def set_seed(self, seed):
        """ Set seed for the next stage 
        
        Args:
            seed: A seed that will be new input of the program

        Return:
            A boolean: false means given seed and initial seed 
        is not compatible
        """

        # Check seed compatibility
        if not seed.startswith(self.seed):
            log.warn('Given seed is not compatible with initial seed')
            return False

        self.emulator.set_input(seed[len(self.seed):])
        self.seed = seed

        return True

    def isJmpInst(self, instType):
        """Check whether a given instType is jmp type
        
        Args:
            instType: inst type of instruction

        Return:
            boolean, true or false
        """

        if instType in [OPCODE.JA, OPCODE.JAE, OPCODE.JB, OPCODE.JBE, OPCODE.JE, 
                    OPCODE.JG, OPCODE.JGE, OPCODE.JL, OPCODE.JLE, OPCODE.JNE, OPCODE.JNO, 
                    OPCODE.JNP, OPCODE.JNS, OPCODE.JO, OPCODE.JP, OPCODE.JS]:
            return True

        else:
            return False
    
    def explore_atoi(self, breakpoint, retaddr):
        """ Find useful atoi results 
        
        Args:
            breakpoint: Emulator state when this function is called
            retaddr: return address of atoi

        Return:
            list, value that the program prefers
        """

        def read_before(emulator, fd, addr, length):
            if emulator.stdin == '':
                emulator.running = False

        self.emulator.add_callback('read_before', read_before)
        
        breakaddr, inst_count = breakpoint
        while self.emulator.running:
            if self.emulator.getpc() == breakaddr and self.emulator.inst_count == inst_count:
                while self.emulator.getpc() != retaddr:
                    self.emulator.process()
                
                log.info(colored('Start symbolizing atoi result register eax', 'green'))
                self.emulator.symbolize_reg('eax')

            self.emulator.process()

        result = []
        
        pco = self.emulator.triton.getPathConstraints()

        for pc in pco:
            if pc.isMultipleBranches():
                branches = pc.getBranchConstraints()
                for branch in branches:
                    if not branch['isTaken']:
                        models = self.emulator.triton.getModel(branch['constraint'])
                        for k, v in models.items():
                            result.append(v.getValue())

        self.result_bridge.put(result)

    def solveConstraint(self, constraint):

        try:
            models = self.emulator.triton.getModel(constraint)
            answer = {}

            for k, v in models.items():
                log.debug(v)
                index = int(v.getName().replace('SymVar_', ''))
                answer[index] = chr(v.getValue())

        except Exception as e:
            log.debug(e)
            return {}

        return answer

    def solve_branch(self, path):
        """ Get seed that will take another branch
        
        Args:
            path: A list of every passed branch address

        Return:
            A string, new seed if exists 
        """
        state = hash(tuple(path))
        if state in self.solve_record:
            return None 

        pcos = self.emulator.triton.getPathConstraints()
        if not pcos:
            return None

        pco = pcos[-1]
        branches = pco.getBranchConstraints()
        for branch in branches:
            if branch['srcAddr'] == self.emulator.last_pc and not branch['isTaken']:
                bco = branch['constraint']
                answer = self.solveConstraint(bco)
                if not answer:
                    return None

                self.solve_record[state] = True
                return answer

    def server(self):
        while True:
            target, args = self.arg_bridge.get()
            print 'target is ', target
            if target == 'explore_atoi':
                p = Process(target=self.explore_atoi, args=args)
                p.start()
                p.join()

            elif target == 'exit':
                log.info('Server exit')
                self.result_bridge.put(None)
                return

            else:
                continue

    def snapshot(self):
        self.server = Process(target=self.server)
        self.server.start()

    def server_run(self, args):
        self.arg_bridge.put(args)
        result = self.result_bridge.get()
        return result

    def do_work(self, seed):
        """ Try to find new branch seeds from current state """
        
        self.set_seed(seed)
        
        def is_symbolize(emulator, offset):
            return True
        
        def read_before(emulator, fd, addr, length):
            if emulator.stdin == '':
                emulator.running = False
                emulator.try_read = length 
            else:
                emulator.try_read = 0

        # def read_after(emulator, content):
        #     if hasattr(emulator, 'seed'):
        #         emulator.seed += content
        #     else:
        #         emulator.seed = content    
                  
        self.emulator.add_callback('symbolize_check', is_symbolize) 
        self.emulator.add_callback('read_before', read_before)
        # self.emulator.add_callback('read_after', read_after)

        self.snapshot()

        result = []
        path = []
        guesser = Guesser(self.binary)
        try:
            while self.emulator.running:
                if self.isJmpInst(self.emulator.lastInstType):
                    path.append(self.emulator.getpc())
                    new_seed = self.solve_branch(path)
                    if new_seed:
                        result.append(new_seed + 'A' * self.mulator.try_read)
                
                elif self.emulator.lastInstType == OPCODE.CALL:
                    # log.info('guessing function at ' + hex(emulator.getpc()))
                    if guesser.guessFunc(self.emulator.getpc()) == FUNCTYPE.FUNC_atoi:
                        state = hash(tuple(path))
                        
                        esp = self.emulator.getreg('esp')
                        buf_ptr = self.emulator.getuint32(esp + 4)
                        atoi_arg = self.emulator.getMemoryString(buf_ptr)

                        log.info('[%s] atoi called, arg is %s' % (hex(self.emulator.last_pc), repr(atoi_arg)))
                        if state not in self.atoi_solve:
                            self.atoi_solve[state] = True

                            breakpoint = (self.emulator.getpc(), self.emulator.inst_count)
                            args = (breakpoint, guesser.getFuncRet(self.emulator.getpc()))
                            atoi_result = self.server_run(('explore_atoi', args))
                            values = []
                            for r in atoi_result:
                                values.append(str(r-1).ljust(8, 'A')[:8])
                                values.append(str(r).ljust(8, 'A')[:8])
                                values.append(str(r+1).ljust(8, 'A')[:8])

                            for i in range(1, 9):
                                values.append(('1'*i).ljust(8, 'A'))
                                values.append(('-'+'1'*i).ljust(8, 'A'))

                            values = list(set(values))
                            log.info('good atoi result is ' + str(values))

                            dst = range(buf_ptr, buf_ptr + 8)
                            breakpoint = (self.emulator.getpc(), self.emulator.inst_count)
                            self.solver.set_breakpoint(breakpoint)
                            self.solver.set_input(seed, self.emulator.read_count)
                            self.solver.solverMemoryList(dst, values)
                            for ans in answer:
                                print ans
                                new_seed = self.solver.createInput(ans)
                                result.append(new_seed)

                        while self.emulator.running and self.emulator.getpc() != self.atoi_end:
                            emulator.process()

                        pattern = re.compile(r'^-?[0-9]+.*')
                        match = pattern.match(atoi_arg)
                        if not match:  # input is not so good
                            log.info(colored('Discarding bad input of atoi', 'red'))
                            return result

                self.emulator.process()

        except IllegalPcException as e:
            log.success(colored('Find crash: ' + repr(seed), 'red'))
            self.crash_seeds.append(seed)
        
        if self.emulator.try_read > 0:
            result.append(seed + 'A' * self.emulator.try_read)
        
        elif seed not in self.tried_seeds:
            log.info(colored('The program finished normally with current seed, no more fuzzing', 'green'))
            self.tried_seeds.append(hash(seed))
        
        return result

    def explore(self, seed):
        self.load_state()
        work = Process(target=self.do_work, args=(seed,))
        work.start()
        work.join()
        result = self.main_queue.get()
        print result
        self.save_state()
        


