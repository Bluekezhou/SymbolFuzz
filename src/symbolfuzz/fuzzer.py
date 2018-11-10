#!/usr/bin/env python
# coding=utf-8 """

"""
Module Name: Fuzzer.py
Create By  : Bluecake
Description: Automatically Fuzzing Module
"""

from multiprocessing import Queue
from termcolor import colored
from solver import *
from triton import *
import ctypes
import random
import shutil
import gc
import re


class Fuzzer(object):
    """ Auto fuzzer module

    Attributes:
        binary: A string, path to executable binary file
        guesser: A Guesser object, provide support for function analysis
        solver: A InputSolver object, provide support for contraints solving
        
        bin_root: A string, directory of executable binary file
        config_file: fuzz state log file
        timeout: The fuzzer process will restart when timeout is reached
    """
    
    def __init__(self, binary_path):
        """Class constructor

        Args:
            binary_path: path of binary file
        """

        self.logger = LogUtil.get_logger()

        if not os.path.exists(binary_path):
            self.logger.warn('binary file %s not exists' % binary_path)
            return

        bin_name = os.path.basename(binary_path)
        self.bin_root = os.path.dirname(os.path.abspath(binary_path))
        self.fuzz_dir = os.path.join(self.bin_root, bin_name + '_symbol_fuzzer')
        if not os.path.exists(self.fuzz_dir):
            os.mkdir(self.fuzz_dir)

        tmp_bin = os.path.join(self.fuzz_dir, bin_name)
        if not os.path.exists(tmp_bin):
            shutil.copy(binary, tmp_bin)
        self.binary = tmp_bin

        self.config_file = os.path.join(self.fuzz_dir, 'fuzz_record.txt')
        # self.log_file = os.path.join(self.fuzz_dir, 'log.txt')
        self.timeout = 180
        self.running = True
        self.bridge = Queue()
        self.circle = 500    # seconds, can be longer
        self.cache_dir = ''

        # if run with root, init ram disk
        if os.geteuid() == 0:
            self.create_ramdisk(1)

    def create_ramdisk(self, size):
        cache_dir = '/tmp/fuzz_ramdisk'
        if os.path.exists(cache_dir):
            self.cache_dir = cache_dir
            return 

        try:
            os.makedirs(cache_dir) 
            if os.path.exists(cache_dir):
                self.cache_dir = cache_dir

            os.system('mount -t tmpfs -o size=%dG tmpfs %s' % (size, cache_dir))

        except Exception as e:
            print e

    def save_state(self):
        self.logger.info('Fuzzer save_state called')

        data1 = (self.solve_record, self.tried_seeds)
        data2 = (self.seed_tree, self.atoi_solve)
        data3 = (self.seeds, self.crash_seeds)
        open(self.config_file, 'wb').write(repr((data1, data2, data3)))

    def load_state(self):
        self.logger.info("Fuzzer load_state called")

        if os.path.exists(self.config_file):
            data = open(self.config_file).read()
            data1, data2, data3 = eval(data)
            self.solve_record, self.tried_seeds = data1
            self.seed_tree, self.atoi_solve = data2
            self.seeds, self.crash_seeds = data3
            if not self.seeds:
                return False

        else:
            # data1
            self.solve_record = {}
            self.tried_seeds = []
            # data2
            self.seed_tree = {
                '': {'father': '', 'path': 0},
                'A': {'father': '', 'path': 0}
            }
            self.atoi_solve = {}
            # data3
            self.seeds = []
            self.crash_seeds = []

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

    def solveConstraint(self, emulator, constraint):

        try:
            models = emulator.triton.getModel(constraint)
            answer = {}

            for k, v in models.items():
                log.debug(v)
                index = int(v.getName().replace('SymVar_', ''))
                answer[index] = chr(v.getValue())

        except Exception as e:
            log.debug(e)
            return {}

        return answer
    
    def getDumpfile(self, seed):
        binary = os.path.basename(self.binary)
        salt = md5(self.binary)
        seed_hash = md5(salt + seed, is_file=False)
        dumpfile_filename = "%s_%s.dump" % (binary, seed_hash) 
        dumpfile_path = os.path.join('/tmp', self.cache_dir, dumpfile_filename)
        return dumpfile_path

    def init_emulator(self, seed):
        base_seed = self.get_base(seed)
        dumpfile_path = self.getDumpfile(base_seed)  
        emulator = Debugger(EmuConstant.MODE_ELF, binary=self.binary, dumpfile=dumpfile_path)
        emulator.show_inst = False
        emulator.show_output = False
        emulator.set_input(seed[len(base_seed):])
        return emulator

    def get_base(self, seed):
        return self.seed_tree[seed]['father']
    
    def get_path(self, seed):
        return self.seed_tree[seed]['path']

    def set_base(self, seed, base_seed):
        self.seed_tree[seed]['father'] = base_seed
        # self.seed_tree[seed]['path'] = self.get_path(base_seed)

    def add_seed(self, base_seed, new_seed, path):
        """ Add new seed to seed_tree """

        if type(path) == int:
            self.seed_tree[new_seed] = {"father": base_seed, "path": path}

        elif len(path) == 1:
            self.seed_tree[new_seed] = {"father": base_seed, "path": path[0]}

        else:
            self.seed_tree[new_seed] = {"father": base_seed, "path": hash(tuple(path))}

    def solve_branch(self, emulator, base_seed, path):
        """ Get seed that will take another branch
        
        Args:
            emulator: Emulator object instance
            base_seed
            path:

        Return:
            A string, new seed if exists 
        """
        pcos = emulator.triton.getPathConstraints()

        def detectConstantBranch():
            if base_seed == '':
                state = hash(tuple(path))
                self.solve_record[state] = True
                log.info('[1] Detect constant branch at %s with state %s' % (hex(emulator.getpc()), state))

        if not pcos:
            detectConstantBranch()
            return None

        pco = pcos[-1]
        branches = pco.getBranchConstraints()
        # log.info('There are %d branches at %s' % (len(branches), hex(emulator.last_pc)))

        for branch in branches:
            if branch['srcAddr'] != emulator.last_pc:
                detectConstantBranch()
                return None

            if branch['isTaken']:
                state = hash(tuple(path))
                self.solve_record[state] = True

            else:
                taken_path = path[:-1]
                taken_path.append(branch['dstAddr'])
                state = hash(tuple(taken_path))
                if state in self.solve_record:
                    log.info('current branch has been explored, state is %s at %s' % (state, hex(emulator.getpc())))
                    continue

                bco = branch['constraint']
                answer = self.solveConstraint(emulator, bco)
                if answer or base_seed == '':
                    if base_seed == '':
                        log.info('[2] Detect constant branch at %s with state %s' % (hex(emulator.getpc()), state))
                    self.solve_record[state] = True
                return answer

        return None

    def explore_atoi(self, breakpoint, retaddr, seed):

        emulator = self.init_emulator(seed)

        def read_before(emulator, fd, addr, length):
            if emulator.stdin == '':
                emulator.running = False

        emulator.add_callback('read_before', read_before)
        
        breakaddr, inst_count = breakpoint
        try:
            while emulator.running:
                if emulator.getpc() == breakaddr and emulator.inst_count == inst_count:
                    while emulator.getpc() != retaddr:
                        emulator.process()

                    self.logger.info(colored('Start symbolizing atoi result register eax', 'green'))
                    emulator.symbolize_reg('eax')

                emulator.process()
        except IllegalPcException as e:
            log.warn(e)

        except IllegalInstException as e:
            log.warn(e)

        result = []
        
        pco = emulator.triton.getPathConstraints()

        for pc in pco:
            if pc.isMultipleBranches():
                branches = pc.getBranchConstraints()
                for branch in branches:
                    if not branch['isTaken']:
                        models = emulator.triton.getModel(branch['constraint'])
                        for k, v in models.items():
                            result.append(v.getValue())
        
        return result

    def explore_reg(self, emulator, reg):

        initial_reg = emulator.getreg(reg)
        log.info('current %s is %d' % (reg, initial_reg))
        min = initial_reg
        max = 0x1000

        treg = eval('emulator.triton.registers.' + reg)
        reg_id = emulator.triton.getSymbolicRegisterId(treg)
        reg_sym = emulator.triton.getSymbolicExpressionFromId(reg_id)
        reg_ast = reg_sym.getAst()

        new_input = {}
        while min < max:
            # print min, max

            medium = (min + max) / 2
            astCtxt = emulator.triton.getAstContext()
            constraints = list()
            constraints.append(emulator.triton.getPathConstraintsAst())
            constraints.append(astCtxt.equal(reg_ast, astCtxt.bv(medium, 32)))
            cstr = astCtxt.land(constraints)
            model = emulator.triton.getModel(cstr)
            new_input = {}
            for k, v in model.items():
                log.debug(v)
                index = int(v.getName().replace('SymVar_', ''))
                new_input[index] = chr(v.getValue())

            if new_input:
                # min can be bigger
                min = medium
            else:
                # max s too big, just be smaller
                max = medium

            if min == max - 1:
                if min > initial_reg:
                    log.info('find a bigger read length input ' + str(min))
                    return new_input
                break

        return new_input
    
    def gen_atoi_seeds(self, emulator, seed, ptr, length, retvs):
        values = []
        for r in retvs:
            r = ctypes.c_int32(r).value
            values.append(str(r).ljust(10, 'A'))

        # Generate some random seeds for atoi
        for i in range(1, 10):
            v = random.randint(10**(i-1), 10**i)
            values.append(str(v).ljust(10, 'A'))

        v = random.randint(10**8, 10**9)
        values.append(str(v * -1))
        
        values = list(set([v[:length] for v in values]))
        log.info('fuzz atoi ' + repr(values))

        dst = range(ptr, ptr + length)
        breakpoint = (emulator.getpc(), emulator.inst_count)
        self.solver.set_breakpoint(breakpoint)
        base_seed = self.get_base(seed)
        dumpfile = self.getDumpfile(base_seed)
        self.solver.set_dumpfile(dumpfile)
        self.solver.set_input(emulator.true_read, emulator.read_count)
        answer = self.solver.solveMemoryList(dst, values)
        
        result = []
        base_seed = self.get_base(seed)
        for ans in answer:
            new_seed = base_seed + self.solver.createInput(ans)
            log.info('[2] Get new seed %s' % repr(new_seed))
            result.append(new_seed)

        return result

    def explore(self, seed='A'):
        """ explore the program with seed and give new seeds
        
        Args:
            seed: initial input of the program
        """
        emulator = self.init_emulator(seed)

        def is_symbolize(emulator, offset):
            return True
        
        def read_before(emulator, fd, addr, length):
            if emulator.stdin == '':
                emulator.running = False
                emulator.try_read = length 
            else:
                emulator.last_read_length = length
                emulator.try_read = 0

        def read_after(emulator, content):
            """ Deal with input filled with 'A' or any other data """

            if hasattr(emulator, 'true_read'):
                emulator.true_read += content
            else:
                emulator.true_read = content

            emulator.sys_read = True

        def syscall_before(emulator, *args):
            emulator.sys_read = False

        emulator.add_callback('symbolize_check', is_symbolize) 
        emulator.add_callback('read_before', read_before)
        emulator.add_callback('read_after', read_after)
        emulator.add_callback('syscall_before', syscall_before)

        result = []
        base_seed = self.get_base(seed)
        path = [self.get_path(base_seed)]
        log.info('base_seed is ' + repr(base_seed))
        log.debug('base_path is ' + repr(path))
        
        try:
            while emulator.running:
                if self.isJmpInst(emulator.last_inst_type):
                    # log.info('Detect branch at %s' % hex(emulator.getpc()))

                    if emulator.sys_read:
                        path = [hash(tuple(path))]
                        emulator.sys_read = False

                    path.append(emulator.getpc())
                    state = hash(tuple(path))
                    if state not in self.solve_record:
                        answer = self.solve_branch(emulator, base_seed, path)
                        if answer:
                            self.solver.set_input(emulator.true_read, emulator.read_count)
                            new_seed = base_seed + self.solver.createInput(answer)
                            log.info('[1] Get new seed %s' % repr(new_seed))
                            self.add_seed(base_seed, new_seed, path)
                            result.append(new_seed)

                        elif base_seed != '':
                            # Since there are some unsolvable branches, I put it back
                            # to new seeds again
                            log.info('[1] Find branch unsolvable %s with state %s' %
                                     (hex(emulator.getpc()), state))
                            self.set_base(seed, '')
                            res = self.explore(seed)
                            result.extend(res)
                            return result

                elif emulator.last_inst_type == OPCODE.CALL:
                    # log.info('guessing function at ' + hex(emulator.last_pc))
                    if self.guesser.guessFunc(emulator.getpc()) == FUNCTYPE.FUNC_atoi:
                        state = hash(tuple(path))

                        esp = emulator.getreg('esp')
                        buf_ptr = emulator.getuint32(esp + 4)
                        atoi_arg = emulator.getMemoryString(buf_ptr)[:8]

                        count = 0
                        for i in range(emulator.read_count):
                            # print emulator.isMemorySymbolized(buf_ptr + i)
                            if not emulator.isMemorySymbolized(buf_ptr + i):
                                break
                            count += 1
                        # print count
                        retaddr = self.guesser.func_info[emulator.getpc()][1]
                        log.info('[%s] atoi arg is %s' %
                                 (hex(emulator.last_pc), repr(atoi_arg)))

                        if state not in self.atoi_solve:
                            if count > 0:
                                self.atoi_solve[state] = True

                                breakpoint = (emulator.getpc(), emulator.inst_count)
                                atoi_result = self.explore_atoi(breakpoint, retaddr, seed)
                                log.info('good atoi result is ' + repr(atoi_result))
                                
                                seeds = self.gen_atoi_seeds(emulator, seed, buf_ptr, count, atoi_result) 
                                for _seed in seeds:
                                    result.append(_seed)
                                    self.add_seed(base_seed, _seed, path)

                            elif base_seed != '':
                                # It's possible that atoi args is not controllabe. There is no easy way 
                                # to judge whether it's args is from user input or constant strings.
                                # A simpler way is downgrade its base_seed and put it back to seeds.
                                log.info('Detect atoi args uncontrolale, may lost symbol information')
                                self.set_base(seed, self.get_base(base_seed))
                                result.append(seed)
                                return result

                        else:
                            log.info('Current atoi branch has been explored, state is %s' % state)

                        # Here we do some check with atoi input. If not starts with
                        # a minus or a number, I think it's not a good input.
                        pattern = re.compile(r'^-?[0-9]+.*')
                        match = pattern.match(atoi_arg)
                        if not match:  
                            self.tried_seeds.append(hash(seed))
                            log.info(colored('Discarding bad input of atoi', 'yellow'))
                            return result

                        while emulator.running and emulator.getpc() != retaddr:
                            # Since we have dealed with atoi input and output, 
                            # we don't need to explore atoi inner branches anymore.
                            emulator.process()

                emulator.process()

        except IllegalPcException:
            log.warn(colored('[1] Find crash at %s with %s' % (hex(emulator.getpc()), repr(seed)), 'red'))
            self.crash_seeds.append(seed)

        except IllegalInstException:
            log.warn(colored('[2] Find crash at %s with %s' % (hex(emulator.getpc()), repr(seed)), 'red'))
            self.crash_seeds.append(seed)

        if emulator.try_read > 0:
            if emulator.isRegisterSymbolized('edx'):
                log.info('find controllable read length')
                ans = self.explore_reg(emulator, 'edx')
                if ans:
                    self.solver.set_input(emulator.true_read, emulator.read_count)
                    new_seed = base_seed + self.solver.createInput(ans)
                    log.info('[4] Get interesting seed %s' % repr(new_seed))
                    self.add_seed(seed, new_seed, path)
                    result.append(new_seed)

            new_seed = seed + 'A' * emulator.try_read
            log.info('[3] Get new seed %s' % repr(new_seed))
            result.append(new_seed)
            
            def check2exp(num):
                for i in range(20):
                    if num == 2**i:
                        return True
                return False

            # Think about such situation: A program read only one bytes in a loop 
            # until '\n' is encountered or any other condition. If we create too
            # new base_seeds, it will occupy a huge disk space. So when such scene
            # happened, we make it aligned to powers of 2.
            if emulator.try_read == 1 and check2exp(len(new_seed)):
                log.info('[1] add_seed, new seed is %s' % repr(new_seed))
                self.add_seed(seed, new_seed, path)
            else:
                log.info('[2] add_seed, new seed is %s' % repr(new_seed))
                self.add_seed(seed, new_seed, path)

            # create inputs from generated seeds
            random_seeds = []
            for i in range(10):
                index = random.randint(0, len(result) - 1)
                random_seeds.append(result[index])

            random_space = ''.join(list(set(random_seeds)))
            
            fuzz_seeds = []
            for i in range(3):
                new_seed = ''
                for _ in range(max(0x10, emulator.try_read)):
                    new_seed += random_space[random.randint(0, len(random_space) - 1)]
                fuzz_seeds.append(new_seed)

            fuzz_seeds = list(set(fuzz_seeds))
            for fuzz_seed in fuzz_seeds: 
                new_seed = seed + fuzz_seed
                result.append(new_seed)
                log.info('[5] Get new seed %s' % repr(new_seed))
                self.add_seed(seed, new_seed, path)
                
        elif seed not in self.tried_seeds:
            log.info(colored('The program finished normally with current seed, no more fuzzing', 'green'))
            self.tried_seeds.append(hash(seed))
        
        return result

    def process_fuzz(self):
        gc.disable()
        # if self.logv:
        #     context.log_level = self.logv
        # context.log_level = "WARN"
        
        if not self.load_state():
            return

        self.guesser = Guesser(self.binary)
        self.solver = InputSolver(self.binary)

        if not self.seeds:
            seeds = [('', 0)]
        else:
            seeds = sorted(self.seeds, key=lambda v: v[1])

        start = int(time.time())
        count = 0
        while seeds:
            new_seeds = []
            for _ in range(len(seeds)):
                log.info('current seeds has %d items' % len(seeds))
                if count % 10 == 0:
                    index = random.randint(0, len(seeds))
                else:
                    index = 0
                
                log.info('random seed index is %d' % index)
                seed, level = seeds.pop(0)

                if hash(seed) in self.tried_seeds:
                    log.info(colored('Discarding duplicate seed', 'green'))
                    continue

                count += 1
                log.info('seed count is %d' % count)
                log.info('try seed: %s, level is %d' % (repr(seed), level))
                result = self.explore(seed)
                if result:
                    # log.info('result ' + repr(result))
                    new_seeds.extend(result)

                now = int(time.time())
                if now - start > self.timeout:
                    log.info('memory leak time is out, restart fuzzer')
                    self.seeds = seeds
                    B = [v[0] for v in seeds]
                    for a in set(new_seeds):
                        if a not in B:
                            self.seeds.append((a, level + 1))

                    self.save_state()
                    self.bridge.put(True)
                    sys.exit()
            
            seeds = [(v, level+1) for v in set(new_seeds)]
            log.debug('seeds ' + repr(seeds))
            self.guesser.save_state()
            self.solver.save_state()
            if self.crash_seeds:
                log.warn(colored(str(self.crash_seeds), "red"))

        self.bridge.put(False)

    def fuzz(self):
        """Start Fuzzing
        
        Since there is a memory leaking problem in Triton, 
        so I fix it with create new fuzzing process continuously.
        """

        if not self.binary:
            return 

        try:
            self.running = True
            for i in range(self.circle):  # about 6 hours
                if self.running:
                    # p = Process(target=self.process_fuzz)
                    # p.start()
                    # p.join()
                    # self.running = self.bridge.get()
                    self.process_fuzz()

        except KeyboardInterrupt:
            sys.exit()

    def stop(self):
        self.running = False

    def get_crash(self):
        self.load_state()
        return self.crash_seeds


if __name__ == '__main__':
    binary = sys.argv[1]
    fuzzer = Fuzzer(binary)
    fuzzer.fuzz()

