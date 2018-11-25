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
import random
import shutil


class Fuzzer(object):
    """ Auto fuzzer module

        In order to speed up the process of fuzzing, we introduce
        a snapshot mechanism which I called Seeds-Tree. As we know,
        a lot of seeds share somme common running state. We simply
        distinguish different states with their input length and the
        initial seed. So we can get something like below:

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

        As we can see, we can switch from s0 to s1, and from s1 to s3 by
        adding only one more byte. So if we want to explore s3 and s4, we
        can use a same initial state s1, which means when we get to s1,
        just hold on, call fork() and input 'C' or 'D' to get into s3 or
        s4.

    Attributes:

        binary: A string, path to executable binary file
        solver: A InputSolver object, provide support for constraints solving
        
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
        shutil.copy(binary_path, tmp_bin)
        self.binary = tmp_bin

        self.config_file = os.path.join(self.fuzz_dir, 'fuzz_record.txt')
        self.timeout = 180
        self.running = True
        self.bridge = Queue()
        self.circle = 500    # seconds, can be longer
        self.cache_dir = ''

        self.recognizer = Recognizer(self.binary)
        self.solver = InputSolver(self.binary)

        self.solve_record = []
        self.tried_seeds = []
        self.seed_tree = {
            '': {'father': '', 'path': 0, "tainted": []},
        }
        self.seeds = []
        self.crash_seeds = []

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
        """

        Returns:

        """
        self.logger.info('Fuzzer save_state called')

        data1 = self.solve_record
        data2 = self.seed_tree
        data3 = (self.seeds, self.crash_seeds)
        with open(self.config_file, "w") as f:
            f.write(repr((data1, data2, data3)))

    def load_state(self):
        """

        Returns:

        """
        self.logger.info("Fuzzer load_state called")

        if os.path.exists(self.config_file):
            with open(self.config_file) as f:
                data = f.read()
            data1, data2, data3 = eval(data)
            self.solve_record = data1
            self.seed_tree = data2
            self.seeds, self.crash_seeds = data3

    def solve_constraint(self, emulator, constraint):
        """Find answer for given constraint

        Args:
            emulator: Emulator instance
            constraint: SMT constraint

        Returns:
            a dict, key is input index and value is corresponding char
        """
        try:
            models = emulator.triton.getModel(constraint)
            answer = {}

            for k, v in models.items():
                self.logger.debug(v)
                index = int(v.getName().replace('SymVar_', ''))
                answer[index] = chr(v.getValue())

        except Exception as e:
            self.logger.error("We have trouble when solving SMT(%s)" % str(e))
            return {}

        return answer
    
    def get_dumpfile(self, seed):
        """

        Args:
            seed:

        Returns:

        """
        binary = os.path.basename(self.binary)
        salt = md5(self.binary)
        seed_hash = md5(salt + seed, is_file=False)
        dumpfile_filename = "%s_%s.dump" % (binary, seed_hash) 
        dumpfile_path = os.path.join('/tmp', self.cache_dir, dumpfile_filename)
        return dumpfile_path

    def init_emulator(self, seed):
        """

        Args:
            seed:

        Returns:

        """
        base_seed = self.get_base(seed)
        dumpfile_path = self.get_dumpfile(base_seed)

        script_root = os.path.dirname(__file__)
        elf = ELF(self.binary)
        arch = get_arch(elf)
        if arch == ARCH.X86:
            library = os.path.join(script_root, "libhook/libhook_x86.so")
        elif arch == ARCH.X86_64:
            library = os.path.join(script_root, "libhook/libhook_x64.so")
        emulator = Emulator(EmuConstant.MODE_ELF, binary=self.binary,
                            dumpfile=dumpfile_path, hook_library=library,
                            seed=base_seed)

        emulator.show_inst = False
        emulator.show_output = False
        emulator.set_input(seed[len(base_seed):])

        return emulator

    def get_base(self, seed):
        """

        Args:
            seed:

        Returns:

        """
        if seed in self.seed_tree:
            return self.seed_tree[seed]['father']
        else:
            return ''
    
    def get_path(self, seed):
        """

        Args:
            seed:

        Returns:

        """
        if seed in self.seed_tree:
            return self.seed_tree[seed]['path']
        else:
            return [0]

    def set_base(self, seed, base_seed):
        """

        Args:
            seed:
            base_seed:

        Returns:

        """
        self.seed_tree[seed]['father'] = base_seed

    def add_seed(self, base_seed, new_seed, path, tainted_memory):
        """ Add new seed to seed_tree

        Args:
            base_seed: base seed of new seed
            new_seed: new seed string
            path: path list
            tainted_memory: tainted memory address list
        """
        if len(path) == 1:
            self.seed_tree[new_seed] = {"father": base_seed, "path": path[0]}
        else:
            self.seed_tree[new_seed] = {"father": base_seed, "path": hash(tuple(path))}

        self.seed_tree[base_seed]['tainted'] = tainted_memory

    def get_other_way(self, emulator):
        """Get unchosen branch constraints

        Args:
            emulator: Emulator instance

        Returns:
            a list, SMT constraints of current branch if existed
        """
        constraints = emulator.triton.getPathConstraints()
        if not constraints:
            self.logger.debug("No constraints for current branch")
            return None

        last_constraint = constraints[-1]
        branches = last_constraint.getBranchConstraints()

        if branches[0]['srcAddr'] != emulator.last_pc:
            return None

        for branch in branches:
            if not branch['isTaken']:
                return branch['constraint']

        self.logger.error("Code should not run to here, please check it")
        return None

    def get_answer(self, emulator, operand, target):
        """ Get input for target value

        Args:
            emulator: Emulator instance
            operand:  operand wrapper instance
            target:   target value

        Returns:
            answer if exits
        """
        if target < 0:
            return None

        ast_ctxt = emulator.triton.getAstContext()
        constraints = list()
        constraints.append(emulator.triton.getPathConstraintsAst())
        if operand.getType() == OPERAND.REG:
            ast = emulator.triton.getRegisterAst(operand)
        elif operand.getType() == OPERAND.MEM:
            ast = emulator.triton.getMemoryAst(operand)

        constraints.append(ast_ctxt.equal(ast, ast_ctxt.bv(target, operand.getSize() * 8)))
        cstr = ast_ctxt.land(constraints)
        model = emulator.triton.getModel(cstr)
        new_input = {}
        for k, v in model.items():
            log.debug(v)
            index = int(v.getName().replace('SymVar_', ''))
            new_input[index] = chr(v.getValue())

        return new_input

    @staticmethod
    def is_jmp_inst(inst_type):
        """Check whether a given instType is jmp type

        Args:
            inst_type: inst type of instruction
        Return:
            boolean, true or false
        """

        if inst_type in [OPCODE.JA, OPCODE.JAE, OPCODE.JB, OPCODE.JBE, OPCODE.JE,
                         OPCODE.JG, OPCODE.JGE, OPCODE.JL, OPCODE.JLE, OPCODE.JNE, OPCODE.JNO,
                         OPCODE.JNP, OPCODE.JNS, OPCODE.JO, OPCODE.JP, OPCODE.JS]:
            return True

        else:
            return False

    def is_operand_tainted(self, emulator, operand):
        if operand.getType() == OPERAND.MEM:
            return emulator.triton.isMemoryTainted(operand)
        elif operand.getType() == OPERAND.REG:
            return emulator.triton.isRegisterTainted(operand)
        else:
            return False

    def run_and_solve(self, emulator, seed):
        """

        Args:
            emulator:
            seed:

        Returns:

        """
        result = []
        base_seed = self.get_base(seed)
        self.logger.info('base_seed is ' + repr(base_seed))
        # emulator.show_inst = True
        # recover tainted memory
        tainted_memory = self.seed_tree[base_seed]['tainted']
        for addr in tainted_memory:
            emulator.taint_memory(addr)

        answers = []
        branch_tainted = False
        try:
            while emulator.running:
                emulator.process()

                if emulator.last_inst_type == OPCODE.CMP:
                    operands = emulator.instruction.getOperands()
                    if self.is_operand_tainted(emulator, operands[0]) \
                            or self.is_operand_tainted(emulator, operands[1]):
                        self.logger.warn(colored("Detected tainted branch", "red"))
                        branch_tainted = True

                    if emulator.instruction.isSymbolized():
                        if operands[1].getType() == OPERAND.IMM:
                            cmp_op2 = operands[1].getValue()
                        elif operands[1].getType() == OPERAND.MEM:
                            cmp_op2 = emulator.triton.getConcreteMemoryValue(operands[1])
                        elif operands[1].getType() == OPERAND.REG:
                            cmp_op2 = emulator.getreg(operands[1].getName())

                        state = hash(tuple(self.path + [emulator.last_pc]))
                        if state in self.solve_record:
                            continue
                        self.solve_record.append(state)

                        extremum = [cmp_op2-1, cmp_op2, cmp_op2+1]
                        for v in extremum:
                            answer = self.get_answer(emulator, operands[0], v)
                            if answer and answer not in answers:
                                answers.append(answer)
                    continue

                elif not Fuzzer.is_jmp_inst(emulator.last_inst_type):
                    continue

                self.path.append(emulator.last_pc)
                if branch_tainted:
                    """ If a branch is tainted, it means that current 
                    branch is influenced by previous input, and we need
                    to update current seed's father with grandfather 
                    seed and explore it again.
                    
                    TODO: think about solution for loop
                    """
                    self.logger.info('new base_seed is "%s"' % self.get_base(base_seed))
                    self.set_base(seed, self.get_base(base_seed))
                    result.append(seed)
                    return result

                if not emulator.instruction.isSymbolized():
                    continue

                state = hash(tuple(self.path))
                if state in self.solve_record:
                    msg = "[%s] Current branch is already solved, continue" % hex(emulator.last_pc)
                    self.logger.debug(colored(msg, "green"))
                    continue

                self.solve_record.append(state)
                constraint = self.get_other_way(emulator)
                if not constraint:
                    continue

                answer = self.solve_constraint(emulator, constraint)
                if answer and answer not in answers:
                    answers.append(answer)

        except IllegalPcException:
            self.logger.warn(colored('[1] Find crash at %s with %s' % (hex(emulator.getpc()), repr(seed)), 'red'))
            self.crash_seeds.append(seed)

        except IllegalInstException:
            self.logger.warn(colored('[2] Find crash at %s with %s' % (hex(emulator.getpc()), repr(seed)), 'red'))
            self.crash_seeds.append(seed)

        except InfinityLoopException:
            self.logger.warn('Find unsupported instruction at %s' % hex(emulator.getpc()))

        for answer in answers:
            self.solver.set_input(emulator.true_read, emulator.read_count)
            new_seed = base_seed + self.solver.createInput(answer)
            if not seed.startswith(new_seed):
                self.logger.info('[1] Get new seed %s' % repr(new_seed))
                self.add_seed(base_seed, new_seed, self.path, tainted_memory)
                result.append(new_seed)

        return result

    def explore(self, seed='A'):
        """ explore the program with seed and generate new seeds
        
        Args:
            seed: initial input of the program

        Return:
            new seeds for new branches
        """
        emulator = self.init_emulator(seed)

        def read_before(_emulator, fd, addr, length):
            """ Record expected read length """
            if fd == 0:
                """ standard input """
                if _emulator.stdin == '':
                    _emulator.running = False
                    _emulator.try_read = length
                else:
                    _emulator.last_read_length = length
                    _emulator.try_read = 0
            else:
                raise NotImplementedException()

        def read_after(_emulator, content):
            """ Monitor all received data """

            if hasattr(emulator, 'true_read'):
                _emulator.true_read += content
            else:
                _emulator.true_read = content

        emulator.add_callback('symbolize_check', lambda *s: True)
        emulator.add_callback('read_before', read_before)
        emulator.add_callback('read_after', read_after)

        base_seed = self.get_base(seed)
        self.path = [self.get_path(base_seed)]
        result = self.run_and_solve(emulator, seed)
        tainted_memory = emulator.get_tainted_memory()
        symbolized_memory = emulator.get_symbolized_memory().keys()
        for addr in symbolized_memory:
            if addr not in tainted_memory:
                tainted_memory.append(addr)

        if emulator.try_read > 0:
            # syscall_arg3_reg = EmuConstant.RegisterTable[emulator.arch]['syscall_arg3']
            # if emulator.is_register_symbolized(syscall_arg3_reg):
            #     self.logger.info('find controllable read length')
            #     current_value = emulator.getreg(syscall_arg3_reg)
            #     for i in range(10):
            #         ans = self.explore_reg(emulator, syscall_arg3_reg, current_value + 2**i)
            #         if ans:
            #             self.solver.set_input(emulator.true_read, emulator.read_count)
            #             new_seed = base_seed + self.solver.createInput(ans)
            #             self.logger.info('[4] Get interesting seed %s' % repr(new_seed))
            #             self.add_seed(seed, new_seed, path, tainted_memory)
            #             result.append(new_seed)

            new_seed = seed + 'A' * emulator.try_read
            self.logger.info('[3] Get new seed %s' % repr(new_seed))
            result.append(new_seed)

            def align_check(num):
                for p in range(20):
                    if num == 2**p:
                        return True
                return False

            # Think about such situation: A program read only one bytes in a loop
            # until '\n' is encountered or any other condition. If we create those
            # new base_seeds, it will occupy a huge disk space. So when such scene
            # happened, we make it aligned to powers of 2.
            if emulator.try_read == 1:
                if align_check(len(new_seed)):
                    self.logger.info('[1] add_seed, new seed is %s' % repr(new_seed))
                    self.add_seed(seed, new_seed, self.path, tainted_memory)

            else:
                self.logger.info('[2] add_seed, new seed is %s' % repr(new_seed))
                self.add_seed(seed, new_seed, self.path, tainted_memory)

            # create inputs from generated seeds
            # random_seeds = []
            # for i in range(10):
            #     index = random.randint(0, len(result) - 1)
            #     random_seeds.append(result[index])
            #
            # random_space = ''.join(list(set(random_seeds)))
            #
            # fuzz_seeds = []
            # for i in range(3):
            #     new_seed = ''
            #     for _ in range(max(0x10, emulator.try_read)):
            #         new_seed += random_space[random.randint(0, len(random_space) - 1)]
            #     fuzz_seeds.append(new_seed)
            #
            # fuzz_seeds = list(set(fuzz_seeds))
            # for fuzz_seed in fuzz_seeds:
            #     new_seed = seed + fuzz_seed
            #     result.append(new_seed)
            #     log.info('[5] Get new seed %s' % repr(new_seed))
            #     self.add_seed(seed, new_seed, path)
                
        return result

    def process_fuzz(self):
        # self.load_state()
        #
        # # if not self.seeds:
        #     seeds = [('', 0)]
        # else:
        #     seeds = sorted(self.seeds, key=lambda s: s[1])

        # start = int(time.time())
        # count = 0
        seeds = [""]
        while seeds:
            new_seeds = []
            self.logger.info('current seeds has %d items' % len(seeds))
            index = random.randint(0, len(seeds)-1)
            self.logger.info('random seed index is %d' % index)
            seed = seeds.pop(index)

            self.logger.info('try seed: %s' % repr(seed))
            result = self.explore(seed)
            if result:
                seeds.extend(result)

            # seeds = [(v, level+1) for v in set(new_seeds)]
            # self.logger.debug('seeds ' + repr(seeds))
            # self.solver.save_state()
            if self.crash_seeds:
                self.logger.warn(colored(str(self.crash_seeds), "red"))

        # self.bridge.put(False)

    def fuzz(self):
        """Start Fuzzing
        
        Since there is a memory leaking problem in Triton, 
        so I fix it with create new fuzzing process continuously.
        """

        if not self.binary:
            return 

        try:
            self.running = True  # can altered at any time
            # for i in range(self.circle):  # about 6 hours
            self.process_fuzz()

        except KeyboardInterrupt:
            sys.exit()

    def stop(self):
        self.running = False

    def get_crash(self):
        self.load_state()
        return self.crash_seeds
