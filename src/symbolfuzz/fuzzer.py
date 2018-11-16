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

    Attributes:
        binary: A string, path to executable binary file
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

        self.solve_record = {}
        self.tried_seeds = []
        self.seed_tree = {
            '': {'father': '', 'path': 0},
            'A': {'father': '', 'path': 0}
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
        self.logger.info('Fuzzer save_state called')

        data1 = (self.solve_record, self.tried_seeds)
        data2 = self.seed_tree
        data3 = (self.seeds, self.crash_seeds)
        with open(self.config_file, "w") as f:
            f.write(repr((data1, data2, data3)))

    def load_state(self):
        self.logger.info("Fuzzer load_state called")

        if os.path.exists(self.config_file):
            data = open(self.config_file).read()
            data1, data2, data3 = eval(data)
            self.solve_record, self.tried_seeds = data1
            self.seed_tree = data2
            self.seeds, self.crash_seeds = data3

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

    @staticmethod
    def solve_constraint(emulator, constraint):

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
    
    def get_dumpfile(self, seed):
        binary = os.path.basename(self.binary)
        salt = md5(self.binary)
        seed_hash = md5(salt + seed, is_file=False)
        dumpfile_filename = "%s_%s.dump" % (binary, seed_hash) 
        dumpfile_path = os.path.join('/tmp', self.cache_dir, dumpfile_filename)
        return dumpfile_path

    def init_emulator(self, seed):
        base_seed = self.get_base(seed)
        dumpfile_path = self.get_dumpfile(base_seed)

        script_root = os.path.dirname(__file__)
        elf = ELF(self.binary)
        arch = get_arch(elf)
        if arch == ARCH.X86:
            library = os.path.join(script_root, "libhook/libhook_x86.so")
        elif arch == ARCH.X86_64:
            library = os.path.join(script_root, "libhook/libhook_x64.so")
        emulator = Debugger(EmuConstant.MODE_ELF, binary=self.binary,
                            dumpfile=dumpfile_path, hook_library=library)

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

        def detect_constant_branch():
            if base_seed == '':
                state = hash(tuple(path))
                self.solve_record[state] = True
                log.info('[1] Detect constant branch at %s with state %s' % (hex(emulator.getpc()), state))

        if not pcos:
            detect_constant_branch()
            return None

        pco = pcos[-1]
        branches = pco.getBranchConstraints()

        for branch in branches:
            if branch['srcAddr'] != emulator.last_pc:
                detect_constant_branch()
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

    @staticmethod
    def explore_reg(emulator, reg, target):
        """ Get input for target value

        Args:
            emulator: Emulator instance
            reg:      register name
            target:   target value

        Returns:
            answer if exits
        """
        treg = eval('emulator.triton.registers.' + reg)
        reg_id = emulator.triton.getSymbolicRegisterId(treg)
        reg_sym = emulator.triton.getSymbolicExpressionFromId(reg_id)
        reg_ast = reg_sym.getAst()

        ast_ctxt = emulator.triton.getAstContext()
        constraints = list()
        constraints.append(emulator.triton.getPathConstraintsAst())
        bits = EmuConstant.bits[emulator.arch]
        constraints.append(ast_ctxt.equal(reg_ast, ast_ctxt.bv(target, bits)))
        cstr = ast_ctxt.land(constraints)
        model = emulator.triton.getModel(cstr)
        new_input = {}
        for k, v in model.items():
            log.debug(v)
            index = int(v.getName().replace('SymVar_', ''))
            new_input[index] = chr(v.getValue())

        return new_input
    
    def explore(self, seed='A'):
        """ explore the program with seed and generate new seeds
        
        Args:
            seed: initial input of the program

        Return:
            new seeds for new branches
        """
        emulator = self.init_emulator(seed)

        def is_symbolize(_emulator, offset):
            """ Switch for input symbolize """
            return True
        
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

            _emulator.sys_read = True

        def syscall_before(_emulator, *args):
            _emulator.sys_read = False

        emulator.add_callback('symbolize_check', is_symbolize) 
        emulator.add_callback('read_before', read_before)
        emulator.add_callback('read_after', read_after)
        emulator.add_callback('syscall_before', syscall_before)

        result = []
        base_seed = self.get_base(seed)
        path = [self.get_path(base_seed)]
        self.logger.info('base_seed is ' + repr(base_seed))
        self.logger.debug('base_path is ' + repr(path))
        
        try:
            while emulator.running:
                if Fuzzer.is_jmp_inst(emulator.last_inst_type):
                    # if emulator.sys_read:
                    #     """ read operation is important so add it to path """
                    #     path = [hash(tuple(path))]
                    #     emulator.sys_read = False

                    path.append(emulator.getpc())
                    state = hash(tuple(path))
                    if state not in self.solve_record:
                        answer = self.solve_branch(emulator, base_seed, path)
                        if answer:
                            self.solver.set_input(emulator.true_read, emulator.read_count)
                            new_seed = base_seed + self.solver.createInput(answer)
                            self.logger.info('[1] Get new seed %s' % repr(new_seed))
                            self.add_seed(base_seed, new_seed, path)
                            result.append(new_seed)

                        elif base_seed != '':
                            # Since there are some unsolvable branches, I put it back
                            # to new seeds again
                            self.logger.info('[1] Find branch unsolvable %s with state %s' %
                                     (hex(emulator.getpc()), state))
                            self.set_base(seed, '')
                            res = self.explore(seed)
                            result.extend(res)
                            return result

                emulator.process()

        except IllegalPcException:
            log.warn(colored('[1] Find crash at %s with %s' % (hex(emulator.getpc()), repr(seed)), 'red'))
            self.crash_seeds.append(seed)

        except IllegalInstException:
            log.warn(colored('[2] Find crash at %s with %s' % (hex(emulator.getpc()), repr(seed)), 'red'))
            self.crash_seeds.append(seed)

        if emulator.try_read > 0:
            syscall_arg3_reg = EmuConstant.RegisterTable[emulator.arch]['syscall_arg3']
            if emulator.is_register_symbolized(syscall_arg3_reg):
                self.logger.info('find controllable read length')
                current_value = emulator.getreg(syscall_arg3_reg)
                for i in range(10):
                    ans = self.explore_reg(emulator, syscall_arg3_reg, current_value + 2**i)
                    if ans:
                        self.solver.set_input(emulator.true_read, emulator.read_count)
                        new_seed = base_seed + self.solver.createInput(ans)
                        self.logger.info('[4] Get interesting seed %s' % repr(new_seed))
                        self.add_seed(seed, new_seed, path)
                        result.append(new_seed)

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
                    self.add_seed(seed, new_seed, path)
            elif emulator.try_read > 1:
                log.info('[2] add_seed, new seed is %s' % repr(new_seed))
                self.add_seed(seed, new_seed, path)

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
                
        elif seed not in self.tried_seeds:
            log.info(colored('The program finished normally with current seed, no more fuzzing', 'green'))
            self.tried_seeds.append(hash(seed))
        
        return result

    def process_fuzz(self):
        self.load_state()

        if not self.seeds:
            seeds = [('', 0)]
        else:
            seeds = sorted(self.seeds, key=lambda s: s[1])

        start = int(time.time())
        count = 0
        while seeds:
            new_seeds = []
            for _ in range(len(seeds)):
                self.logger.info('current seeds has %d items' % len(seeds))
                if count % 10 == 0:
                    index = random.randint(0, len(seeds))
                else:
                    index = 0
                
                self.logger.info('random seed index is %d' % index)
                seed, level = seeds.pop(0)

                if hash(seed) in self.tried_seeds:
                    self.logger.info(colored('Discarding duplicate seed', 'green'))
                    continue

                count += 1
                self.logger.info('seed count is %d' % count)
                self.logger.info('try seed: %s, level is %d' % (repr(seed), level))
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
            self.logger.debug('seeds ' + repr(seeds))
            self.solver.save_state()
            if self.crash_seeds:
                self.logger.warn(colored(str(self.crash_seeds), "red"))

        self.bridge.put(False)

    def fuzz(self):
        """Start Fuzzing
        
        Since there is a memory leaking problem in Triton, 
        so I fix it with create new fuzzing process continuously.
        """

        if not self.binary:
            return 

        try:
            self.running = True  # can altered at any time
            for i in range(self.circle):  # about 6 hours
                self.process_fuzz()

        except KeyboardInterrupt:
            sys.exit()

    def stop(self):
        self.running = False

    def get_crash(self):
        self.load_state()
        return self.crash_seeds
