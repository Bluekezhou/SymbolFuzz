#!/usr/bin/env python
# coding=utf-8

from fuzzer import *
import threading


class SymbolFuzzer:
    
    def __init__(self, binary, logv=None):
        bin_dir = os.path.abspath(os.path.dirname(binary))
        bin_name = os.path.basename(binary)
        self.fuzz_dir = os.path.join(bin_dir, 'symbol_fuzz')
        if not os.path.exists(self.fuzz_dir):
            os.mkdir(self.fuzz_dir)

        tmp_bin = os.path.join(self.fuzz_dir, bin_name)
        if not os.path.exists(tmp_bin):
            shutil.copy(binary, tmp_bin)

        self.binary = tmp_bin
        self.fuzzer = Fuzzer(tmp_bin, logv)

        self.crash_files = []

    def fuzz(self):
        t = threading.Thread(target=self.fuzzer.fuzz) 
        t.start()

    def stop(self):
        self.fuzzer.stop()

    def get_crash(self):
        crashes = self.fuzzer.get_crash()
        for crash in crashes:
            crash_file = os.path.join(self.fuzz_dir, md5(crash, is_file=False))
            if crash_file not in self.crash_files:
                if not os.path.exists(crash_file):
                    f = open(crash_file, 'wb').write(crash)
                self.crash_files.append(crash_file)
            
        return self.crash_files
