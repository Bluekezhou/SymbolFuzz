import logging
import hashlib
import sys
from triton import ARCH


class LogUtil:
    __logger = None
    __log_handler = None

    @classmethod
    def init_log(cls, logfile=None, logger_name=None):
        if logfile is sys.stdout or not logfile:
            cls.__logger = logging.getLogger("stdout")
            cls.__log_handler = logging.StreamHandler(sys.stdout)
        elif logfile and not logger_name:
            cls.__logger = logging.getLogger(logfile)
            cls.__log_handler = logging.StreamHandler(open(logfile, "a"))
        else:
            cls.__logger = logging.getLogger(logger_name)
            cls.__log_handler = logging.StreamHandler(open(logfile, "a"))

        cls.__logger.setLevel(logging.DEBUG)

        format_str = "[%(asctime)s file=%(filename)s line=%(lineno)d %(levelname)s] %(message)s"
        formatter = logging.Formatter(format_str)
        cls.__log_handler.setFormatter(formatter)
        cls.__logger.addHandler(cls.__log_handler)

    @classmethod
    def close(cls):
        if cls.__log_handler:
            cls.__log_handler.close()

    @classmethod
    def get_logger(cls):
        if not cls.__logger:
            cls.init_log(sys.stdout)
        return cls.__logger


def title(msg, obj=None, length=70, fill='='):
    """ Print debug information """
    msg = ' ' + msg + ' '
    msg = fill * ((length-len(msg))/2) + msg
    print msg.ljust(length, fill)
    if obj is not None:
        print obj


def memorize(f):
    cached = {}

    def helper(*args, **kargs):

        key = (args, tuple(kargs.values()))
        if key not in cached:
            cached[key] = f(*args, **kargs)
        return cached[key]

    return helper


@memorize
def md5(stream, is_file=True):
    """ Generate md5 for file or string """
    md5 = hashlib.md5()
    if is_file:
        with open(stream) as f:
            data = f.read()
        md5.update(data)
    else:
        md5.update(stream)

    return md5.hexdigest()


def str2int(data):
    """Try to transform a string to an integer

    Args:
        data: a string representing a number which might be hex format
                or metric format

    Returns:
        an integer
    """
    try:
        return int(data, 16)
    except ValueError:
        return int(data, 10)


def get_arch(elf):
    """translate ELF.get_machine_arch() to triton.ARCH

    Args:
        elf: instance of ELF class

    Returns:
        an integer, supported triton ARCH
    """
    if elf.get_machine_arch() in ['x86', 'i386']:
        return ARCH.X86
    elif elf.get_machine_arch() in ['x86_64', 'amd64']:
        return ARCH.X86_64


def connect_pycharm(ip, port=4444):
    """ Just for local debug """
    try:
        import sys
        sys.path.append('/data/pydev')
        import pydevd
        pydevd.settrace(ip, port=port, stdoutToServer=True, stderrToServer=True)
    except Exception as e:
        print(e)
        print("failed to load pycharm debugger")
