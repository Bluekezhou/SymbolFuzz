from triton import ARCH


class EmuConstant:
    def __init__(self):
        pass

    MODE_ELF = 0x1
    MODE_CODE = 0x2

    UNKNOWN_ARCH = -1

    SUPPORT_ARCH = {
        ARCH.X86: "i386",
        ARCH.X86_64: "amd64"
    }

    RegisterTable = {
        ARCH.X86: {
            "pc": "eip"
        },

        ARCH.X86_64: {
            "pc": "rip"
        }
    }

    RegisterList = {
        ARCH.X86: ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp"],
        ARCH.X86_64: ["rax", "rbx", "rcx", "rdx", "rdi", "rsi", "r8", "r9",
                      "r10", "r11", "r12", "r13", "r14", "r15", "rsp", "rbp"]
    }
