from symbolfuzz import Signature


def test_signature():
    # binary_sign = Signature("../example/binary/atoi")
    # sign = binary_sign.get_sign(0x804d8b0)
    # print sign

    # libc_sign = Signature("/lib/i386-linux-gnu/libc.so.6")
    # libc_sign = Signature("../src/symbolfuzz/signature/signature")
    libc_sign = Signature("../src/symbolfuzz/signature/signature_kali")
    # sign2 = libc_sign.get_sign(libc_sign.functions['atoi'])
    # print sign2

    binary_sign = Signature("../example/binary/atoi")
    sign = binary_sign.get_sign(binary_sign.functions['malloc'])
    # print sign

    print libc_sign.match_sign(sign)
    libc_sign.save_sign()
    stop = 1



if __name__ == '__main__':
    test_signature()
