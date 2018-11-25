from symbolfuzz import Signature


def test_signature():
    libc_sign = Signature("../src/symbolfuzz/utils/signature/signature")
    # printf_sign = libc_sign.get_sign(libc_sign.functions['printf'])
    binary_sign = Signature("../example/binary/atoi")
    sign = binary_sign.get_sign(binary_sign.functions['malloc'])
    print libc_sign.match_sign(sign)
    libc_sign.save_sign()


if __name__ == '__main__':
    test_signature()
