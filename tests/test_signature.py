from symbolfuzz import Signature


def test_signature():
    libc_sign = Signature("../src/symbolfuzz/signature/signature")
    binary_sign = Signature("../example/binary/atoi")
    sign = binary_sign.get_sign(binary_sign.functions['malloc'])
    print libc_sign.match_sign(sign)
    libc_sign.save_sign()


if __name__ == '__main__':
    test_signature()
