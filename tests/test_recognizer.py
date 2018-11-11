from symbolfuzz import Recognizer
import os


binary_dir = '../example/binary/'


def test_recognizer():
    binary = os.path.join(binary_dir, "atoi")
    recognizer = Recognizer(binary)
    assert recognizer.is_static() is True
    print("is_static() check passed")
    assert recognizer.is_pie() is False
    print("is_pie() check passed")


if __name__ == "__main__":
    test_recognizer()
