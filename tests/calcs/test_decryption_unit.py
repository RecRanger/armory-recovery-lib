import unittest
import pytest
from pathlib import Path

from armory_lib.calcs.decryption import (
    _key_derivation_function_romix_one_iter,
    decrypt_aes_cfb,
)

TEST_ROOT_PATH = Path(__file__).parent.parent

kdf_romix_single_iter_test_data = [
    {
        "niter": 1,
        "pass_len_bytes": 0,
        "mem": 8388608,
        "pass": "",
        "salt": "6c4cba900df40f2d5582d22eb2bac28b02dc43741e7ea2d9b1d25fcba9e70e20",  # noqa
        "out": "af0de8d829701dd248633a1ce03638727cf0c6f15f76003846775a098c998392",  # noqa
    },
    {
        "niter": 1,
        "pass_len_bytes": 1,
        "mem": 8388608,
        "pass": "89",
        "salt": "25a39382cae2f45f4c06dc9943d672a3b99fd4c38171916928ee8b3f1194acbe",  # noqa
        "out": "4da348684336b1f5b50daa3f9e2c743a2d2e2ec33ec314813bba7b76a429c81f",  # noqa
    },
    {
        "niter": 1,
        "pass_len_bytes": 10,
        "mem": 8388608,
        "pass": "0b14e6c1188997351957",
        "salt": "be3adbc61f9513bcfd1fd16c1ebd937b4bbb8743bd4820992ed911066d3701c4",  # noqa
        "out": "64f291c7c04a166e23c5b84984cc792f8d8114e115f9df4a038f14e4ea7b5820",  # noqa
    },
    {
        "niter": 1,
        "pass_len_bytes": 25,
        "mem": 8388608,
        "pass": "ed7d8cfa5067d74c4236a68077a712b62beccf60b4afd6be43",
        "salt": "13d884a6bac7773a8c39fa8ea18b37b8e6f3d15890423b97cd99e9909d681d47",  # noqa
        "out": "fc8dac51f7b5ac07f7ebbf1dd07ab2527010e4b3bd49a0221cf3bac81a91aaa8",  # noqa
    },
    {
        "niter": 1,
        "pass_len_bytes": 50,
        "mem": 8388608,
        "pass": "7ffcdde07e8e8544f3bf41b744102adc9fe41023572c69f2ee9aaca4f67bbe1ca6d5f852c71f4c934fe16492f61b753d4569",  # noqa
        "salt": "ed8a2ba1998b88372dcc04b51cd774af9c067cfdb756ee21cca40074c7760494",  # noqa
        "out": "57be1d8c510554a3bcca6224dc103da5ad5b93fb96ddbc52f9d85803c1cf7d8f",  # noqa
    },
    {
        "niter": 1,
        "pass_len_bytes": 70,
        "mem": 8388608,
        "pass": "8953df9e852516adf84cdcc1f323a87540e9a62dd35fbe89ffe0c541188c8ed22f76f531c05a8b1c3153b1fc0f2d40946c1f99903ae5f3ebe65cee8e208236e0d5982a5a251a",  # noqa
        "salt": "02c7a2641ed8f517f80eee5fcc9cdf33cac39ff8856c876d05a7c01b200e2567",  # noqa
        "out": "09a14ff19409a970634cb4835d73117d2d9a2d2f0407abc2814918dce4213a95",  # noqa
    },
    {
        "niter": 1,
        "pass_len_bytes": 0,
        "mem": 128,
        "pass": "31323335",
        "salt": "68777977736973737871626966786d61666a6c7966676661667173787369726f",  # noqa
        "out": "573b1f633158904395736403563aaaf4a0c766478d75eb453ae392a50f350da2",  # noqa
    },
]


def test__key_derivation_function_romix_one_iter_test1():
    test_data: dict = {
        "pass": "89",
        "pass_len_bytes": 1,
        "niter": 1,
        "mem": 8388608,
        "salt": "25a39382cae2f45f4c06dc9943d672a3b99fd4c38171916928ee8b3f1194acbe",  # noqa
        "out": "4da348684336b1f5b50daa3f9e2c743a2d2e2ec33ec314813bba7b76a429c81f",  # noqa
    }
    passphrase = bytes.fromhex(test_data["pass"])
    salt = bytes.fromhex(test_data["salt"])
    memory_requirement = test_data["mem"]
    assert test_data["niter"] == 1
    expected_output = bytes.fromhex(test_data["out"])

    kdf_output_key = _key_derivation_function_romix_one_iter(
        passphrase=passphrase,
        salt=salt,
        memory_requirement_bytes=memory_requirement,
    )

    assert kdf_output_key.hex() == expected_output.hex()


def test__key_derivation_function_romix_one_iter_test2():
    test_data: dict = {
        "niter": 1,
        "pass_len_bytes": 0,
        "mem": 128,  # very tiny, easier debug
        "pass": "31323335",  # b"1235"
        "salt": "68777977736973737871626966786d61666a6c7966676661667173787369726f",  # noqa
        "out": "573b1f633158904395736403563aaaf4a0c766478d75eb453ae392a50f350da2",  # noqa
    }
    passphrase = bytes.fromhex(test_data["pass"])
    salt = bytes.fromhex(test_data["salt"])
    memory_requirement = test_data["mem"]
    assert test_data["niter"] == 1
    expected_output = bytes.fromhex(test_data["out"])

    kdf_output_key = _key_derivation_function_romix_one_iter(
        passphrase=passphrase,
        salt=salt,
        memory_requirement_bytes=memory_requirement,
    )

    assert kdf_output_key.hex() == expected_output.hex()


@pytest.mark.parametrize("test_data", kdf_romix_single_iter_test_data)
def test__key_derivation_function_romix_one_iter_all(test_data: dict):
    assert set(test_data.keys()) == {
        "niter",
        "pass_len_bytes",
        "mem",
        "pass",
        "salt",
        "out",
    }
    passphrase = bytes.fromhex(test_data["pass"])
    salt = bytes.fromhex(test_data["salt"])
    memory_requirement = test_data["mem"]
    assert test_data["niter"] == 1
    expected_output = bytes.fromhex(test_data["out"])

    kdf_output_key = _key_derivation_function_romix_one_iter(
        passphrase=passphrase,
        salt=salt,
        memory_requirement_bytes=memory_requirement,
    )

    assert kdf_output_key.hex() == expected_output.hex()


class TestDecryptAesCfb(unittest.TestCase):
    def test_decrypt_aes_cfb_test1(self):
        key = bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000000000"
        )
        iv = bytes.fromhex("80000000000000000000000000000000")
        cipher_text = bytes.fromhex("ddc6bf790c15760d8d9aeb6f9a75fd4e")
        expected_plaintext = bytes.fromhex("00000000000000000000000000000000")
        decrypted_text = decrypt_aes_cfb(cipher_text, key, iv)
        assert decrypted_text == expected_plaintext

    def test_decrypt_aes_cfb_test2(self):
        key = bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000000000"
        )
        iv = bytes.fromhex("014730f80ac625fe84f026c60bfd547d")
        cipher_text = bytes.fromhex("5c9d844ed46f9885085e5d6a4f94c7d7")
        expected_plaintext = bytes.fromhex("00000000000000000000000000000000")
        decrypted_text = decrypt_aes_cfb(cipher_text, key, iv)
        assert decrypted_text == expected_plaintext

    def test_decrypt_aes_cfb_test3(self):
        key = bytes.fromhex(
            "ffffffffffff0000000000000000000000000000000000000000000000000000"
        )
        iv = bytes.fromhex("00000000000000000000000000000000")
        cipher_text = bytes.fromhex("225f068c28476605735ad671bb8f39f3")
        expected_plaintext = bytes.fromhex("00000000000000000000000000000000")
        decrypted_text = decrypt_aes_cfb(cipher_text, key, iv)
        assert decrypted_text == expected_plaintext
