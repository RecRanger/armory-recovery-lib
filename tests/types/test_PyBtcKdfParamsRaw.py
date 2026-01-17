from pathlib import Path

import pytest

from armory_lib.types import (
    PyBtcKdfParamsMinimal,
    PyBtcKdfParamsRaw,
    PyBtcWalletRaw,
)

TEST_ROOT_PATH = Path(__file__).parent.parent


@pytest.fixture
def raw_params_example_1() -> PyBtcKdfParamsRaw:
    return PyBtcKdfParamsRaw(
        memory_requirement_raw=b"\x00\x10\x00\x00\x00\x00\x00\x00",
        num_iterations_raw=b"\x00\x20\x00\x00",
        salt=b"xryfjfizwfzeqhugovgqezoyzqhuujab",
        checksum=b"\xff\xff\xff\xff",  # Note: invalid checksum
    )


def test_ex1_from_bytes(raw_params_example_1):
    byte_string = (
        raw_params_example_1.memory_requirement_raw
        + raw_params_example_1.num_iterations_raw
        + raw_params_example_1.salt
        + raw_params_example_1.checksum
    )
    parsed = PyBtcKdfParamsRaw.from_bytes(byte_string)
    assert parsed == raw_params_example_1


def test_ex1_to_hex_dict(raw_params_example_1):
    hex_dict = raw_params_example_1.to_hex_dict()
    assert hex_dict == {
        "memory_requirement_raw": "0010000000000000",
        "num_iterations_raw": "00200000",
        "salt": b"xryfjfizwfzeqhugovgqezoyzqhuujab".hex(),
        "checksum": "ffffffff",
    }


def test_ex1_validate_checksum_failure(raw_params_example_1):
    assert not raw_params_example_1.validate_checksum()  # == False


def test_ex1_to_PyBtcKdfParamsMinimal(raw_params_example_1):
    minimal = raw_params_example_1.to_PyBtcKdfParamsMinimal()
    assert isinstance(minimal, PyBtcKdfParamsMinimal)
    assert minimal.memory_requirement == 4096
    assert minimal.num_iterations == 8192
    assert minimal.salt == b"xryfjfizwfzeqhugovgqezoyzqhuujab"


def test_ex1_to_from_PyBtcKdfParamsMinimal_no_checksum(raw_params_example_1):
    # Raw -> Minimal -> Raw
    assert isinstance(raw_params_example_1, PyBtcKdfParamsRaw)
    minimal = raw_params_example_1.to_PyBtcKdfParamsMinimal()
    assert isinstance(minimal, PyBtcKdfParamsMinimal)

    new_raw = PyBtcKdfParamsRaw.from_PyBtcKdfParamsMinimal(
        minimal, add_checksum=False
    )
    assert isinstance(new_raw, PyBtcKdfParamsRaw)
    assert new_raw.checksum is None
    orig_no_checksum = raw_params_example_1
    orig_no_checksum.checksum = None
    assert new_raw == orig_no_checksum


def test_ex1_to_from_PyBtcKdfParamsMinimal_add_checksum(raw_params_example_1):
    # Raw -> Minimal -> Raw
    assert isinstance(raw_params_example_1, PyBtcKdfParamsRaw)
    minimal = raw_params_example_1.to_PyBtcKdfParamsMinimal()
    assert isinstance(minimal, PyBtcKdfParamsMinimal)

    new_raw = PyBtcKdfParamsRaw.from_PyBtcKdfParamsMinimal(
        minimal, add_checksum=True
    )
    assert isinstance(new_raw, PyBtcKdfParamsRaw)
    assert new_raw.checksum is not None and isinstance(new_raw.checksum, bytes)
    assert new_raw.validate_checksum() is True
    orig_correct_checksum = raw_params_example_1
    orig_correct_checksum.checksum = orig_correct_checksum.calculate_checksum()
    assert new_raw == orig_correct_checksum


# Tests for PyBtcKdfParamsRaw
@pytest.fixture
def raw_params_example_2() -> PyBtcKdfParamsRaw:
    """From tests/test_data/test_wallets/armory_MJUwhWUF_.wallet, encrypted."""

    wallet_bytes = (
        TEST_ROOT_PATH / "test_data/test_wallets/armory_MJUwhWUF_.wallet"
    ).read_bytes()

    wallet_raw = PyBtcWalletRaw.from_bytes(wallet_bytes)

    # just check that the read is good
    file_kdf_params: bytes = wallet_raw.kdf_parameters
    stored_kdf_params: bytes = bytes.fromhex(
        "000080000000000001000000a7671460d65d64a705ae43e1d45d336ae452a7c8b466db54f466a8cc2add8d0b37c15dc7"
    )
    assert file_kdf_params.startswith(stored_kdf_params)

    assert isinstance(wallet_raw.kdf_parameters, bytes)
    assert len(wallet_raw.kdf_parameters) == 256
    return PyBtcKdfParamsRaw.from_bytes(wallet_raw.kdf_parameters)


def test_ex2_from_file_bytes(raw_params_example_2):
    assert isinstance(raw_params_example_2, PyBtcKdfParamsRaw)
    byte_string = (
        raw_params_example_2.memory_requirement_raw
        + raw_params_example_2.num_iterations_raw
        + raw_params_example_2.salt
        + raw_params_example_2.checksum
    )  # pyright: ignore[reportOperatorIssue]
    parsed = PyBtcKdfParamsRaw.from_bytes(byte_string)
    assert parsed == raw_params_example_2


def test_ex2_reading_values(raw_params_example_2):
    assert raw_params_example_2.validate_checksum() is True  # should be good
    assert raw_params_example_2.memory_requirement_raw == bytes.fromhex(
        "0000800000000000"
    )
    assert (
        raw_params_example_2.memory_requirement == (8 * 1024 * 1024) == 8388608
    )  # 8 MiB in UI (= 8388608 bytes)

    # Good example of the little-endian byte order used throughout Armory.
    # The hex value starts with "01" byte, which equals an integer of val=1.
    # Note: The LSB appears first in the byte string. Ignore how humans right
    # numbers.
    assert raw_params_example_2.num_iterations_raw == bytes.fromhex("01000000")
    assert raw_params_example_2.num_iterations == 1

    assert raw_params_example_2.salt == bytes.fromhex(
        "a7671460d65d64a705ae43e1d45d336ae452a7c8b466db54f466a8cc2add8d0b"
    )
    assert raw_params_example_2.checksum == bytes.fromhex("37c15dc7")
    assert (
        raw_params_example_2.calculate_checksum()
        == raw_params_example_2.checksum
    )
