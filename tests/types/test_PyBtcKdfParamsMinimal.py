import pytest
from armory_lib.types import PyBtcKdfParamsMinimal, PyBtcKdfParamsRaw


@pytest.fixture
def minimal_params_example_1():
    return PyBtcKdfParamsMinimal(
        memory_requirement=1024,
        num_iterations=2048,
        salt=b"ctdhtfbtcqupnzydqbyeywhxpgbcgjmb",
    )


def test_to_bytes(minimal_params_example_1):
    expected_bytes = (
        bytes.fromhex("0004000000000000")  # 1024 LE
        + bytes.fromhex("00080000")  # 2048 LE
        + b"ctdhtfbtcqupnzydqbyeywhxpgbcgjmb"  # salt
    )
    assert minimal_params_example_1.to_bytes() == expected_bytes


def test_to_from_PyBtcKdfParamsRaw_no_checksum(minimal_params_example_1):
    # Minimal -> Raw -> Minimal
    assert isinstance(minimal_params_example_1, PyBtcKdfParamsMinimal)
    raw = minimal_params_example_1.to_PyBtcKdfParamsRaw(add_checksum=False)
    assert isinstance(raw, PyBtcKdfParamsRaw)

    new_minimal = PyBtcKdfParamsMinimal.from_PyBtcKdfParamsRaw(raw)
    assert new_minimal == minimal_params_example_1


def test_to_from_PyBtcKdfParamsRaw_add_checksum(minimal_params_example_1):
    # Minimal -> Raw -> Minimal
    assert isinstance(minimal_params_example_1, PyBtcKdfParamsMinimal)
    raw = minimal_params_example_1.to_PyBtcKdfParamsRaw(add_checksum=True)
    assert isinstance(raw, PyBtcKdfParamsRaw)
    assert raw.checksum is not None

    new_minimal = PyBtcKdfParamsMinimal.from_PyBtcKdfParamsRaw(raw)
    assert new_minimal == minimal_params_example_1
