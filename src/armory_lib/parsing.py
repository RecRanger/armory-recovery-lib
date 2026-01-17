from typing import TypeVar, overload


@overload
def find_nth_occurrence(haystack: bytes, needle: bytes, n: int) -> int: ...


@overload
def find_nth_occurrence(haystack: str, needle: str, n: int) -> int: ...


def find_nth_occurrence(
    haystack: str | bytes, needle: str | bytes, n: int
) -> int:
    """Returns the index of the nth occurrence of a substring ("needle").
    n = 1 is the minimum.
    """
    assert (isinstance(haystack, bytes) and isinstance(needle, bytes)) or (
        isinstance(haystack, str) and isinstance(needle, str)
    ), "string and sub_string must be the same type"
    assert n > 0, "n must be greater than 0. n=1 is the first occurrence."

    start_index = haystack.find(needle)  # pyright: ignore[reportArgumentType]
    while start_index >= 0 and n > 1:
        start_index = haystack.find(needle, start_index + 1)  # pyright: ignore[reportArgumentType]
        n -= 1
    return start_index


T = TypeVar("T", bytes, str)


def fill_to_length(start: T, fill_val: T, length: int) -> T:
    """Returns a string that is the original string with the fill_val added to
    the end until the string is length characters long.
    """
    assert (isinstance(start, bytes) and isinstance(fill_val, bytes)) or (
        isinstance(start, str) and isinstance(fill_val, str)
    ), "start and fill_val must be the same type"
    assert length >= len(start), (
        "length must be greater than or equal to the length of start"
    )
    assert len(fill_val) == 1, "fill_val must be a single character or byte"

    return start + fill_val * (length - len(start))


def normalize_csv_hex_str(csv_hex_str: str) -> str:
    """Takes a hex str like "0, 83, e9, f1, 63" and returns '0083e9f1633'.
    Each hex str is expected to be a single byte, like '83' or '9'.
    They are all zero-padded to 2 characters.
    """
    return "".join(
        [hex_str.strip().zfill(2) for hex_str in csv_hex_str.split(",")]
    )
