from dataclasses import dataclass
from typing import Optional

# Source: @latest: armoryengine/PyBtcWallet.py/serializeKdfParams(...)


@dataclass
class PyBtcKdfParamsMinimal:
    memory_requirement: int  # UInt64
    num_iterations: int  # UInt32
    salt: bytes  # 32 bytes

    def to_bytes(self, add_checksum: bool = False) -> bytes:
        val = b"".join(
            [
                self.memory_requirement.to_bytes(8, byteorder="little"),
                self.num_iterations.to_bytes(4, byteorder="little"),
                self.salt,
            ]
        )
        if add_checksum:
            from armory_lib.calcs import compute_checksum

            val += compute_checksum(val)

        if add_checksum:
            assert len(val) == 48
        else:
            assert len(val) == 44
        return val

    @classmethod
    def from_bytes(cls, byte_string: bytes) -> "PyBtcKdfParamsMinimal":
        return PyBtcKdfParamsRaw.from_bytes(
            byte_string
        ).to_PyBtcKdfParamsMinimal()

    def to_PyBtcKdfParamsRaw(
        self, add_checksum: bool = False
    ) -> "PyBtcKdfParamsRaw":
        return PyBtcKdfParamsRaw.from_bytes(
            self.to_bytes(add_checksum=add_checksum)
        )

    @staticmethod
    def from_PyBtcKdfParamsRaw(
        kdf_params_raw: "PyBtcKdfParamsRaw",
    ) -> "PyBtcKdfParamsMinimal":
        assert isinstance(kdf_params_raw, PyBtcKdfParamsRaw)
        return kdf_params_raw.to_PyBtcKdfParamsMinimal()


@dataclass
class PyBtcKdfParamsRaw:
    memory_requirement_raw: bytes  # 8 bytes (UInt64)
    num_iterations_raw: bytes  # 4 bytes (UInt32)
    salt: bytes  # 32 bytes
    checksum: Optional[bytes]  # 4 bytes; optional
    # the rest of the bytes (to 256 bytes) are all zeros

    @property
    def memory_requirement(self) -> int:
        return int.from_bytes(self.memory_requirement_raw, byteorder="little")

    @property
    def num_iterations(self) -> int:
        return int.from_bytes(self.num_iterations_raw, byteorder="little")

    @classmethod
    def from_bytes(cls, byte_string: bytes) -> "PyBtcKdfParamsRaw":
        """Reads 44+ bytes and returns a PyBtcKdfParamsRaw object."""
        assert isinstance(byte_string, bytes), "Byte string must be type bytes"
        assert len(byte_string) >= 44, (
            "Byte string must be at least 44 bytes long"
        )

        memory_requirement_raw = byte_string[0:8]
        num_iterations_raw = byte_string[8:12]
        salt = byte_string[12:44]

        if len(byte_string) >= 48:
            checksum = byte_string[44:48]
        else:
            checksum = None

        return cls(
            memory_requirement_raw=memory_requirement_raw,
            num_iterations_raw=num_iterations_raw,
            salt=salt,
            checksum=checksum,
        )

    def to_hex_dict(self) -> dict[str, str | None]:
        return {
            "memory_requirement_raw": self.memory_requirement_raw.hex(),
            "num_iterations_raw": self.num_iterations_raw.hex(),
            "salt": self.salt.hex(),
            "checksum": (
                self.checksum.hex() if self.checksum is not None else None
            ),
        }

    def to_dict(self) -> dict[str, str | int | None]:
        return {
            "memory_requirement_raw": self.memory_requirement_raw.hex(),
            "num_iterations_raw": self.num_iterations_raw.hex(),
            "memory_requirement": self.memory_requirement,
            "num_iterations": self.num_iterations,
            "salt": self.salt.hex(),
            "checksum": (
                self.checksum.hex() if self.checksum is not None else None
            ),
        }

    def calculate_checksum(self) -> bytes:
        from armory_lib.calcs import compute_checksum

        return compute_checksum(
            self.memory_requirement_raw + self.num_iterations_raw + self.salt
        )

    def validate_checksum(self) -> bool | None:
        """Validate the checksum if it is present.
        Return True if valid, False if invalid, and None if checksum is absent.
        """
        if self.checksum is None:
            return None

        return self.checksum == self.calculate_checksum()

    def to_PyBtcKdfParamsMinimal(self) -> "PyBtcKdfParamsMinimal":
        return PyBtcKdfParamsMinimal(
            memory_requirement=self.memory_requirement,
            num_iterations=self.num_iterations,
            salt=self.salt,
        )

    @staticmethod
    def from_PyBtcKdfParamsMinimal(
        kdf_params_minimal: PyBtcKdfParamsMinimal,
        add_checksum: bool = False,
    ) -> "PyBtcKdfParamsRaw":
        assert isinstance(kdf_params_minimal, PyBtcKdfParamsMinimal)
        return PyBtcKdfParamsRaw.from_bytes(
            kdf_params_minimal.to_bytes(add_checksum=add_checksum)
        )
