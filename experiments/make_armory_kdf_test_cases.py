# make_armory_kdf_test_cases.py
# Python 2 code
# This file is not meant to be used, and was created for debugging
# and testing/exploration purposes only.

import json
import sys

sys.path.insert(0, "<path_to>/armory_0.96.5_source/Armory3")

import CppBlockUtils as u  # pyright: ignore[reportMissingImports]


def print_kdf_sample_single_random(pass_len_bytes, mem):
    kdf = u.KdfRomix()

    if 0:
        extraEntropy = u.SecureBinaryData(0)
        salt_sbin = u.SecureBinaryData().GenerateRandom(32, extraEntropy)
        pass_sbin = u.SecureBinaryData().GenerateRandom(
            pass_len_bytes, extraEntropy
        )

    salt_sbin = u.SecureBinaryData(
        "hwywsissxqbifxmafjlyfgfafqsxsiro"
    )  # 32 bytes
    pass_sbin = u.SecureBinaryData("1235")  # any length I want

    # self.kdf.usePrecomputedKdfParams(mem, niter, salt)
    kdf.usePrecomputedKdfParams(mem, 1, salt_sbin)

    kdf_out = kdf.DeriveKey_OneIter(pass_sbin)

    print(
        "In: mem="
        + str(mem)
        + ", salt="
        + str(salt_sbin.toHexStr())
        + ", pass="
        + str(pass_sbin.toHexStr())
    )
    print("Out: " + str(kdf_out.toHexStr()))
    kdf.printKdfParams()

    data_out = {
        "mem": mem,
        "salt": salt_sbin.toHexStr(),
        "pass": pass_sbin.toHexStr(),
        "pass_len_bytes": pass_len_bytes,
        "niter": 1,
        "out": kdf_out.toHexStr(),
    }
    print(data_out)

    return data_out


def get_kdf_samples():
    print("Start get_kdf_samples")

    output_list = []
    # print_kdf_sample_single("Test data 1", "some salt", 8*1024*1024)
    for pass_len_bytes in [0, 1, 10, 25, 50, 70]:
        data_out = print_kdf_sample_single_random(
            pass_len_bytes, 128
        )  # 8*1024*1024)
        output_list.append(data_out)
        print("\n\n")
        break  # fixed passwd now

    with open("data_out.json", "w") as f:
        json.dump(output_list, f, indent=4)

    print("Done get_kdf_samples")


def main():
    print("Starting main()")

    get_kdf_samples()

    print("Done main()")


if __name__ == "__main__":
    main()
