# Armory Experiments

To re-implement the KDF in Python 3, we needed to generate test cases from
the original C code.

The "experiments" in this folder aren't really meant to be executed, especially
not in installations of this library.

## Development Notes
* The Armory KDF function is not implement anywhere other than the C++ code. 
* To get unit test cases of the KDF function:
    1. Setup an Lubuntu 18 VM
    2. Install python2.
    3. Download the Armory source, and build it (follow their instructions).
    4. Make changes to the source, like adding `cout << ` print lines.
    5. Rebuild.
    6. Run `python2 make_armory_kdf_test_cases.py` to get test cases.
    