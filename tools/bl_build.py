#!/usr/bin/env python

# Copyright 2023 The MITRE Corporation. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-13.

"""
Bootloader Build Tool

This tool is responsible for building the bootloader from source and copying
the build outputs into the host tools directory for programming.
"""
import argparse
import hashlib #crying
import os
import pathlib
import shutil
import subprocess
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from binascii import unhexlify
from util import print_hex
from pwn import *

REPO_ROOT = pathlib.Path(__file__).parent.parent.absolute()
BOOTLOADER_DIR = os.path.join(REPO_ROOT, "bootloader")

# Generates random byte strings
# Takes number of bytes to be generated
# Returns generated bytes
def generate(num):
    key = os.urandom(num)
    return key

# Converts binary string to hex array
# Takes binary string
# Returns byte string
# (Def not warren's stolen code, we'd never do that)
def arrayize(binary_string):
    return '{' + ', '.join([hex(char) for char in binary_string]) + '}'

# Copies initial firmware binary to the bootloader
def copy_initial_firmware(binary_path: str):
    os.chdir(os.path.join(REPO_ROOT, "tools"))
    shutil.copy(binary_path, os.path.join(BOOTLOADER_DIR, "src/firmware.bin"))

# Builds the bootloader from source
def make_bootloader() -> bool:
    os.chdir(BOOTLOADER_DIR)

    subprocess.call("make clean", shell=True)
    status = subprocess.call("make")

    # Return True if make returned 0, otherwise return False.
    return status == 0

# Runs program
if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Bootloader Build Tool")
    parser.add_argument(
        "--initial-firmware",
        help="Path to the the firmware binary.",
        default=os.path.join(REPO_ROOT, "firmware/gcc/main.bin"),
    )
    args = parser.parse_args()
    firmware_path = os.path.abspath(pathlib.Path(args.initial_firmware))

    if not os.path.isfile(firmware_path):
        raise FileNotFoundError(
            f'ERROR: {firmware_path} does not exist or is not a file. You may have to call "make" in the firmware directory.'
        )

    # Generates AES key and header/aad
    aes_key = generate(16)
    header = generate(16)

    # Writes AES key and header to Python secret file in binary format
    with open("../bootloader/secret_build_output.txt", "wb") as file:
        file.write(aes_key + b"\n")
        file.write(header)
        
    # Writes AES key and header to C header file
    with open("../bootloader/keys.h", "w") as file:
        file.write('#ifndef KEYS_H' + "\n")
        file.write('#define KEY (const uint8_t[]) ' + arrayize(aes_key) + "\n")
        file.write('#define HEADER (const uint8_t[]) ' + arrayize(header) + "\n")
        file.write('#endif')
    
    # Copies firmware and builds bootloader
    copy_initial_firmware(firmware_path)
    make_bootloader()


