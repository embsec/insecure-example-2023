#!/usr/bin/env python

# Copyright 2023 The MITRE Corporation. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-13.

import argparse
import pathlib
import subprocess
import os
from util import *


def emulate(binary_path, debug=False):
    cmd = ["qemu-system-arm", "-M", "lm3s6965evb", "-nographic", "-kernel", binary_path]

    if debug:
        cmd.extend(["-s", "-S"])

    uart_paths = ["/embsec/UART0", "/embsec/UART1", "/embsec/UART2"]
    for i in range(3):
        cmd.extend(["-serial", f"unix:{uart_paths[i]},server"])
    
    # Try to kill and delete leftover stuff before starting qemu
    os.system("pkill qemu")
    try:
        os.system(f"rm -rf {UART0_PATH}")
    except:
        pass

    try:
        os.system(f"rm -rf {UART1_PATH}")
    except:
        pass

    try:
        os.system(f"rm -rf {UART2_PATH}")
    except:
        pass
    os.system("rm -rf /flash/*")
    
    subprocess.Popen(cmd)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Stellaris Emulator")
    parser.add_argument("--boot-path", help="Path to the the bootloader binary.", default=None)
    parser.add_argument("--debug", help="Start GDB server and break on first instruction", action="store_true")
    args = parser.parse_args()
    if args.boot_path is None:
        binary_path = (pathlib.Path(__file__).parent / ".." / "bootloader" / "gcc" / "main.axf")
    else:
        binary_path = pathlib.Path(args.boot_path)

    emulate(binary_path.resolve(), debug=args.debug)
