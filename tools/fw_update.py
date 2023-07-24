#!/usr/bin/env python

# Copyright 2023 The MITRE Corporation. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-13.

"""
Firmware Updater Tool

A frame consists of two sections:
1. Two bytes for the length of the data section
2. A data section of length defined in the length section

[ 0x02 ]  [ variable ]
--------------------
| Length | Data... |
--------------------

In our case, the data is from one line of the Intel Hex formated .hex file

We write a frame to the bootloader, then wait for it to respond with an
OK message so we can write the next frame. The OK message in this case is
just a zero
"""

import argparse
import struct
import time
import socket

from util import *

RESP_OK = b"\x00"
FRAME_SIZE = 256


def send_metadata(ser, metadata, debug=False):
    version, size = struct.unpack_from("<HH", metadata)
    print(f"Version: {version}\nSize: {size} bytes\n")

    # Handshake for update
    ser.write(b"U")

    print("Waiting for bootloader to enter update mode...")
    while ser.read(1).decode() != "U":
        print("got a byte")
        pass

    # Send size and version to bootloader.
    if debug:
        print(metadata)

    ser.write(metadata)

    # Wait for an OK from the bootloader.
    resp = ser.read(1)
    if resp != RESP_OK:
        raise RuntimeError("ERROR: Bootloader responded with {}".format(repr(resp)))


def send_frame(ser, frame, debug=False):
    ser.write(frame)  # Write the frame...

    if debug:
        print_hex(frame)

    resp = ser.read(1)  # Wait for an OK from the bootloader

    time.sleep(0.1)

    if resp != RESP_OK:
        raise RuntimeError("ERROR: Bootloader responded with {}".format(repr(resp)))

    if debug:
        print("Resp: {}".format(ord(resp)))


def update(ser, infile, debug):
    # Open serial port. Set baudrate to 115200. Set timeout to 2 seconds.
    with open(infile, "rb") as fp:
        firmware_blob = fp.read()

    metadata = firmware_blob[:4]
    firmware = firmware_blob[4:]

    send_metadata(ser, metadata, debug=debug)

    for idx, frame_start in enumerate(range(0, len(firmware), FRAME_SIZE)):
        data = firmware[frame_start : frame_start + FRAME_SIZE]

        # Get length of data.
        length = len(data)
        frame_fmt = ">H{}s".format(length)

        # Construct frame.
        frame = struct.pack(frame_fmt, length, data)

        send_frame(ser, frame, debug=debug)
        print(f"Wrote frame {idx} ({len(frame)} bytes)")

    print("Done writing firmware.")

    # Send a zero length payload to tell the bootlader to finish writing it's page.
    ser.write(struct.pack(">H", 0x0000))
    resp = ser.read(1)  # Wait for an OK from the bootloader
    if resp != RESP_OK:
        raise RuntimeError("ERROR: Bootloader responded to zero length frame with {}".format(repr(resp)))
    print(f"Wrote zero length frame (2 bytes)")

    return ser


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Firmware Update Tool")

    parser.add_argument("--port", help="Does nothing, included to adhere to command examples in rule doc", required=False)
    parser.add_argument("--firmware", help="Path to firmware image to load.", required=False)
    parser.add_argument("--debug", help="Enable debugging messages.", action="store_true")
    args = parser.parse_args()

    uart0_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    uart0_sock.connect(UART0_PATH)

    time.sleep(0.2)  # QEMU takes a moment to open the next socket

    uart1_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    uart1_sock.connect(UART1_PATH)
    uart1 = DomainSocketSerial(uart1_sock)

    time.sleep(0.2)

    uart2_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    uart2_sock.connect(UART2_PATH)

    # Close unused UARTs (if we leave these open it will hang)
    uart2_sock.close()
    uart0_sock.close()

    update(ser=uart1, infile=args.firmware, debug=args.debug)

    uart1_sock.close()
