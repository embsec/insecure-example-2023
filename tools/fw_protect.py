#!/usr/bin/env python

# Copyright 2023 The MITRE Corporation. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-13.

"""
Firmware Bundle-and-Protect Tool

"""
import argparse
import struct
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

def encrypt(data, key, nonce):
    print("Encrypting")
    header = b"header" #DO NOT KEEP IN FINAL VERSION

    cipher = AES.new(key, AES.MODE_GCM)
    cipher.update(header)
    cipher.update(nonce)
    ciphertext, tag = cipher.encrypt_and_digest(data)#Encrypts the data


def protect_firmware(infile, outfile, version, message, key, nonce):
    # Load firmware binary from infile
    with open(infile, 'rb') as fp:
        firmware = fp.read()

    # Append null-terminated message to end of firmware
    firmware_and_message = firmware + message.encode() + b'\00'

    # Pack version and size into two little-endian shorts
    metadata = struct.pack('<HH', version, len(firmware))

    # Append firmware and message to metadata
    firmware_blob = metadata + firmware_and_message

    # Write firmware blob to outfile
    with open(outfile, 'wb+') as outfile:
        outfile.write(firmware_blob)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Firmware Update Tool')
    parser.add_argument("--infile", help="Path to the firmware image to protect.", required=True)
    parser.add_argument("--outfile", help="Filename for the output firmware.", required=True)
    parser.add_argument("--version", help="Version number of this firmware.", required=True)
    parser.add_argument("--message", help="Release message for this firmware.", required=True)
    parser.add_argument("--key", help="Encryption key", required=True)
    parser.add_argument("--nonce", help="Nonce used by AES", required=True)
    args = parser.parse_args()

    protect_firmware(infile=args.infile, outfile=args.outfile, version=int(args.version), message=args.message, key=args.key, nonce=args.nonce)
