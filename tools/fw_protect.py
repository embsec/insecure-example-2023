#!/usr/bin/env python

# Copyright 2023 The MITRE Corporation and team BRUGH!!. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-13.

"""
Firmware Bundle-and-Protect Tool

"""
import argparse
import random
from Crypto.Cipher import AES
from pwn import *

# Pads the input data using random characters
# Takes the data to be padded, and the completed size
# Returns padded data
def randPad(data, size):
    # Calculates the number of bytes of padding
    toPad = size - len(data) % size

    randData = b""
    # Generates padding
    for i in range(toPad):
        randData += p8(random.randint(0, 255), endian = "little")

    return data + randData

# Encrypts the input data using GCM
# Takes the data to be encrypted, the key,
# and additional authenticated data
# Returns the encypted data
def encrypt(data, key, header):
    # Set up the AES object with the key, mode, and header/aad
    cipher = AES.new(key, AES.MODE_GCM)
    cipher.update(header)

    # Encrypts the data
    ciphertext, tag = cipher.encrypt_and_digest(data)
    
    # Returns encrypted data, tag, and nonce/IV
    return(ciphertext + tag + cipher.nonce)

# Packages the firmware
# Takes firmware location, output location,
# version, release message, and keys location
def protect_firmware(infile, outfile, version, message, secret):
    # Load firmware binary from infile
    with open(infile, 'rb') as fp:
        firmware = fp.read()

    # Instantiate and read the key (0x10) and header/aad (0x10)
    key = b""
    header = b""
    with open (secret, "rb") as fp:
        key = fp.read(16);
        fp.read(1); # Gets rid of new line between key and header
        header = fp.read(16);

    # Encrypt the firmware
    fwEncrypt = b""
    i = 0
    # Breaks into chunks
    for i in range (0, len(firmware), 15):
        # Check if the firmware fills a full 0xF chunk
        if ((len(firmware) - i) // 15 != 0):
            temp = p8(2, endian = "little") + firmware[i : i + 15] # Message type + firmware
            fwEncrypt += temp
    # If the last chunk is not a 0xF chunk, pads and encrypts
    if (len(firmware) % 15 != 0):
        temp = randPad((p8(2, endian = "little") + firmware[i : len(firmware)]), 16) # Message type + firmware + padding
        fwEncrypt += temp

    # Encode and encrypt the release message
    messageBin = message.encode()
    messageBin += b"\00"
    rmEncrypt = b""
    # Breaks into chunks
    for i in range (0, len(messageBin), 15):
        # Check if message fills a full 0xF chunk
        if ((len(messageBin) - i) // 15 != 0):
            temp = p8(2, endian = "little") + messageBin[i : i + 15] # Type and RM
            rmEncrypt += temp

    # If the last chunk is not a 0xF chunk, pads and encrypts
    if (len(messageBin) % 15 != 0):
        temp = randPad((p8(2, endian = "little") + messageBin[i : len(firmware)]), 16) # Type, RM, null byte, and padding
        rmEncrypt += temp

    # Create START frame
    # Temp is the type + version num + firmware len + RM len + padding
    temp = randPad(p8(1, endian = "little") + p16(version, endian = "little") + p16(len(firmware), endian = "little") + p16(len(messageBin), endian = "little"), 16)
    begin = temp

    # Create END frame
    # Temp is the type + padding
    temp = randPad(p8(3, endian = "little"), 16)
    end = temp

    # For debugging?
    # print(begin)
    
    # Smush the START frame, encrypted firmware and RM, and END frame together
    firmware_blob = begin + fwEncrypt + rmEncrypt + end
    print(firmware_blob)
    # Write encrypted firmware blob to outfile
    with open(outfile, 'wb+') as outfile:
        outfile.write(firmware_blob)
    
# Runs the program
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Firmware Update Tool')
    parser.add_argument("--infile", help="Path to the firmware image to protect.", required=True)
    parser.add_argument("--outfile", help="Filename for the output firmware.", required=True)
    parser.add_argument("--version", help="Version number of this firmware.", required=True)
    parser.add_argument("--message", help="Release message for this firmware.", required=True)
    parser.add_argument("--secret", help="path to secret_build_output.txt", required=True)
    args = parser.parse_args()

    protect_firmware(infile=args.infile, outfile=args.outfile, version=int(args.version), message=args.message, secret=args.secret)#Calls the firmware protect method
    # EXAMPLE COMMAND TO RUN THIS CODE
    # python3 ./fw_protect.py --infile ../firmware/gcc/main.bin --outfile ../firmware/gcc/protected.bin --version 0 --message lolz --secret ../bootloader/secret_build_output.txt