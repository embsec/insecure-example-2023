#!/usr/bin/env python

# Copyright 2023 The MITRE Corporation and team BRUGH!!. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-13.

"""
Firmware Bundle-and-Protect Tool

"""
import argparse
import struct
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from  pwn import *

def encrypt(data, key, header):

    cipher = AES.new(key, AES.MODE_GCM)#instantiates an AES object
    cipher.update(header)#Updates it to use common header (also on Stellaris)
    ciphertext, tag = cipher.encrypt_and_digest(pad(data, 16))#Encrypts the data
    return(ciphertext + cipher.nonce + tag)#Returns encrypted data




def protect_firmware(infile, outfile, version, message, secret):
    # Load firmware binary from infile
    with open(infile, 'rb') as fp:
        firmware = fp.read()
    #load secret key (256 bits) and header
    key = b""
    header = b""
    #Reads secret_build_output.txt and parses it into the key (32 bytes) and the header (16 bytes)
    with open (secret, "rb") as fp:
        key = fp.readline()
        key = key[0 : len(key) - 1]
        header = fp.readline()


    encrypted = b""

    i = 0
    for i in range (0, len(firmware), 15):#Breaks firmware binary into chunks and runs those chunks through encrypt(). Uses keys from secret_build_output.txt.
        encrypted += encrypt((p8(2) + firmware[i : i + 15]), key, header)
    if (len(firmware) // 15 != 0):
        encrypted += encrypt((p8(2) + firmware[i : len(firmware)]), key, header)
    print(encrypted)

    # Append null-terminated message to end of firmware
    firmware_and_message = firmware + encrypt(message.encode(), key, header)

    # Pack message type as a uint8, and version, firmware length and message length as uint16s and encrypts them
    beginFrame = encrypt(p8(1) + p16(version) + p16(len(firmware)) + p16(len(message)), key, header)
    # Append firmware and message to metadata
    firmware_blob = beginFrame + firmware_and_message

    # Write encrypted firmware blob to outfile
    with open(outfile, 'wb+') as outfile:
        outfile.write(firmware_blob)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Firmware Update Tool')
    parser.add_argument("--infile", help="Path to the firmware image to protect.", required=True)
    parser.add_argument("--outfile", help="Filename for the output firmware.", required=True)
    parser.add_argument("--version", help="Version number of this firmware.", required=True)
    parser.add_argument("--message", help="Release message for this firmware.", required=True)
    parser.add_argument("--secret", help="path to secret_build_output.txt", required=True)
    args = parser.parse_args()

    protect_firmware(infile=args.infile, outfile=args.outfile, version=int(args.version), message=args.message, secret=args.secret)#Calls the firmware protect method
