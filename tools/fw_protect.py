#!/usr/bin/env python

# Copyright 2023 The MITRE Corporation and team BRUGH!!. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-13.

"""
Firmware Bundle-and-Protect Tool

"""
import argparse
import struct
import random
from Crypto.Cipher import AES
from  pwn import *

def randPad(data, size):#Pads using random data cus we're too cool for pkcs7
    toPad = len(data) % size
    randData = b""
    for i in range(toPad):
        randData += p8(random.randint(0, 255), endian = "big")
    
    return data + randData

def encrypt(data, key, header):

    cipher = AES.new(key, AES.MODE_GCM)#instantiates an AES object
    cipher.update(header)#Updates it to use common header (also on Stellaris)
    ciphertext, tag = cipher.encrypt_and_digest(data)#Encrypts the data
    # print("SIZE: " + str(len(ciphertext))) #DEBUG
    return(ciphertext + tag + cipher.nonce)#Returns encrypted data




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
        if ((len(firmware) - i) // 15 != 0):#If the firmware fills a full chunk, encrypt 15 bytes
            encrypted += encrypt((p8(2, endian = "big") + firmware[i : i + 15]), key, header)
    if (len(firmware) % 15 != 0):#Pads what's left over
        encrypted += encrypt(randPad((p8(2, endian = "big") + firmware[i : len(firmware)]), 16), key, header)

    # Append message to end of firmware
    #firmware_and_message = firmware + encrypt(pad(p8(5, endian = "big") + message.encode(), 16), key, header)

    messageBin = message.encode()
    messageEncrypted = b""
    
    for i in range (0, len(messageBin), 15):#Breaks message into chunks and runs those chunks through encrypt(). Uses keys from secret_build_output.txt.
        if ((len(messageBin) - i) // 15 != 0):#If the firmware fills a full chunk, encrypt 15 bytes
            messageEncrypted += encrypt((p8(5, endian = "big") + messageBin[i : i + 15]), key, header)
        
    if (len(messageBin) % 15 != 0):#Pads what's left over
        messageEncrypted += encrypt(randPad((p8(5, endian = "big") + messageBin[i : len(firmware)]), 16), key, header)
    firmware_and_message = firmware + messageEncrypted
    
    
    # Pack message type as a uint8, and version, firmware length and message length as uint16s and encrypts them
    beginFrame = encrypt(randPad(p8(1, endian = "big") + p16(version, endian = "big") + p16(len(firmware), endian = "big") + p16(len(message), endian = "big"), 16), key, header)
    #Generates end frame and encrypts it
    endFrame = encrypt(randPad(p8(3, endian = "big"), 16), key, header)
    # Append firmware and message to metadata
    firmware_blob = beginFrame + encrypted + messageEncrypted + endFrame #Builds firmware blob

    # Write encrypted firmware blob to outfile
    with open(outfile, 'wb+') as outfile:
        outfile.write(firmware_blob)
    
    print(firmware_blob)


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