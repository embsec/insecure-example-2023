#!/usr/bin/env python

# Copyright 2023 The MITRE Corporation. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-13.

import argparse
import time
import socket

from util import *

from Crypto.Util.Padding import pad
from pwn import *

OK = b"\x00"
ERROR = b"\x01"
END = b"\x02"

FRAME_SIZE = 48
    
def send_metadata(ser, metadata, debug=False):
    # Handshake for update TODO: change frame?
    ser.write(b"U")

    print("Waiting for bootloader to enter update mode...")
    while ser.read(1).decode() != "U":
        print("got a byte")
        pass
    print("ok got here")
    
    send_frame(ser, metadata, debug)


def send_frame(ser, frame, debug=False):
    # Write the DATA frame
    ser.write(frame) 
    
    if debug:
        print_hex(frame)

    #counter for times ERROR was returns
    falsetimes = 0
    #boolean that stores whether frame sent was successful
    framesuccess = False
    
    #resend frame if given ERROR message
    while framesuccess == False:
        if falsetimes >= 10:
            raise RuntimeError("invalid frame sent too many times, aborting")
        
        # get return message type
        returnmessagetype = ser.read(1)
        #get return message info
        returnmessageinfo = ser.read(1)
        time.sleep(0.1)
        
        if debug:
            print("Resp: {}".format(ord(returnmessageinfo)))
            
        #check for valid return message type
        if returnmessagetype == b'\x04':
            if returnmessageinfo == OK:
                framesuccess = True
            elif returnmessageinfo == ERROR:
                ser.write(frame)
                #increment falsetimes if frame was invalid
                falsetimes += 1
            elif returnmessageinfo == END:
                raise RuntimeError("invalid frame sent, aborting update")
            else:
                raise RuntimeError("invalid message, aborting update")
        else:
            raise RuntimeError("invalid message number, aborting update")



def update(ser, infile, debug):
    # Open serial port. Set baudrate to 115200. Set timeout to 2 seconds.
    with open(infile, "rb") as fp:
        firmware_blob = fp.read()

    metadata = firmware_blob[:48]
    firmware = firmware_blob[48:]

    #SEND START FRAME
    send_metadata(ser, metadata, debug=debug)

    #SEND DATA FRAMES, MESSAGE FRAME, END FRAME
    for idx, frame_start in enumerate(range(0, len(firmware), FRAME_SIZE)):
        data = firmware[frame_start : frame_start + FRAME_SIZE]

        send_frame(ser, data, debug=debug)
        print(f"Wrote frame {idx} ({len(data)} bytes)")
        
    print("Wrote end frame")
    print("Done writing firmware.")


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
