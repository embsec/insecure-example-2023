#!/usr/bin/env python

# Copyright 2023 The MITRE Corporation. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-13.

import socket

UART0_PATH = "/embsec/UART0"
UART1_PATH = "/embsec/UART1"
UART2_PATH = "/embsec/UART2"

class DomainSocketSerial:
    def __init__(self, ser_socket: socket.socket):
        self.ser_socket = ser_socket
    
    def read(self, length: int) -> bytes:
        if length < 1:
            raise ValueError("Read length must be at least 1 byte")
        
        return self.ser_socket.recv(length)
    
    def readline(self) -> bytes:
        line = b""

        c = self.ser_socket.recv(1)
        while c != b"\n":
            line += c
            c = self.ser_socket.recv(1)
        
        line += b'\n'
        return line

    def write(self, data: bytes):
        self.ser_socket.send(data)

    def close(self):
        self.ser_socket.close()
        del self

def print_hex(data):
    hex_string = ' '.join(format(byte, '02x') for byte in data)
    print(hex_string)