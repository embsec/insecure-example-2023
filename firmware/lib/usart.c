// Copyright 2023 The MITRE Corporation. ALL RIGHTS RESERVED
// Approved for public release. Distribution unlimited 23-02181-13.

#include "usart.h"
#include "uart.h"

int readLine(char *buffer, int max_bytes)
{
    int i;
    int ret;
    for (i = 0;i < max_bytes; ++i)
    {
        // Fetch the received byte value into the variable "received_byte".
        char received_byte = uart_read(UART2, 1, &ret);
        // If the line has ended, terminate the string and break. Otherwise,
        // store the byte and contintue.
        if(received_byte == '\n' || received_byte == '\r')
        {
            buffer[i] = '\0';
            break;
        }
        else
        {
            buffer[i] = received_byte;
        }
    }

    // Reture number of bytes received (length of string).
    return i;
}

void write(const char *buffer)
{
    uart_write_str(UART2, (char *) buffer); // Send the byte.
}

void writeLine(const char *buffer)
{
    write(buffer);
    nl(UART2);
}

void initializeUSART()
{
    uart_init(UART2);
}
