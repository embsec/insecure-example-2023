// Copyright 2023 The MITRE Corporation. ALL RIGHTS RESERVED
// Approved for public release. Distribution unlimited 23-02181-13.

#include "util.h"
#include <string.h>

// strnlen seems to be nonstandard in this setup, but it is present so signature to supress warning
size_t strnlen(const char *s, size_t maxlen);

char hex2nybble(char nybble)
{
    if(nybble >= 'A' && nybble <= 'F') return nybble - 'A' + 10;
    else if(nybble >= 'a' && nybble <= 'f') return nybble - 'a' + 10;
    else if(nybble >= '0' && nybble <= '9') return nybble - '0';
    else return -1;
}

char hex2byte(char upper_nybble, char lower_nybble)
{
    return (hex2nybble(upper_nybble) << 4) | hex2nybble(lower_nybble);
}

int hex2str(char *hex_str, int length, char *byte_str)
{
    length = strnlen(hex_str, length);
    int i;
    for(i = 0; i < length; i+=2)
    {
        byte_str[i>>1] = hex2byte(hex_str[i], hex_str[i+1]);
    }
    return i>>1;
}

int str2hex(char *byte_str, int length, char *hex_str)
{
    int i;
    for(i = 0; i < length; ++i)
    {
        hex_str[i*2]   = (byte_str[i]>>4)  > 9 ? (byte_str[i]>>4)  + 'a' - 10 : (byte_str[i]>>4)  + '0';
        hex_str[i*2+1] = (byte_str[i]&0xF) > 9 ? (byte_str[i]&0xF) + 'a' - 10 : (byte_str[i]&0xF) + '0';
    }
    return i*2;
}
