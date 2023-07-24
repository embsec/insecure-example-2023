// Copyright 2023 The MITRE Corporation. ALL RIGHTS RESERVED
// Approved for public release. Distribution unlimited 23-02181-13.

char hex2nybble(char nybble);
char hex2byte(char upper_nybble, char lower_nybble);
int hex2str(char* hex_str, int length, char* byte_str);
int str2hex(char *byte_str, int length, char *hex_str);
