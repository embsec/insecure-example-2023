// Copyright 2023 The MITRE Corporation. ALL RIGHTS RESERVED
// Approved for public release. Distribution unlimited 23-02181-13.

#include <string.h>

#define VERSION_2
#include "usart.h"
#include "uart.h"
#include "util.h"
#include "mitre_car.h"

static const char *FLAG_RESPONSE = "Nice try.";

void getFlag(char *flag)
{
    flag = strcpy(flag, FLAG_RESPONSE);
}

int main(void) __attribute__((section(".text.main")));
int main (void)
{
    printBanner();
    for(;;) // Loop forever.
    {
        char buff[256];
        int len = prompt(buff, 256);
        if(buff[0] != '\0' && strncmp(buff, "FLAG", len) == 0)
        {
            getFlag(buff);
            writeLine(buff);
        }
    }
}
