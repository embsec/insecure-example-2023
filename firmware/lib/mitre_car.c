// Copyright 2023 The MITRE Corporation. ALL RIGHTS RESERVED
// Approved for public release. Distribution unlimited 23-02181-13.

#include "mitre_car.h"
#include "uart.h"
#include "usart.h"

#include <string.h>

static const char *STARTUP_BANNER =
    "                                                                        \n"
    "  __  __ _____ _______ _____  ______    _____          _____            \n"
    " |  \\/  |_   _|__   __|  __ \\|  ____|  / ____|   /\\   |  __ \\       \n"
    " | \\  / | | |    | |  | |__) | |__    | |       /  \\  | |__) |        \n"
    " | |\\/| | | |    | |  |  _  /|  __|   | |      / /\\ \\ |  _  /        \n"
    " | |  | |_| |_   | |  | | \\ \\| |____  | |____ / ____ \\| | \\ \\      \n"
    " |_|  |_|_____|  |_|  |_|  \\_\\______|  \\_____/_/    \\_\\_|  \\_\\   \n"
    "                                                                        \n"
    " (    (                      )    )  (         (         (              \n"
    " )\\ ) )\\ )   (     (      ( /( ( /(  )\\ ) *   ))\\ )  (   )\\ )      \n"
    "(()/((()/(   )\\    )\\ )   )\\()))\\())(()/` )  /(()/(  )\\ (()/(      \n"
    " /(_))/(_)((((_)( (()/(  ((_)\\((_)\\  /(_)( )(_)/(_)(((_) /(_))        \n"
    "(_))_(_))  )\\ _ )\\ /(_))_ _((_) ((_)(_))(_(_()(_)) )\\___(_))         \n"
    " |   |_ _| (_)_\\(_(_)) __| \\| |/ _ \\/ __|_   _|_ _((/ __/ __|        \n"
    " | |) | |   / _ \\   | (_ | .` | (_) \\__ \\ | |  | | | (__\\__ \\      \n"
    " |___|___| /_/ \\_\\   \\___|_|\\_|\\___/|___/ |_| |___| \\___|___/     \n"
    "                                                                        \n"
    "Type \"HELP\" for a listing of commands.                                \n"
    "\n";

static const char *HELP_TEXT =
    "MITRE Car Diagnotics System Commands:\n"
    " * HELP - This message\n"
    " * EMISSIONS - Query emissions system status\n"
    " * SAFETY - Query safety system status\n"
    " * INFOTAINMENT - Query information/entertainment system status\n"
    " * SECURITY - Query cybersecurity system status\n"
    " * FLAG - ???\n"
    "\n";

void printBanner()
{
    write(STARTUP_BANNER);
}

int prompt(char* buffer, int max_bytes)
{
    write("->");
    int len = readLine(buffer, max_bytes);
    parseCommand(buffer, len);

    return len;
}

void parseCommand(char* buffer, int len)
{
    if(strncmp(buffer, "HELP", len) == 0)
    {
        write(HELP_TEXT);
    }
    else if(strncmp(buffer, "EMISSIONS", len) == 0)
    {
        writeLine("Now that you mention it, the smoke usually isn't that color...");
    }
    else if(strncmp(buffer, "SAFETY", len) == 0)
    {
        writeLine("System normal.");
    }
    else if(strncmp(buffer, "INFOTAINMENT", len) == 0)
    {
        writeLine("Playing video: https://www.youtube.com/watch?v=dQw4w9WgXcQ");
    }
    else if(strncmp(buffer, "SECURITY", len) == 0)
    {
        writeLine("No viruses detected. Signatures last updated 1/1/1970.\n"
                  "Firewall disabled because it stops the airbags from "
                  "deploying.");
    }
    else if(strncmp(buffer, "FLAG", len) == 0);
    else
    {
        writeLine("Command not recognized. Use \"HELP\" for a listing.");
    }
}
