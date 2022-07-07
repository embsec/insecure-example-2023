# README

## running the insecure example

1. build the firmware by navigating to `firmware/firmware`, and running `make`.
2. build the bootloader by navigating to `tools`, and running `python bl_build.py`

## troubleshooting

Ensure that BearSSL is compiled for the stellaris: `cd ~/lib/BearSSL && make CONF=../../stellaris/bearssl/stellaris clean && make CONF=../../stellaris/bearssl/stellaris`


©2022 The MITRE Corporation. ALL RIGHTS RESERVED

Approved for public release. Distribution unlimited PR_22-xxxxx-x.