#!/bin/bash

if printf -v regex ':%04X .* 0A ' 1234;grep -q "$regex" /proc/net/tcp*;
then
    gdb-multiarch -ex 'target remote :1234' -ex 'layout split' -ex 'file ../bootloader/gcc/main.axf'
else
    echo "Didn't detect GDB port listening. Did you remember to run python ./bl_emulate --debug ?"
fi