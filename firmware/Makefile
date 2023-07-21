#******************************************************************************
#
# Makefile - Rules for building the project example.
#
# Copyright (c) 2013 Texas Instruments Incorporated.  All rights reserved.
# Software License Agreement
# 
#   Redistribution and use in source and binary forms, with or without
#   modification, are permitted provided that the following conditions
#   are met:
# 
#   Redistributions of source code must retain the above copyright
#   notice, this list of conditions and the following disclaimer.
# 
#   Redistributions in binary form must reproduce the above copyright
#   notice, this list of conditions and the following disclaimer in the
#   documentation and/or other materials provided with the  
#   distribution.
# 
#   Neither the name of Texas Instruments Incorporated nor the names of
#   its contributors may be used to endorse or promote products derived
#   from this software without specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# 
# This is part of revision 10636 of the Stellaris Firmware Development Package.
#
#******************************************************************************

#
# Defines the part type that this project uses.
#
PART=LM3S6965

#
# Base library directory
#
ROOT=${HOME}
LIB=${ROOT}/lib

#
# The base directory for individual libraries
#
STELLARIS=${LIB}/stellaris
UART=${LIB}/uart


#
# Include the common make definitions.
#
include ${STELLARIS}/makedefs

#
# Where to find header files that do not live in this directory.
#
IPATH+=./include
IPATH=${STELLARIS}
IPATH+=${UART}
IPATH+=$(realpath ./lib/)

#
# Where to find source files that do not live in this directory
#
VPATH=./src
VPATH+=${UART}
IPATH+=$(realpath ./lib/)

#CFLAGS+=-ffunction-sections

#
# The default rule, which causes the project example to be built.
#
all: ${COMPILER}
all: driverlib
all: ${COMPILER}/main.axf

#
# The rule to clean out all the build products.
#
clean:
	@rm -rf ${COMPILER} ${wildcard *~}

#
# Rule to remove intermediate build objects to avoid confusing students.
#
remove_objects:
	@rm -f ${COMPILER}/*[^.bin]

# Because this project is so small, build speed impact is negligible.
# We want to make the process as clear as possible to students by only having the important, final files present.
all: remove_objects

#
# The rule to create the target directory.
#
${COMPILER}:
	@mkdir -p ${COMPILER}

#
# Rules for building the project example.
#
${COMPILER}/main.axf: $(realpath ./lib/)/usart.o
${COMPILER}/main.axf: $(realpath ./lib/)/mitre_car.o
${COMPILER}/main.axf: $(realpath ./lib/)/util.o
${COMPILER}/main.axf: ${COMPILER}/uart.o
${COMPILER}/main.axf: ${COMPILER}/firmware.o
${COMPILER}/main.axf: ${STELLARIS}/driverlib/${COMPILER}-cm3/libdriver-cm3.a
${COMPILER}/main.axf: $(realpath ./)/firmware.ld
SCATTERgcc_main=$(realpath ./)/firmware.ld
ENTRY_main=main

driverlib:
	@cd ${STELLARIS} && make

#
# Include the automatically generated dependency files.
#
ifneq (${MAKECMDGOALS},clean)
-include ${wildcard src/${COMPILER}/*.d} __dummy__
endif
