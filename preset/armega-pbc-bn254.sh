#!/bin/sh
ARDUINO=/usr/share/arduino
CC="${ARDUINO}/hardware/tools/avr/bin/avr-gcc -nostdlib" CXX="${ARDUINO}/hardware/tools/avr/bin/avr-g++ -nostdlib" LDFLAGS=" -Wl,--gc-sections" CFLAGS="-O2 -ggdb -DF_CPU=16000000L -mmcu=atmega2560 -ffunction-sections -fdata-sections" cmake -DCMAKE_SYSTEM_NAME="Generic" -DARCH=AVR -DWSIZE=8 -DOPSYS=DUINO -DSEED=LIBC -DSHLIB=OFF -DSTBIN=ON -DTIMER=HREAL -DWITH="DV;BN;FP;EP;EC;CP;MD;FPX;EPX;PP;PC" -DBENCH=0 -DTESTS=0 -DCHECK=off -DVERBS=off -DSTRIP=on -DQUIET=off -DARITH=easy -DBN_METHD="COMBA;COMBA;BASIC;BASIC;STEIN;BASIC" -DBN_PRECI=256 -DBN_MAGNI=DOUBLE -DFP_PRIME=254 -DFP_QNRES=on -DFP_METHD="INTEG;COMBA;COMBA;MONTY;EXGCD;LOWER;SLIDE" -DEP_ENDOM=on -DEP_PLAIN=off -DEP_SUPER=off -DEC_ENDOM=on -DEC_METHD="PRIME" -DMD_METHD=SH256 -DFPX_METHD="INTEG;INTEG;LAZYR" -DPP_METHD="LAZYR;OATEP" -DEP_PRECO=off $1
