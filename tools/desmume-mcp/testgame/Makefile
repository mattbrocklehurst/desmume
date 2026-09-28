# Builds testgame.nds with a stock arm-none-eabi toolchain
# (Debian/Ubuntu: apt install gcc-arm-none-eabi). No devkitPro needed.
#
# testgame.elf keeps the symbols, so it can be used as ground truth when
# checking what the debugging tools report.

CC      = arm-none-eabi-gcc
OBJCOPY = arm-none-eabi-objcopy
NM      = arm-none-eabi-nm
CFLAGS  = -mcpu=arm946e-s -marm -mthumb-interwork -O2 -ffreestanding -nostdlib -Wno-multichar

all: testgame.nds testgame.sym

testgame.elf: crt0.s game.c link.ld
	$(CC) $(CFLAGS) -T link.ld crt0.s game.c -o $@ -lgcc

overlay0.elf: overlay.c overlay.ld
	$(CC) $(CFLAGS) -T overlay.ld overlay.c -o $@

%.bin: %.elf
	$(OBJCOPY) -O binary $< $@

testgame.sym: testgame.elf
	$(NM) -n $< > $@

testgame.nds: testgame.bin overlay0.bin mkrom.py
	python3 mkrom.py testgame.bin overlay0.bin $@

clean:
	rm -f *.elf *.bin

.PHONY: all clean
