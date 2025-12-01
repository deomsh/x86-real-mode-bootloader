CC = ia16-elf-gcc
LD = ia16-elf-ld
OBJCOPY = ia16-elf-objcopy
CFLAGS = -ffreestanding -nostdlib -O1 -Wall

all: boot.qcow2

boot.qcow2: boot.img
	qemu-img convert -f raw -O qcow2 boot.img boot.qcow2

boot.img: boot io.sys
	dd if=/dev/zero of=$@ bs=20M count=1
	mformat -i $@ -B boot ::
	mcopy -i $@ boot.c io.c io.sys boot.ld ::

boot: boot.elf
	$(OBJCOPY) -O binary boot.elf boot

boot.elf: boot.o
	$(LD) --no-warn-rwx-segments --Map=boot.map -T boot.ld -o boot.elf boot.o

boot.o: boot.c
	$(CC) $(CFLAGS) -c -o boot.o boot.c

io.sys: io.elf
	$(OBJCOPY) -O binary io.elf io.sys

io.elf: io.o
	$(LD) --no-warn-rwx-segments --Map=io.map -T io.ld -o io.elf io.o

io.o: io.c
	$(CC) $(CFLAGS) -c -o io.o io.c

.PHONY: all clean run debug

rebuild: clean all

clean:
	rm -f *.o *.elf *.map io.sys boot.qcow2 boot.img boot

run: boot.img
	qemu-system-i386 -drive format=raw,file=boot.img -nographic -no-reboot

debug: boot.img
	qemu-system-i386 -drive format=raw,file=boot.img -nographic -s -S

disasm: boot.elf
	ia16-elf-objdump -d boot.elf -M i8086,intel

dostest.img: boot
	dd if=/dev/zero of=$@ bs=20M count=1
	mformat -i $@ -B boot ::
	mcopy -i $@ -s ./dos622/* ::

blahblah: boot
	echo "Hello, world!"

print_at.bin: print_at.asm boot.img
	nasm -f bin print_at.asm -o print_at.bin
	mcopy -i boot.img print_at.bin ::IO.SYS

# Test9

oemboot.bin: oemboot.asm magic.mac
	nasm -f bin -i magic.mac oemboot.asm -o oemboot.bin

oemboot800.bin: oemboot800.asm
	nasm -f bin oemboot800.asm -o oemboot800.bin

oemboot801.bin: oemboot801.asm
	nasm -f bin oemboot801.asm -o oemboot801.bin

oemboot93.bin: oemboot93.asm
	nasm -f bin oemboot93.asm -o oemboot93.bin

test.bin: test.nasm
	nasm -f bin test.nasm -o test.bin

boot.bin: boot.asm
	nasm -f bin boot.asm -o boot.bin

msdos.bin: msdos.nasm
	nasm -f bin msdos.nasm -o msdos.bin

msboot.bin: MSBOOT.nasm
	nasm -f bin MSBOOT.nasm -o msboot.bin

oldmbr.bin: oldmbr.asm
	nasm -f bin oldmbr.asm -o oldmbr.bin

simple_boot.bin: simple_boot.asm
	nasm -f bin simple_boot.asm -o simple_boot.bin


