obj = boot.o
elf = boot.elf
bin = boot
disk = boot.img

CC = ia16-elf-gcc
LD = ia16-elf-ld
OBJCOPY = ia16-elf-objcopy
CFLAGS = -ffreestanding -nostdlib -O1 -Wall

all: $(disk)

boot.img: boot io.sys
	dd if=/dev/zero of=$@ bs=20M count=1
	mformat -i $@ -B boot ::
	mcopy -i $@ boot.c gdb-boot.txt io.c io.sys boot.ld ::

boot: boot.elf
	$(OBJCOPY) -O binary $< $@

boot.elf: boot.o
	$(LD) --no-warn-rwx-segments --Map=boot.map -T boot.ld -o $@ $^

boot.o: boot.c
	$(CC) $(CFLAGS) -c -o $@ $^

io.sys: io.elf
	$(OBJCOPY) -O binary $< $@

io.elf: io.o
	$(LD) --no-warn-rwx-segments --Map=io.map -T io.ld -o $@ $^

io.o: io.c
	$(CC) $(CFLAGS) -c -o $@ $^

.PHONY: all clean run debug

rebuild: clean all

clean:
	rm -f *.o *.elf *.map io.sys $(disk) boot

run: $(disk)
	qemu-system-i386 -drive format=raw,file=$(disk) -nographic -no-reboot

debug: $(disk)
	qemu-system-i386 -drive format=raw,file=$(disk) -nographic -s -S

disasm: boot.elf
	ia16-elf-objdump -d boot.elf -M i8086,intel

dostest.img: boot
	dd if=/dev/zero of=$@ bs=20M count=1
	mformat -i $@ -B boot ::
	mcopy -i $@ -s ./dos622/* ::