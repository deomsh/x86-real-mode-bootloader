# Connect to QEMU
target remote localhost:1234

# Set up 16-bit real-mode
set architecture i8086
set tdesc filename i8086.xml
set disassembly-flavor intel

define state16
  printf "AX:%04X BX:%04X CX:%04X DX:%04X\n", (unsigned short)$ax, (unsigned short)$bx, (unsigned short)$cx, (unsigned short)$dx
  printf "SI:%04X DI:%04X BP:%04X SP:%04X\n", (unsigned short)$si, (unsigned short)$di, (unsigned short)$bp, (unsigned short)$sp
  printf "CS:%04X DS:%04X SS:%04X ES:%04X\n", (unsigned short)$cs, (unsigned short)$ds, (unsigned short)$ss, (unsigned short)$es
  printf "IP:%04X FLAGS:%04X\n", (unsigned short)$pc, $eflags
  x/i $pc
end

define hook-stop
  state16
end

# Set breakpoint at boot sector start (0x7c00)
break *0x7c00

# Continue execution
continue
