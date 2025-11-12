# Connect to QEMU
target remote localhost:1234

# Set up 16-bit real-mode
set architecture i8086
set tdesc filename i8086.xml
set disassembly-flavor intel
set disassemble-next-line on

# Log to file
set logging file qemu-trace.log
set logging enabled on

# Kill on exit
set detach-on-fork off

define state16
  printf "AX:%04X BX:%04X CX:%04X DX:%04X\n", (unsigned short)$ax, (unsigned short)$bx, (unsigned short)$cx, (unsigned short)$dx
  printf "SI:%04X DI:%04X BP:%04X SP:%04X\n", (unsigned short)$si, (unsigned short)$di, (unsigned short)$bp, (unsigned short)$sp
  printf "CS:%04X DS:%04X SS:%04X ES:%04X\n", (unsigned short)$cs, (unsigned short)$ds, (unsigned short)$ss, (unsigned short)$es
  printf "IP:%04X FLAGS:%04X\n", (unsigned short)$pc, $eflags
  #x/i ($cs << 4) + $pc
end

define hook-stop
  state16
end

# Step while skipping interrupt handlers and rep instructions
define si-smart
  set $csip = ($cs << 4) + $pc
  set $op = *(unsigned char*)$csip
  set $skip = 0
  
  # int N
  if $op == 0xCD
    set $skip = 2
  end
  
  # repe/repz
  if $op == 0xF3 || $op == 0xF2
    set $skip = 2
  end

  if $skip > 0
    tbreak *($csip + $skip)
    c
  else
    si
  end
end

define repeat-si-smart
  if $argc < 1
    printf "Usage: repeat-si-smart <count>\n"
  else
    set $count = $arg0
    set $i = 0
    while $i < $count
      si-smart
      set $i = $i + 1
    end
  end
end

# Set breakpoint at boot sector start (0x7c00)
break *0x7c00

# Continue execution
continue
