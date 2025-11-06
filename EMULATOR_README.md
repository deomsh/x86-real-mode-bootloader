# x86 Real Mode Bootloader Emulator

A Python-based emulator using [icicle-emu](https://github.com/icicle-emu/icicle-emu) to emulate x86 real mode bootloaders with step-by-step instruction and memory access tracing.

## Features

- **Step-by-step execution**: Execute bootloader code one instruction at a time
- **Instruction logging**: Log every instruction with program counter, bytes, and register state
- **Memory access tracking**: Monitor memory reads and writes (especially stack operations)
- **Register state tracking**: Display all general-purpose registers after each instruction
- **Boot sector validation**: Verify boot signature (0xAA55)
- **Configurable execution limits**: Set maximum instruction count to prevent infinite loops

## Installation

### Prerequisites

```bash
pip install icicle-emu
```

### System Requirements

- Python 3.7 or higher
- Linux, macOS, or Windows
- icicle-emu package (automatically installs required dependencies)

## Usage

### Basic Usage

```bash
python3 emulator.py <bootloader.bin>
```

### Options

```bash
python3 emulator.py [options] <bootloader.bin>

Arguments:
  binary                Path to bootloader binary file

Options:
  -h, --help           Show help message
  -m, --max-instructions N
                       Maximum number of instructions to execute (default: 10000)
  -q, --quiet          Reduce verbosity (only show first 50 instructions)
```

### Examples

1. **Emulate a simple bootloader:**
   ```bash
   python3 emulator.py simple_boot.bin
   ```

2. **Limit execution to 500 instructions:**
   ```bash
   python3 emulator.py simple_boot.bin -m 500
   ```

3. **Quiet mode (less verbose output):**
   ```bash
   python3 emulator.py simple_boot.bin -q
   ```

## Output Format

### Instruction Trace

Each instruction execution shows:

```
[Step 00001] PC: 0x00007C00
  Bytes: FA 31 C0 8E D8 8E C0 8E
  Regs:  RAX:00000000 RBX:00000000 RCX:00000000 RDX:00000080 ...
  Memory: PUSH - wrote 8 bytes to stack at 0x00007BF8
```

- **Step**: Sequential instruction number
- **PC**: Program Counter (instruction address)
- **Bytes**: Raw instruction bytes (up to 8 bytes shown)
- **Regs**: Current state of all general-purpose registers
- **Memory**: Memory access operations (if any)

### Summary

At the end of execution:

```
================================================================================
Emulation Summary
================================================================================
Total instructions executed: 16
Final PC: 0x00007C28

Final register state:
  RAX: 0x0000000005A30E48
  RBX: 0x0000000000000000
  ...

Memory at boot sector (0x7C00):
  0x7C00: FA 31 C0 8E D8 8E C0 8E D0 BC 00 7C FB FC B8 34
  ...
```

## How It Works

### Memory Layout

The emulator sets up a 1 MB memory region (0x00000 - 0xFFFFF) to simulate real mode address space:

- **0x00000 - 0x7BFF**: Available RAM
- **0x7C00 - 0x7DFF**: Boot sector location (512 bytes)
- **0x7E00 - 0xFFFFF**: Additional RAM

### CPU Initialization

The CPU is initialized with:
- **RIP**: 0x7C00 (boot sector start)
- **RSP**: 0x7C00 (stack pointer)
- **RDX**: 0x80 (drive number - hard disk)
- All other registers cleared to 0

### Execution Model

1. Load bootloader binary at 0x7C00
2. Initialize CPU registers
3. Execute instructions one at a time using `vm.step(1)`
4. After each instruction:
   - Log PC, instruction bytes, and registers
   - Detect memory accesses by monitoring register changes
   - Check for exit conditions (halt, invalid instruction, etc.)

### Exit Conditions

The emulator stops when it encounters:
- **HLT instruction**: CPU halted
- **Invalid instruction**: Undefined opcode
- **Memory violation**: Access to unmapped memory
- **Infinite loop**: PC doesn't advance
- **Instruction limit**: Max instruction count reached
- **Keyboard interrupt**: Ctrl+C

## Limitations

### Real Mode vs. Long Mode

The emulator uses x86_64 architecture, which differs from true 16-bit real mode:

- **64-bit registers**: Registers are 64-bit (RAX vs. AX)
- **No segment registers**: Real mode segment:offset addressing not fully supported
- **No BIOS**: BIOS interrupts (INT 0x10, INT 0x13, etc.) are not emulated

### BIOS Interrupts

The emulator does not provide BIOS services. Instructions like:
- `INT 0x10` (video services)
- `INT 0x13` (disk services)
- `INT 0x16` (keyboard services)

Will execute but have no effect. For full BIOS emulation, consider using QEMU or Bochs.

### Memory Access Tracking

Memory access detection is simplified and primarily tracks:
- Stack operations (PUSH/POP) via RSP changes
- Direct memory operations require manual instrumentation

## Examples

### Simple Bootloader (simple_boot.asm)

A minimal bootloader that demonstrates basic operations:

```nasm
BITS 16
ORG 0x7C00

start:
    cli                 ; Disable interrupts
    xor ax, ax         ; Clear AX
    mov ds, ax         ; Set DS = 0
    mov es, ax         ; Set ES = 0
    mov ss, ax         ; Set SS = 0
    mov sp, 0x7C00     ; Set stack pointer
    sti                ; Enable interrupts
    cld                ; Clear direction flag

    ; Write test value
    mov ax, 0x1234
    mov [0x0500], ax

    ; Read it back
    mov bx, [0x0500]

    ; Test loop
    mov cx, 5
loop_start:
    dec cx
    jnz loop_start

    ; Print 'H'
    mov ah, 0x0E
    mov al, 'H'
    int 0x10

    ; Halt
halt_loop:
    hlt
    jmp halt_loop

times 510-($-$$) db 0
dw 0xAA55
```

**Compile:**
```bash
nasm -f bin simple_boot.asm -o simple_boot.bin
```

**Run:**
```bash
python3 emulator.py simple_boot.bin
```

## Advanced Usage

### Custom Binary Analysis

The emulator can be imported as a module:

```python
from emulator import BootloaderEmulator

# Create emulator
emu = BootloaderEmulator('bootloader.bin', max_instructions=1000, verbose=True)

# Setup
emu.setup_memory()
emu.load_bootloader()
emu.setup_cpu_state()

# Custom analysis before running
print(f"Boot sector signature: {emu.vm.mem_read(0x7DFE, 2)}")

# Run
emu.run()
```

### Debugging

The emulator provides detailed logging that can help debug bootloader issues:

1. **Instruction-level debugging**: See exactly what each instruction does
2. **Register tracking**: Monitor register changes after each instruction
3. **Memory inspection**: View memory contents at any address
4. **Exception handling**: Clear error messages for common issues

## Comparison with Other Tools

| Feature | icicle-emu Emulator | QEMU | Bochs | GDB + QEMU |
|---------|-------------------|------|-------|------------|
| Instruction trace | ✓ Built-in | Manual | ✓ Built-in | Manual |
| Memory logging | ✓ Built-in | Manual | ✓ Built-in | Manual |
| Python integration | ✓ Native | External | External | External |
| BIOS support | ✗ | ✓ | ✓ | ✓ |
| Real mode | Limited | ✓ Full | ✓ Full | ✓ Full |
| Speed | Fast | Fastest | Slow | Medium |
| Setup complexity | Low | Medium | Medium | High |

## Troubleshooting

### Import Error: icicle-emu not found

```bash
pip install icicle-emu
```

### Invalid Architecture Error

Ensure you're using 'x86_64' architecture:
```python
vm = icicle.Icicle('x86_64')
```

### Memory Access Violations

If you see unmapped memory errors:
- Check that memory is properly mapped before access
- Verify addresses are within 0x00000 - 0xFFFFF range

### Infinite Loops

The emulator detects infinite loops (PC not advancing). Use `-m` to limit instructions:
```bash
python3 emulator.py bootloader.bin -m 100
```

## Contributing

Contributions welcome! Areas for improvement:

- [ ] Add BIOS interrupt emulation
- [ ] Implement true 16-bit real mode support
- [ ] Add disassembly integration (capstone)
- [ ] Enhanced memory access tracking with read/write hooks
- [ ] Support for disk image files (FAT filesystem)
- [ ] Interactive debugging mode
- [ ] Export trace to file formats (JSON, CSV)

## References

- [icicle-emu GitHub](https://github.com/icicle-emu/icicle-emu)
- [icicle-python Documentation](https://github.com/icicle-emu/icicle-python)
- [x86 Real Mode Memory Map](https://wiki.osdev.org/Memory_Map_(x86))
- [Boot Sector Format](https://wiki.osdev.org/Boot_Sequence)

## License

This emulator script is provided as-is for educational purposes. See the main repository LICENSE for details.
