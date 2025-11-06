# x86 Real Mode Bootloader Emulator

A Python-based emulator using [Unicorn Engine](https://www.unicorn-engine.org/) and [Capstone](https://www.capstone-engine.org/) to emulate x86 real mode bootloaders with step-by-step instruction tracing and BIOS interrupt emulation.

## Features

- **True 16-bit Real Mode Emulation**: Uses Unicorn Engine with UC_MODE_16 for accurate real mode emulation
- **Instruction Tracing**: Logs every instruction with address, disassembly, and relevant registers
- **BIOS Interrupt Emulation**: Implements INT 0x10 (video) and INT 0x13 (disk services)
- **Disk Image Support**: Attach disk images to emulate complete boot process
- **Flat Text Output**: Simple format: `address|instruction|register=value|...`
- **Intelligent Register Tracking**: Only shows registers actually used by each instruction

## Installation

### Prerequisites

```bash
pip install unicorn capstone
```

### System Requirements

- Python 3.7 or higher
- Linux, macOS, or Windows
- unicorn package (CPU emulator)
- capstone package (disassembler)

## Usage

### Basic Usage

```bash
python3 emulator.py <bootloader.bin>
```

### With Disk Image

```bash
python3 emulator.py boot.bin -d boot.img
```

### Options

```bash
python3 emulator.py [options] <bootloader.bin>

Arguments:
  binary                Path to bootloader binary file

Options:
  -h, --help           Show help message
  -m, --max-instructions N
                       Maximum number of instructions to execute (default: 1000000)
  -o, --output FILE    Output trace file (default: trace.txt)
  -q, --quiet          Reduce verbosity (suppress console output, only write to trace file)
  -d, --disk IMAGE     Attach disk image file (e.g., boot.img)
```

### Examples

1. **Emulate a simple bootloader:**
   ```bash
   python3 emulator.py simple_boot.bin
   ```

2. **With disk image:**
   ```bash
   python3 emulator.py boot -d boot.img -m 5000
   ```

3. **Quiet mode with custom output:**
   ```bash
   python3 emulator.py simple_boot.bin -q -o my_trace.txt
   ```

## Output Format

### Trace File Format

Each line in the trace file follows the format:

```
address|instruction|register=value|register=value|...
```

Example:

```
0x7c00|cli
0x7c01|xor ax, ax|ax=0x0
0x7c03|mov ds, ax|ax=0x0
0x7c11|mov word ptr [0x500], ax|ax=0x1234
0x7c18|add ax, bx|ax=0x1234|bx=0x1234
0x7c28|int 0x10|int=0x10
```

### Console Output

```
[*] Initializing Unicorn Engine (x86 16-bit real mode)...
[*] Setting up memory...
  - Mapped 1024 KB at 0x00000000
[*] Loading bootloader from simple_boot.bin...
  ✓ Valid boot signature: 0xAA55
[*] Setting up CPU state...
  - CS:IP: 0x0000:0x7C00

0x7c00|cli
0x7c01|xor ax, ax|ax=0x0
[INT 0x10] Teletype output: 'H'
...

Total instructions executed: 29
Final CS:IP: 0x0000:0x7C2B
```

## BIOS Interrupt Emulation

### INT 0x10 - Video Services

- **AH=0x0E**: Teletype output - prints character in AL to console

### INT 0x13 - Disk Services

- **AH=0x08**: Get drive parameters - returns fake geometry
  - Returns 80 sectors per track, 2 heads
- **AH=0x42**: Extended read sectors (LBA)
  - Reads sectors from attached disk image
  - Uses Disk Address Packet structure
  - Writes data to specified memory buffer

## How It Works

### Memory Layout

The emulator sets up a 1 MB memory region (0x00000 - 0xFFFFF) for real mode:

- **0x00000 - 0x7BFF**: Available RAM
- **0x7C00 - 0x7DFF**: Boot sector location (512 bytes)
- **0x7E00 - 0xFFFFF**: Additional RAM

### CPU Initialization

The CPU is initialized for boot:
- **CS:IP**: 0x0000:0x7C00 (boot sector start)
- **SS:SP**: 0x0000:0x7C00 (stack pointer)
- **DL**: 0x80 (drive number - hard disk)
- **DS, ES**: 0x0000
- All other registers cleared to 0

### Execution Model

1. Map 1MB of memory
2. Load disk image (if provided)
3. Load boot sector at 0x7C00 (from disk or binary file)
4. Initialize CPU registers
5. Hook instruction execution
6. Execute instructions one at a time
7. For each instruction:
   - Disassemble using Capstone
   - Parse operands to find relevant registers
   - Log address, instruction, and register values
   - Handle BIOS interrupts (INT 0x10, INT 0x13)
8. Stop on HLT, error, or instruction limit

### Register Tracking

The emulator intelligently tracks which registers are relevant for each instruction:

- **Register operands**: Included if not write-only destination
- **Memory operands**: Base and index registers included
- **Implicit reads**: FLAGS register for conditional jumps
- **Special cases**:
  - CALL instructions show return address
  - INT instructions show interrupt number

## Disk Image Support

### Loading a Disk Image

```bash
python3 emulator.py boot -d boot.img
```

When a disk image is attached:
1. Boot sector is loaded from first 512 bytes of the image
2. Bootloader can read additional sectors using INT 0x13, AH=0x42
3. Full FAT filesystem can be emulated

### Creating a Disk Image

Use the project's Makefile:

```bash
make boot.img
```

This creates a FAT16 formatted image with the bootloader in the boot sector.

## Limitations

### BIOS Services

Only the following BIOS interrupts are implemented:
- INT 0x10, AH=0x0E (teletype output)
- INT 0x13, AH=0x08 (get drive parameters)
- INT 0x13, AH=0x42 (extended read sectors)

Other BIOS services will be logged but not executed.

### Real Mode Quirks

- Segment registers (CS, DS, ES, SS) are supported
- Real mode addressing (segment << 4 + offset) is implemented
- No protected mode or long mode support

## Examples

### Example 1: Simple Bootloader

```nasm
BITS 16
ORG 0x7C00

start:
    cli
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, 0x7C00
    sti

    mov ah, 0x0E
    mov al, 'H'
    int 0x10

    hlt
    jmp $

times 510-($-$$) db 0
dw 0xAA55
```

**Output:**
```
0x7c00|cli
0x7c01|xor ax, ax|ax=0x0
0x7c03|mov ds, ax|ax=0x0
0x7c05|mov es, ax|ax=0x0
0x7c22|mov ah, 0xe
0x7c24|mov al, 0x48
0x7c28|int 0x10|int=0x10
[INT 0x10] Teletype output: 'H'
0x7c2a|hlt
```

### Example 2: With Disk Reading

```bash
# Run the actual bootloader with disk image
python3 emulator.py boot -d boot.img -m 10000
```

This will:
1. Load boot sector from boot.img
2. Emulate INT 0x13 disk reads
3. Allow bootloader to read FAT filesystem
4. Load and jump to IO.SYS (if found)

## Debugging

The emulator provides detailed logging:

1. **Instruction-level**: See every instruction executed
2. **Register tracking**: Monitor register changes
3. **BIOS calls**: See all interrupt calls with parameters
4. **Memory access**: Track reads and writes
5. **Disk I/O**: See LBA reads from disk image

## Advanced Usage

### Analyzing Boot Process

```bash
# Run with high instruction limit and capture full trace
python3 emulator.py boot -d boot.img -m 50000 -o full_trace.txt

# Analyze the trace
grep "int 0x13" full_trace.txt  # Find all disk reads
grep "int 0x10" full_trace.txt  # Find all screen output
```

### Custom Binary Analysis

```python
from emulator import BootloaderEmulator

# Create emulator
emu = BootloaderEmulator(
    'bootloader.bin',
    max_instructions=5000,
    trace_file='analysis.txt',
    verbose=True,
    disk_image='disk.img'
)

# Setup and run
emu.setup_memory()
emu.load_disk_image()
emu.load_bootloader()
emu.setup_cpu_state()
emu.run()
```

## Comparison with Other Tools

| Feature | Unicorn Emulator | QEMU | Bochs | icicle-emu |
|---------|------------------|------|-------|------------|
| Real mode | ✓ True 16-bit | ✓ Full | ✓ Full | ✗ 64-bit only |
| BIOS support | ✓ INT 0x10/0x13 | ✓ Full | ✓ Full | ✗ |
| Disk image | ✓ | ✓ | ✓ | ✗ |
| Instruction trace | ✓ Built-in | Manual | ✓ Built-in | ✓ Built-in |
| Python integration | ✓ Native | External | External | ✓ Native |
| Speed | Fast | Fastest | Slow | Fastest |
| Setup complexity | Low | Medium | Medium | Low |
| Trace format | Flat text | Various | Custom | JSON |

## Troubleshooting

### Import Error: unicorn or capstone not found

```bash
pip install unicorn capstone
```

### Disk Read Failures

If you see "No disk image attached!" errors:
- Verify disk image path with `-d` option
- Check that disk image file exists
- Ensure disk image is at least 512 bytes

### Invalid Boot Signature

The emulator warns if boot signature (0xAA55) is missing but continues execution.

## Contributing

Contributions welcome! Areas for improvement:

- [ ] Add more BIOS interrupts (INT 0x16 - keyboard, INT 0x15 - memory)
- [ ] Implement CHS disk addressing (in addition to LBA)
- [ ] Add memory access logging hooks
- [ ] Export trace to JSON format
- [ ] Interactive debugging mode
- [ ] Support for protected mode switching
- [ ] FAT filesystem helpers

## References

- [Unicorn Engine](https://www.unicorn-engine.org/)
- [Capstone Disassembler](https://www.capstone-engine.org/)
- [x86 Real Mode Memory Map](https://wiki.osdev.org/Memory_Map_(x86))
- [Boot Sector Format](https://wiki.osdev.org/Boot_Sequence)
- [INT 0x10 BIOS Services](https://en.wikipedia.org/wiki/INT_10H)
- [INT 0x13 BIOS Services](https://en.wikipedia.org/wiki/INT_13H)

## License

This emulator script is provided as-is for educational purposes. See the main repository LICENSE for details.
