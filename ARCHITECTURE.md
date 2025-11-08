# x86 Real-Mode Bootloader: Complete Architecture Guide

## Table of Contents
1. [Executive Summary](#executive-summary)
2. [Architecture Overview](#architecture-overview)
3. [Component Deep Dive](#component-deep-dive)
4. [Boot Process Flow](#boot-process-flow)
5. [Memory Layout](#memory-layout)
6. [FAT16 Filesystem Implementation](#fat16-filesystem-implementation)
7. [BIOS Services](#bios-services)
8. [Build System](#build-system)
9. [Testing Infrastructure](#testing-infrastructure)
10. [Development Workflow](#development-workflow)
11. [Technical Innovations](#technical-innovations)

---

## Executive Summary

This is a modern x86 real-mode bootloader written entirely in C using the `gcc-ia16` compiler. Unlike traditional bootloaders written in assembly, this project generates true 16-bit code directly from C source, avoiding the performance penalties of 32-bit code with size-override prefixes.

**Key Characteristics:**
- **Language**: C (compiled to 16-bit x86 via gcc-ia16)
- **Boot Method**: FAT16 filesystem-based bootloading
- **Stages**: 2-stage bootloader (boot sector + IO.SYS)
- **Target**: x86 real-mode execution
- **Development**: Fully containerized with devcontainer support
- **Testing**: Python-based emulator with instruction tracing
- **CI/CD**: Automated GitHub Actions workflow

**Project Goals:**
1. Demonstrate practical x86 real-mode programming in modern C
2. Provide a working bootloader for educational purposes
3. Prove that gcc-ia16 can generate production-quality boot code
4. Establish best practices for modern bootloader development

---

## Architecture Overview

### System Design

The bootloader follows a hierarchical 2-stage architecture:

```
┌─────────────────────────────────────────────┐
│             BIOS Boot Process               │
│  (Hardware loads first 512 bytes to 0x7C00) │
└────────────────┬────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────┐
│  Stage 1: Boot Sector (boot.c @ 0x7C00)    │
│  ─────────────────────────────────────────  │
│  • Minimal setup (registers, stack, flags) │
│  • FAT16 boot header embedded              │
│  • Filesystem parsing and file search      │
│  • Load IO.SYS from disk                   │
│  • Transfer control to Stage 2             │
│  • Max size: 510 bytes (512 - signature)   │
└────────────────┬────────────────────────────┘
                 │ Far jump to 0x0000:0x0700
                 ▼
┌─────────────────────────────────────────────┐
│  Stage 2: IO.SYS (io.c @ 0x0700)           │
│  ─────────────────────────────────────────  │
│  • Receives control from Stage 1           │
│  • Extends bootloader functionality        │
│  • Current: Demo/test implementation       │
│  • Max size: 3 sectors (1536 bytes)        │
│  • Future: Full DOS-like functionality     │
└─────────────────────────────────────────────┘
```

### Component Relationships

```
┌──────────────────────────────────────────────────┐
│          Compilation Toolchain                   │
│  (gcc-ia16, binutils, ld with custom scripts)   │
└──────────┬───────────────────────────────────────┘
           │
           ├─► boot.c + boot.ld ──► boot.elf ──► boot (binary)
           │
           └─► io.c + io.ld ──────► io.elf ──► io.sys (binary)
                                      │
                                      ▼
                        ┌──────────────────────────┐
                        │   Disk Image Creation    │
                        │  (mformat, dd, mtools)   │
                        └──────────┬───────────────┘
                                   │
                   ┌───────────────┼───────────────┐
                   │               │               │
                   ▼               ▼               ▼
              boot.img        boot.qcow2    (QEMU compatible)
              (FAT16)         (compressed)
                   │
         ┌─────────┼─────────┐
         │         │         │
         ▼         ▼         ▼
      QEMU      QEMU       Python
      Normal    Debug      Emulator
      (run)    (debug)    (emulator.py)
```

---

## Component Deep Dive

### 1. Boot Sector (boot.c)

**File**: `boot.c`
**Compiled Output**: `boot.elf` / `boot` (binary)
**Linker Script**: `boot.ld`
**Load Address**: `0x7C00` (BIOS-standard bootloader location)
**Maximum Size**: 510 bytes (512 byte sector - 2 byte signature)

#### Purpose
The boot sector is the first code executed by the BIOS. It must:
1. Initialize the CPU state for real-mode operation
2. Parse the FAT16 filesystem
3. Locate and load the IO.SYS file
4. Transfer control to the secondary bootloader

#### Structure and Implementation

**Startup Sequence (_start function)**
```c
// Disable interrupts to prevent interference during setup
asm("cli");

// Initialize segment registers (clear to 0 for simplicity)
asm("xor %ax, %ax\n\t mov %ax, %ds\n\t mov %ax, %ss");

// Set stack pointer to 0x7C00 (grows downward from boot sector)
asm("mov $0x7c00, %sp");

// Save the drive number passed by BIOS in DL register
// This identifies which disk we're booting from
```

**FAT16 Parsing Algorithm**

The boot sector contains the FAT16 boot record in the first 62 bytes, containing critical filesystem metadata:

```c
// Key FAT fields parsed:
uint16_t bytes_per_sector;        // Usually 512
uint8_t sectors_per_cluster;      // Usually 1 for large disks
uint16_t reserved_sectors;        // FAT boot sector(s)
uint8_t num_fats;                 // Usually 2 (redundant FATs)
uint16_t sectors_per_fat;         // FAT table size
uint16_t root_entries;            // Max files in root directory
```

**File Search Process**

```
1. Calculate Root Directory Location:
   root_sector = reserved_sectors + (num_fats × sectors_per_fat)

2. Calculate Root Directory Size:
   root_dir_sectors = CEIL((root_entries × 32) / bytes_per_sector)

3. Load Root Directory Sectors:
   For each sector in root directory:
      - Load 512 bytes into buffer at 0x0700
      - Each sector contains 16 directory entries (512 / 32)
      - Compare each 8-byte filename with "IO      SYS"

4. Directory Entry Structure (32 bytes):
   Offset  Size  Field
   ──────  ────  ─────────────────────
   0       8     Filename (8.3 format, space-padded)
   8       3     File extension
   11      1     Attributes
   12      10    Reserved/timing info
   26      2     First cluster number (FAT table entry)
   28      4     File size in bytes
```

**File Loading with LBA**

When "IO.SYS" is found, the bootloader:

```c
// Get first cluster from directory entry
uint16_t first_cluster = dir_entry->first_cluster_low;

// Calculate absolute sector number
// Clusters are numbered starting from 2
// Data area begins after root directory
uint32_t file_sector = root_dir_sector + root_dir_sectors
                     + (first_cluster - 2) * sectors_per_cluster;

// Load sectors using extended INT 0x13 AH 0x42
// Packet structure (for INT 0x13 AH 0x42):
struct disk_address_packet {
    uint8_t size;              // 0x10
    uint8_t reserved;
    uint16_t sectors_to_read;  // Load 3 sectors for IO.SYS
    uint16_t buffer_offset;    // 0x0700
    uint16_t buffer_segment;   // 0x0000
    uint64_t lba_address;      // Absolute sector number
};
```

**Control Transfer**

```c
// Once IO.SYS is loaded at 0x0700, jump to it
// Using 16-bit far jump: segment:offset addressing
asm("ljmp $0, $0x0700");  // Jump to 0x0000:0x0700
```

#### Embedded FAT16 Header

The boot sector embeds the complete FAT16 boot record (62 bytes):
- **Bytes 0-2**: x86 JMP instruction to skip FAT header
- **Bytes 3-61**: FAT16 BIOS Parameter Block (BPB)
- **Bytes 62-509**: Boot code
- **Bytes 510-511**: Boot signature (0xAA55)

This allows the boot sector to be directly executable AND recognized as a valid FAT16 boot sector by tools.

#### Error Handling

The bootloader handles failures gracefully:
```c
// If "IO.SYS" is not found:
// 1. Print error character 'N'
// 2. Execute HLT instruction (infinite halt loop)
// 3. System dead without crash messages that might corrupt state
```

---

### 2. Secondary Bootloader (io.c)

**File**: `io.c`
**Compiled Output**: `io.elf` / `io.sys` (binary)
**Linker Script**: `io.ld`
**Load Address**: `0x0700` (determined by stage 1)
**Maximum Size**: 1536 bytes (3 sectors × 512 bytes)

#### Purpose

The secondary bootloader (IO.SYS) represents the second stage of boot. Currently it's a proof-of-concept that demonstrates:
1. Successful stage 1 to stage 2 transfer
2. Continued access to BIOS services
3. Extensibility for future functionality

#### Current Implementation

The current `io.c` is intentionally minimal:

```c
// Print a message indicating successful load
putchar('L');  // Print 'L' via INT 0x10
putchar('O');  // Print 'O'
putchar('\n'); // Print newline

// Demonstrate memory access
// Dump memory around boot sector location
uint8_t *memory = (uint8_t *)0x7C00;
for (int i = 0; i < 16; i++) {
    print_hex(memory[i]);
}

// Halt
asm("hlt");
```

#### Future Potential

Future versions could implement:
- **FAT filesystem navigation**: Directory traversal, kernel loading
- **DOS services**: INT 0x21 services emulation
- **Protected mode**: Transition to 32-bit mode
- **Kernel loading**: Load and execute OS kernel
- **Configuration**: Read boot.ini or similar config files

---

### 3. Linker Scripts

#### boot.ld (Boot Sector)

**Purpose**: Link boot.o into a 512-byte bootloader with proper memory layout

```ld
/* Bootloader loads at 0x7C00 - BIOS standard */
ENTRY(_start)

SECTIONS {
  . = 0x7C00;

  /* Code section */
  .text : {
    *(.text.start)     /* Entry point first */
    *(.text)
    *(.rodata)
  }

  /* Data sections */
  .data : { *(.data) }
  .bss : { *(.bss) }

  /* Boot signature at exactly 0x7DFE */
  . = 0x7DFE;
  .signature : { LONG(0xAA55) }

  /* Validate size */
  ASSERT(. <= 0x7E00, "Bootloader too large!");
}
```

**Key Features**:
- Fixes entry point at 0x7C00
- Enforces 510-byte maximum via ASSERT
- Places boot signature at exact offset
- Combines all sections (.text, .rodata, .data, .bss)

#### io.ld (IO.SYS)

**Purpose**: Link io.o into a 3-sector secondary bootloader

```ld
ENTRY(_start)

SECTIONS {
  . = 0x0700;

  .text : {
    *(.text.start)
    *(.text)
    *(.rodata)
  }

  .data : { *(.data) }
  .bss : { *(.bss) }

  /* Enforce 3-sector (1536 byte) limit */
  ASSERT(. <= 0x0700 + 0x600, "IO.SYS too large!");
}
```

**Key Features**:
- Fixes load address at 0x0700
- Ensures .text.start is first (entry point)
- Enforces 3-sector maximum
- Separate from boot sector layout

---

### 4. Python Emulator (emulator.py)

**File**: `emulator.py`
**Lines of Code**: ~838
**Purpose**: Execute bootloader with instruction-level tracing
**Dependencies**: Unicorn (CPU emulator), Capstone (disassembler)

#### Architecture

The emulator provides step-by-step execution with detailed tracing:

```python
class BootloaderEmulator:
    """
    Unicorn-based x86 real-mode emulator for bootloader execution.

    Provides:
    - Real-mode addressing (segment << 4 + offset)
    - BIOS interrupt emulation (INT 0x10, INT 0x13)
    - Disk image loading and CHS/LBA geometry detection
    - Instruction-level tracing with register tracking
    - Memory access logging
    """
```

#### Key Components

**Initialization**
```python
def __init__(self, bootloader_file, disk_image=None, **options):
    """
    Initialize emulator with bootloader and optional disk image.

    Args:
        bootloader_file: Path to bootloader binary (512 bytes)
        disk_image: Optional disk image for disk I/O emulation
        max_instructions: Limit execution (default: 1,000,000)
        geometry: Override disk geometry (chs or floppy type)
    """
    self.uc = uc.Uc(uc.UC_ARCH_X86, uc.UC_MODE_16)
    self.setup_memory()
    self.load_bootloader(bootloader_file)
    if disk_image:
        self.load_disk_image(disk_image)
```

**Memory Setup**
```python
def setup_memory(self):
    """
    Map 1 MB of RAM for real-mode operation.

    Real-mode addressing:
    - Physical address = (segment << 4) + offset
    - Maximum addressable: 0xFFFFF (1 MB)
    """
    self.uc.mem_map(0, 0x100000)  # 1 MB mapping
    self.uc.mem_write(0x7C00, bootloader_code)  # Boot sector at 0x7C00
```

**Disk Geometry Detection**

The emulator intelligently detects disk geometry to match QEMU:

```python
def detect_geometry(self):
    """
    Determine disk CHS geometry from image size or MBR.

    Priority:
    1. Manual override from command line
    2. Floppy type override (1.44MB, 2.88MB, etc.)
    3. Auto-detect standard floppy sizes
    4. Parse MBR partition table
    5. Fallback: 16 heads, 63 sectors/track

    Returns: (cylinders, heads, sectors_per_track)
    """
```

**Instruction Tracing**

Every instruction is logged with relevant context:

```
Format: address|mnemonic operands|register=value|mem[address]=value

Example output:
0x7c00|cli
0x7c01|xor ax, ax|ax=0x0
0x7c03|mov ds, ax|ds=0x0
0x7c05|mov ss, ax|ss=0x0
0x7c07|mov sp, 0x7c00|sp=0x7c00
0x7c0a|sti
```

**Smart Register Tracking**

The emulator only displays registers modified by instructions:

```python
def hook_code(self, uc, address, size, user_data):
    """
    Hook called for each instruction execution.

    1. Disassemble instruction using Capstone
    2. Identify registers touched by instruction
    3. Log registers that changed
    4. Track memory accesses
    5. Handle special instructions (INT, HLT)
    """
    # Only show registers touched by this instruction
    # This keeps trace output concise and readable
```

**BIOS Interrupt Emulation**

```python
def hook_interrupt(self, uc, intno, user_data):
    """
    Handle BIOS interrupts (INT 0x10, INT 0x13, etc.)
    """

    if intno == 0x10:  # Video services
        self.handle_int10()
    elif intno == 0x13:  # Disk services
        self.handle_int13()
```

#### INT 0x10 Emulation (Video Services)

```python
def handle_int10(self):
    """
    INT 0x10: Video and teletype services.

    Supported:
    - AH=0x0E: Teletype output (print character)
      AL = character
      BH = video page (ignored)
      Output: Write AL to console
    """
```

#### INT 0x13 Emulation (Disk Services)

```python
def handle_int13(self):
    """
    INT 0x13: Disk I/O services.

    Supported:
    - AH=0x08: Get drive parameters
      Input: DL = drive number
      Output: DH = max head, CL = sectors/track, CH = max cylinder

    - AH=0x42: Extended LBA read (requires packet)
      Input: DS:SI = disk address packet
      Packet format:
        Offset 0: size (0x10)
        Offset 2: sectors to read
        Offset 4: buffer address (segment:offset)
        Offset 8: LBA address (64-bit)
      Output: Read sectors from disk image to buffer
    """
```

#### Execution Engine

```python
def run(self):
    """
    Execute bootloader until:
    - HLT instruction (normal termination)
    - Invalid memory access
    - Invalid instruction
    - Instruction limit reached

    Returns: Execution status and statistics
    """
    self.uc.emu_start(0x7C00, 0x7DFF)  # Execute in boot sector address range
```

#### Output Generation

```python
def print_summary(self):
    """
    Generate execution statistics and summary.

    Includes:
    - Total instructions executed
    - INT calls by interrupt number
    - Memory reads/writes
    - Final register state
    - Execution time
    """
```

---

### 5. Build System (Makefile)

**File**: `Makefile`
**Purpose**: Automate compilation, linking, and testing

#### Key Build Targets

| Target | Purpose | Output |
|--------|---------|--------|
| `all` | Default: build QEMU image | `boot.qcow2` |
| `boot` | Compile bootloader | `boot.elf`, `boot` binary |
| `io.sys` | Compile secondary stage | `io.elf`, `io.sys` binary |
| `boot.img` | Create FAT16 disk image | `boot.img` (raw image) |
| `boot.qcow2` | Convert to QEMU format | `boot.qcow2` (compressed) |
| `run` | Execute in QEMU | Runs bootloader |
| `debug` | Run in QEMU with GDB stub | Port 1234 available for GDB |
| `disasm` | Disassemble bootloader | Intel syntax assembly listing |
| `rebuild` | Clean + all | Full rebuild |
| `dostest.img` | Create DOS test image | Requires dos622/ directory |
| `clean` | Remove artifacts | Deletes binaries and images |

#### Compilation Flow

**Boot Sector Compilation**
```makefile
boot.o: boot.c
	ia16-elf-gcc -c $(CFLAGS) boot.c -o boot.o

boot.elf: boot.o boot.ld
	ia16-elf-ld -T boot.ld boot.o -o boot.elf --Map=boot.map

boot: boot.elf
	ia16-elf-objcopy -O binary boot.elf boot
```

**IO.SYS Compilation**
```makefile
io.o: io.c
	ia16-elf-gcc -c $(CFLAGS) io.c -o io.o

io.elf: io.o io.ld
	ia16-elf-ld -T io.ld io.o -o io.elf

io.sys: io.elf
	ia16-elf-objcopy -O binary io.elf io.sys
```

**Disk Image Creation**
```makefile
boot.img: boot io.sys
	# Create empty FAT16 image with boot sector
	mformat -C -f 1440 -L boot.img

	# Write boot sector (includes FAT header)
	dd if=boot of=boot.img conv=notrunc bs=1 count=512

	# Add IO.SYS file to FAT filesystem
	mcopy -i boot.img io.sys ::IO.SYS

boot.qcow2: boot.img
	qemu-img convert -f raw -O qcow2 boot.img boot.qcow2
```

#### Compiler Flags

```makefile
CFLAGS = -ffreestanding -nostdlib -O1 -Wall
  -ffreestanding   # No standard library, standalone code
  -nostdlib        # No C runtime
  -O1              # Minimal optimization (preserve clarity)
  -Wall            # All warnings

LDFLAGS = --no-warn-rwx-segments -T
  --no-warn-rwx-segments  # Bootloaders have RWX sections
  -T                      # Specify linker script
```

---

### 6. Development Environment

#### Devcontainer Configuration

**File**: `.devcontainer/devcontainer.json`

```json
{
  "name": "x86 Real-Mode Bootloader",
  "image": "ghcr.io/mrexodia/x86-real-mode-bootloader:latest",
  "features": {
    "ghcr.io/devcontainers/features/python:1": {}
  },
  "customizations": {
    "vscode": {
      "extensions": ["ms-python.python"]
    }
  }
}
```

**Benefits**:
- **Reproducibility**: Same environment across all machines
- **Cloud Support**: GitHub Codespaces integration
- **Multi-platform**: Works on macOS, Linux, Windows
- **Pre-configured**: All tools pre-installed

#### Dockerfile

**File**: `.devcontainer/Dockerfile`

**Base**: Ubuntu 24.04
**Toolchain Installation**:
- `gcc-ia16`: Cross-compiler for 16-bit x86
- `binutils`: Assembler, linker, object tools
- `mtools`: FAT filesystem manipulation
- `qemu`: Virtual machine emulator
- `gdb`: Debugger with 16-bit support

**Python Environment**:
- `unicorn`: CPU emulation library
- `capstone`: Disassembly engine

#### GitHub Actions Workflow

**File**: `.github/workflows/emulator-trace.yml`

```yaml
on: [push, pull_request]

jobs:
  emulator-trace:
    runs-on: ubuntu-latest
    container:
      image: ghcr.io/mrexodia/x86-real-mode-bootloader:latest

    steps:
      - Checkout code
      - Compile simple_boot.asm (NASM)
      - Compile boot.c and io.c
      - Run emulator on simple_boot.bin
      - Run emulator on boot with boot.img
      - Upload trace artifacts
      - Display statistics
```

**Artifacts**: Execution traces retained for 30 days

---

## Boot Process Flow

### Step-by-Step Execution

```
┌─────────────────────────────────────────┐
│   BIOS Power-On Self Test (POST)        │
└──────────────┬──────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────┐
│  BIOS Boot Device Selection              │
│  (Looks for bootable disks)              │
└──────────────┬──────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────┐
│  BIOS Loads First Sector (LBA 0)        │
│  - Read 512 bytes into RAM at 0x7C00    │
│  - Validate boot signature (0xAA55)     │
│  - Set DL = drive number (0x00 or 0x80) │
└──────────────┬──────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────┐
│  BIOS Jumps to 0x7C00                   │
│  - CPU in real mode, 16-bit             │
│  - No virtual memory, no segmentation   │
└──────────────┬──────────────────────────┘
               │
               ▼
     ╔═════════════════════════════════════╗
     ║  Stage 1: Boot Sector Execution     ║
     ║          (boot.c code)              ║
     ╚═════════════════════════════════════╝
               │
    ┌──────────┴──────────┐
    │                     │
    ▼                     │
┌────────────────────┐   │
│ Initialize Regs    │   │
│ • CLI (disable int)│   │
│ • xor ax, ax       │   │
│ • mov ds, ax       │   │
│ • mov ss, ax       │   │
│ • mov sp, 0x7c00   │   │
│ • STI (enable int) │   │
└────────────┬───────┘   │
             │           │
             ▼           │
┌────────────────────────────────────┐   │
│ Parse FAT16 Header (62 bytes)      │   │
│ • Read bytes_per_sector            │   │
│ • Read sectors_per_cluster         │   │
│ • Read num_fats                    │   │
│ • Read sectors_per_fat             │   │
│ • Read root_entries                │   │
└────────────┬───────────────────────┘   │
             │                           │
             ▼                           │
┌──────────────────────────────────────────┐
│ Calculate Root Directory Location        │
│ root_sector = reserved_sectors +         │
│              (num_fats × sectors_per_fat)│
│ root_size = CEIL((root_entries × 32) /   │
│            bytes_per_sector)             │
└────────────┬─────────────────────────────┘
             │                           │
             ▼                           │
┌──────────────────────────────────────────┐
│ Search Root Directory for "IO.SYS"       │
│ For each root directory sector:          │
│ • INT 0x13 AH 0x42: Load sector         │
│ • Parse 16 directory entries (32B each) │
│ • Compare filename at offset 0-7        │
│ • If match: Get first_cluster_low       │
└────────────┬─────────────────────────────┘
             │                           │
        Yes  │  No                       │
             ▼   │                       │
    ┌──────────┐ │                       │
    │ Found!   │ │                       │
    └────┬─────┘ │                       │
         │       ▼                       │
         │   ┌──────────┐                │
         │   │ Not Found│                │
         │   │ Print 'N'│                │
         │   │ HLT loop │                │
         │   └──────────┘                │
         │                               │
         ▼                               │
┌────────────────────────────────────────────┐
│ Calculate IO.SYS Sector Location          │
│ file_sector = root_sector +               │
│              root_size +                  │
│              (first_cluster - 2) ×        │
│              sectors_per_cluster          │
└────────────┬───────────────────────────────┘
             │                              │
             ▼                              │
┌────────────────────────────────────────────┐
│ Load IO.SYS with Extended LBA Read        │
│ INT 0x13 AH 0x42:                        │
│ • Create disk address packet at stack    │
│ • Set sectors_to_read = 3                │
│ • Set buffer address = 0x0700            │
│ • Set LBA address = file_sector          │
│ • BIOS loads 1536 bytes (3 sectors)      │
└────────────┬───────────────────────────────┘
             │                              │
             ▼                              │
┌────────────────────────────────────────────┐
│ Transfer Control to IO.SYS                │
│ Far jump: ljmp $0, $0x0700               │
│ CPU executes at 0x0000:0x0700            │
│ (Physical address 0x0700)                │
└────────────────────────────────────────────┘
             │
             ▼
    ╔═════════════════════════════════════╗
    ║ Stage 2: IO.SYS Execution           ║
    ║         (io.c code)                 ║
    ╚═════════════════════════════════════╝
             │
             ▼
┌────────────────────────────────────────────┐
│ IO.SYS Execution (Current Impl)           │
│ • Print 'L' via INT 0x10                  │
│ • Print 'O' via INT 0x10                  │
│ • Dump memory contents                    │
│ • HLT (halt processor)                    │
└────────────────────────────────────────────┘
```

### Critical Timing Points

| Point | Address | Segment | Offset | Description |
|-------|---------|---------|--------|-------------|
| BIOS loads | 0x00000 | 0x0000 | 0x7C00 | Boot sector entry |
| Boot stack | 0x07C00 | 0x0000 | 0x7C00 | Stack grows down |
| Root dir buf | 0x07000 | 0x0000 | 0x0700 | Sector reading buffer |
| IO.SYS load | 0x07000 | 0x0000 | 0x0700 | IO.SYS loaded here |
| Far jump | 0x07000 | 0x0000 | 0x0700 | Transfer control |

---

## Memory Layout

### During Boot Sector Execution

```
Address   Segment:Offset   Size    Content
──────────────────────────────────────────────────────
0x00000   0000:0000        64 KB   Interrupt vector table (IVT)
0x10000   1000:0000        ~48 KB  BIOS data area, free RAM
0x6F000   6F00:0000        ?       Free RAM (variable)
0x70000   7000:0000        4 KB    IO.SYS buffer (during search)
0x7C00    7C00:0000        512 B   Boot sector @ 0x7C00
0x7C00    (implied)        510 B   Boot code
0x7DFE    (implied)        2 B     Boot signature (0xAA55)
0x7E00                      ~8 KB   Unused/BIOS ROM

Addressing Mode in Real Mode:
Physical address = (Segment << 4) + Offset
Example: 0x1000:0x0500 = (0x1000 << 4) + 0x0500 = 0x10500
```

### Stack Layout

```
During Boot Execution:
SS=0x0000, SP=0x7C00

┌──────────────────┐  0x7C00
│  Stack pointer   │  ↓ (grows downward)
│   (empty)        │
│                  │  Available for local variables
│                  │  and function calls
│                  │
├──────────────────┤  0x7BFF (1 byte before SP)
```

**Stack Constraints:**
- Must not overwrite boot code (0x7C00-0x7DFF)
- Maximum ~31 KB available before overwriting IVT
- Typical boot code uses minimal stack

### Memory During Disk I/O

```
When loading root directory:
┌─────────────────┐  0x0700
│   Root Dir      │
│   Sector 1      │
│  (512 bytes)    │  Contains 16 directory entries
└─────────────────┘  0x0900

When loading IO.SYS:
┌─────────────────┐  0x0700
│   IO.SYS Sector 1
│   IO.SYS Sector 2   (1536 bytes total)
│   IO.SYS Sector 3
└─────────────────┘  0x0D00
```

---

## FAT16 Filesystem Implementation

### FAT16 Basics

FAT16 (File Allocation Table, 16-bit) is a simple filesystem that uses:
1. **Boot Sector**: Filesystem metadata and partition info
2. **FAT Table**: Linked-list of cluster chains
3. **Root Directory**: Fixed-size directory listing
4. **Data Area**: File data in clusters

### FAT16 Boot Sector Layout

```
Offset  Size   Field                Description
───────────────────────────────────────────────────────
0x00    3      JMP instruction      Jump over BPB
0x03    8      OEM name             Usually "MSDOS5.0"
0x0B    2      Bytes/sector         Typically 512
0x0D    1      Sectors/cluster      Typically 1-8
0x0E    2      Reserved sectors     Usually 1 (boot sector)
0x10    1      Number of FATs       Usually 2 (redundancy)
0x11    2      Root directory       Usually 224 or 512
        entries
0x13    2      Total sectors        Size of partition
0x15    1      Media descriptor     0xF8 = hard disk
0x16    2      Sectors per FAT      Size of FAT table
0x18    2      Sectors/track        Drive geometry
0x1A    2      Number of heads      Drive geometry
0x1C    4      Hidden sectors       Before partition start
0x20    4      Total sectors        If > 65535
0x24    1      Drive number         0x80 = C:, 0x00 = A:
0x25    1      Reserved             0x00
0x26    1      Boot signature       0x29 indicates extended
0x27    4      Volume serial        Serial number
0x2B    11     Volume label         11-byte label
0x36    8      Filesystem type      "FAT16   "
```

**In this project**: The boot sector IS the FAT16 boot sector. The first 62 bytes contain the FAT header, and bytes 62-509 contain boot code.

### Root Directory Entry Layout

```
Offset  Size   Field            Description
──────────────────────────────────────────────────
0x00    8      Filename         8 characters (padded)
0x08    3      Extension        3 characters (padded)
0x0B    1      Attributes       Flags: read-only, hidden, etc.
0x0C    10     Reserved         Timing and DOS compatibility info
0x16    2      First cluster    FAT cluster index
0x18    4      File size        Bytes in file
```

**Filename Format** (8.3):
- **Filename**: 8 characters, space-padded if shorter
- **Extension**: 3 characters, space-padded if shorter
- Example: "IO.SYS" → "IO      " + "SYS"

**Attributes Byte**:
```
Bit 0: Read-only
Bit 1: Hidden
Bit 2: System
Bit 3: Volume label
Bit 4: Directory
Bit 5: Archive
Bits 6-7: Reserved
```

### FAT Cluster Chain

Each entry in the FAT table is a 16-bit value pointing to the next cluster:

```
FAT Table Entry Values:
0x0000        Free cluster
0x0001        Reserved
0x0002-0xFFED Next cluster number in chain
0xFFF0-0xFFF6 Reserved
0xFFF7        Bad sector
0xFFF8-0xFFFF End of file marker (EOF)
```

**Example File Allocation**:
```
File "IO.SYS" starts at cluster 2

FAT Table:
  Cluster 0: 0xFFF8 (media descriptor, reserved)
  Cluster 1: 0xFFF8 (reserved)
  Cluster 2: 0x0003 → (points to cluster 3)
  Cluster 3: 0x0004 → (points to cluster 4)
  Cluster 4: 0xFFFF → (end of file)

Physical Disk Layout:
  Cluster 2 (sector N):     Bytes 0-511 of IO.SYS
  Cluster 3 (sector N+1):   Bytes 512-1023 of IO.SYS
  Cluster 4 (sector N+2):   Bytes 1024-1535 of IO.SYS
```

### File Search Algorithm (Implemented in boot.c)

```c
// 1. Calculate root directory sector
root_sector = boot_record.reserved_sectors
            + (boot_record.num_fats × boot_record.sectors_per_fat);

// 2. Calculate root directory size
root_dir_sectors = CEILING(
    (boot_record.root_entries × 32) / boot_record.bytes_per_sector
);

// 3. Search root directory
for (int sector = root_sector; sector < root_sector + root_dir_sectors; sector++) {
    // Load sector using INT 0x13 AH 0x42
    read_sector(sector, 0x0700);

    // Parse 16 directory entries per sector (512 bytes / 32 bytes)
    fat_dir_entry_t *entries = (fat_dir_entry_t *)0x0700;
    for (int i = 0; i < 16; i++) {
        if (entries[i].name matches "IO      SYS") {
            first_cluster = entries[i].first_cluster_low;
            goto found;
        }
    }
}
```

---

## BIOS Services

### INT 0x10 - Video Services

**Purpose**: Display output and video control

**Function AH=0x0E - Teletype Output**

Used by boot.c for printing characters:

```c
void putchar(char c) {
    asm volatile(
        "mov $0x0e, %%ah\n\t"    // AH = 0x0E (teletype)
        "mov %0, %%al\n\t"       // AL = character
        "xor %%bh, %%bh\n\t"     // BH = 0 (page 0)
        "int $0x10"              // Call INT 0x10
        :
        : "r"(c)
    );
}
```

**Calling Convention**:
- **Input**:
  - AH = 0x0E (function number)
  - AL = ASCII character to print
  - BH = video page (0)
  - BL = color (for graphics mode, 0 for text mode)
- **Output**: Character displayed on screen
- **Affected Registers**: None (BIOS preserves all)

**Usage in boot.c**:
```c
putchar('H');  // Print 'H'
putchar('e');  // Print 'e'
putchar('l');  // Print 'l'
putchar('l');  // Print 'l'
putchar('o');  // Print 'o'
```

---

### INT 0x13 - Disk Services

**Purpose**: Low-level disk I/O operations

**Function AH=0x08 - Get Drive Parameters**

Detects disk geometry:

```c
uint8_t get_drive_params(uint8_t drive) {
    uint16_t params;
    asm volatile(
        "mov $0x08, %%ah\n\t"    // AH = 0x08 (get drive params)
        "mov %1, %%dl\n\t"       // DL = drive number
        "int $0x13"              // Call INT 0x13
        : "=d"(params)
        : "r"(drive)
    );
    // DH = max head number
    // CL = sectors per track (bits 5-0)
    // CH = max cylinder number (low 8 bits)
}
```

**Calling Convention**:
- **Input**:
  - AH = 0x08
  - DL = drive number (0x00-0x7F = floppy, 0x80+ = hard disk)
- **Output**:
  - CF = 0 if success, 1 if error
  - DH = maximum head number (0-based)
  - CL = maximum sector number (1-based, in bits 5-0)
  - CH = maximum cylinder number (low 8 bits)

---

**Function AH=0x42 - Extended LBA Read**

Loads sectors from disk using Logical Block Addressing:

```c
struct disk_address_packet {
    uint8_t size;              // 0x10 (16 bytes)
    uint8_t reserved;          // 0x00
    uint16_t sectors_to_read;  // Number of sectors to load
    uint16_t buffer_offset;    // Buffer address (offset)
    uint16_t buffer_segment;   // Buffer address (segment)
    uint64_t lba_address;      // Logical Block Address (LBA)
};

void read_sectors(uint32_t lba, uint16_t count, uint16_t segment, uint16_t offset) {
    struct disk_address_packet packet = {
        .size = 0x10,
        .reserved = 0,
        .sectors_to_read = count,
        .buffer_offset = offset,
        .buffer_segment = segment,
        .lba_address = lba
    };

    asm volatile(
        "mov $0x42, %%ah\n\t"    // AH = 0x42 (extended read)
        "mov %0, %%dl\n\t"       // DL = drive number
        "mov %1, %%si\n\t"       // SI = packet address
        "int $0x13"              // Call INT 0x13
        :
        : "r"(drive), "r"(&packet)
    );
}
```

**Calling Convention**:
- **Input**:
  - AH = 0x42
  - DL = drive number
  - DS:SI = pointer to disk address packet
- **Disk Address Packet**:
  - Offset 0: Size (0x10 for basic packet)
  - Offset 2: Sectors to read (16-bit count)
  - Offset 4: Buffer segment
  - Offset 6: Buffer offset
  - Offset 8: LBA address (64-bit little-endian)
- **Output**:
  - CF = 0 if success, 1 if error
  - AH = status (0 if success)
  - Sectors loaded into memory at DS:SI buffer

**Advantages over CHS Read (AH=0x02)**:
- No need for sector/head/cylinder calculations
- Supports large disks (>8 GB)
- Simpler error handling
- BIOS handles LBA to CHS translation internally

---

## Build System

### Compilation Process

**Step 1: Preprocess and Compile C to Assembly**
```bash
ia16-elf-gcc -c -ffreestanding -nostdlib -O1 -Wall boot.c -o boot.o
```

- Preprocesses (handles `#include`, `#define`)
- Compiles to x86 real-mode assembly
- Generates object file with symbols

**Step 2: Link Object Files**
```bash
ia16-elf-ld -T boot.ld boot.o -o boot.elf --Map=boot.map
```

- Reads linker script (`boot.ld`)
- Resolves symbols between objects
- Assigns addresses (0x7C00 for boot sector)
- Validates size constraints
- Generates symbol map file

**Step 3: Extract Binary**
```bash
ia16-elf-objcopy -O binary boot.elf boot
```

- Removes ELF headers, debug info, symbol tables
- Creates raw binary suitable for disk boot

### Linker Script Directives

```ld
/* Set entry point */
ENTRY(_start)

SECTIONS {
  /* Place code at exact address */
  . = 0x7C00;

  /* Code and read-only data */
  .text : {
    *(.text.start)    /* Start section first */
    *(.text)          /* Rest of code */
    *(.rodata)        /* Read-only data */
  }

  /* Initialized data */
  .data : { *(.data) }

  /* Uninitialized data */
  .bss : { *(.bss) }

  /* Boot signature at 510-511 */
  . = 0x7DFE;
  .signature : { LONG(0xAA55) }

  /* Enforce maximum size */
  ASSERT(. <= 0x7E00, "Bootloader exceeds 512 bytes!")
}
```

**Key Directives**:
- `. = address`: Set location counter
- `*(.section)`: Include section from all objects
- `ENTRY(symbol)`: Set entry point
- `LONG(value)`: Insert 32-bit value
- `ASSERT()`: Compile-time assertion

### Disk Image Creation

**Step 1: Create FAT16 Filesystem**
```bash
mformat -C -f 1440 -L boot.img
```

- Creates FAT16 image file
- `-C`: Create new image
- `-f 1440`: 1440 KB floppy size (1.44 MB)
- `-L boot.img`: Output filename

**Step 2: Write Boot Sector**
```bash
dd if=boot of=boot.img conv=notrunc bs=1 count=512
```

- Copies boot sector to image start
- `conv=notrunc`: Don't truncate output file
- `bs=1`: Byte-by-byte copy
- `count=512`: Copy exactly 512 bytes

**Step 3: Add File to Filesystem**
```bash
mcopy -i boot.img io.sys ::IO.SYS
```

- Copies io.sys into FAT filesystem
- `-i boot.img`: Image file to modify
- `::IO.SYS`: Destination on virtual filesystem

**Step 4: Convert to QEMU Format**
```bash
qemu-img convert -f raw -O qcow2 boot.img boot.qcow2
```

- Converts raw image to QEMU format
- `-f raw`: Input format (raw binary)
- `-O qcow2`: Output format (QEMU compressed)
- Reduces file size via compression

---

## Testing Infrastructure

### Python Emulator Features

#### 1. Real-Mode Execution

The emulator accurately simulates x86 real-mode operation:

```python
# Physical address = (Segment << 4) + Offset
physical_addr = (segment << 4) + offset
```

**Segment Registers Supported**:
- CS: Code segment
- DS: Data segment
- ES: Extra segment
- SS: Stack segment

---

#### 2. Instruction Tracing

Every instruction generates a trace line:

```
Format: address|mnemonic|operands|register_updates|memory_accesses

Example:
0x7c00|cli
0x7c01|xor ax, ax|ax=0x0
0x7c03|mov ds, ax|ds=0x0, ea=0x7d02
0x7c05|mov ss, ax|ss=0x0
```

**Trace Analysis Tools**:
- Filter by address range
- Search for specific instructions
- Track register changes
- Identify memory access patterns

---

#### 3. Disk Image Loading

Automatically detects and loads disk images:

```python
# Geometry detection priority:
1. Command-line override
2. Floppy type specification
3. Auto-detect standard sizes
4. Parse MBR partition table
5. Default: 16H × 63S/T
```

**Supported Formats**:
- Raw binary images (.img, .bin)
- QEMU images (.qcow2)
- Floppy images (1.44 MB, 2.88 MB, etc.)
- Hard disk images

---

#### 4. BIOS Interrupt Handling

Emulates critical BIOS services:

**INT 0x10 AH=0x0E (Teletype)**
- Captures all printed characters
- Displays output to console
- Logs characters in trace

**INT 0x13 AH=0x08 (Get Drive Parameters)**
- Returns simulated disk geometry
- Matches QEMU defaults
- Enables FAT parsing in emulator

**INT 0x13 AH=0x42 (Extended LBA Read)**
- Reads from disk image
- Updates memory with sector data
- Simulates real disk I/O timing

---

### CI/CD Integration

**GitHub Actions Workflow** (`.github/workflows/emulator-trace.yml`)

```yaml
on:
  push:
    branches: [master, main]
  pull_request:
    branches: [master, main]

jobs:
  emulator-trace:
    runs-on: ubuntu-latest
    steps:
      # Compile test bootloader
      - run: nasm -f bin simple_boot.asm -o simple_boot.bin

      # Compile main bootloader
      - run: make boot io.sys boot.img

      # Run emulator (generates trace)
      - run: python3 emulator.py boot -d boot.img -o trace.txt

      # Upload artifacts
      - uses: actions/upload-artifact@v3
        with:
          name: emulator-traces
          path: "*.txt"
          retention-days: 30

      # Display statistics
      - run: |
          echo "Instructions: $(grep -c '^0x' trace.txt)"
          grep '\[INT' trace.txt | sort | uniq -c
```

**Benefits**:
- Automated testing on every commit
- Detects regressions immediately
- Preserves execution traces for analysis
- Provides execution statistics

---

## Development Workflow

### Building the Project

**Quick Start**:
```bash
# Build everything
make all

# Build individual components
make boot          # Build boot sector
make io.sys        # Build secondary bootloader
make boot.img      # Create disk image
make boot.qcow2    # Create QEMU image
```

**Rebuild**:
```bash
# Clean and rebuild
make rebuild
```

### Running Bootloader

**In QEMU (Graphical)**:
```bash
make run
```

This boots the image in QEMU with visual output.

**In QEMU (Headless)**:
```bash
make run  # (already -nographic by default)
```

**With GDB Debugger**:
```bash
# Terminal 1: Start QEMU with GDB stub
make debug

# Terminal 2: Connect GDB
gdb
(gdb) source real-mode.gdb
(gdb) target remote localhost:1234
(gdb) continue
(gdb) break *0x7c00   # Breakpoint at boot sector
(gdb) state16         # Show 16-bit registers
```

### Using the Emulator

**Basic Execution**:
```bash
python3 emulator.py boot -d boot.img
```

**With Output File**:
```bash
python3 emulator.py boot -d boot.img -o trace.txt
```

**Limited Instructions**:
```bash
python3 emulator.py boot -d boot.img -m 10000
```

**Quiet Mode**:
```bash
python3 emulator.py boot -d boot.img -q
```

**Custom Geometry**:
```bash
python3 emulator.py boot -d boot.img --geometry 65,16,63
```

### Debugging Workflow

**1. Run Emulator and Capture Trace**:
```bash
python3 emulator.py boot -d boot.img -o trace.txt
```

**2. Analyze Trace**:
```bash
# Find where execution jumps
grep "ljmp\|jmp\|call\|ret" trace.txt

# Track register changes
grep "ax=" trace.txt

# Find INT calls
grep "\[INT" trace.txt
```

**3. Compare with Disassembly**:
```bash
make disasm
# Review boot.disasm for instructions at specific addresses
```

**4. Verify FAT Parsing**:
```bash
# Check root directory search
grep -E "0x[0-9a-f]*0[89ab]" trace.txt

# Verify cluster calculation
grep "0x0" trace.txt | head -20
```

---

## Technical Innovations

### 1. True 16-Bit Code Generation

**Problem**: Most modern bootloaders are compiled as 32-bit code with 0x66 size-override prefixes to run in real mode.

**Solution**: Use `gcc-ia16` to generate native 16-bit x86 instructions.

**Advantages**:
- Smaller code size
- Faster execution
- More efficient
- Cleaner disassembly

**Example**:
```c
// This generates true 16-bit:
uint16_t ax = 0;  // `xor ax, ax` (2 bytes)

// Not:
uint32_t eax = 0; // `xor eax, eax` with 0x66 prefix (3-4 bytes)
```

---

### 2. FAT16 Boot Sector Design

**Innovation**: Boot sector IS the FAT16 boot sector

**Traditional Approach**:
```
Sector 0: MBR (partition table)
Sector 1: Boot code (separate from FAT)
```

**This Project**:
```
Sector 0: Hybrid FAT16 boot sector + code
- Bytes 0-62: FAT16 BIOS Parameter Block
- Bytes 62-509: Boot code
- Bytes 510-511: Boot signature
```

**Benefits**:
- Single sector bootloader
- No MBR required
- Directly compatible with FAT16 filesystem tools
- Simpler disk image creation

---

### 3. Comprehensive Development Container

**Innovation**: Complete devcontainer with all tools pre-installed

**Includes**:
- gcc-ia16 toolchain
- QEMU emulator
- Python emulation environment
- GDB with 16-bit support
- All necessary build tools

**Benefits**:
- Works on any OS (macOS, Linux, Windows)
- GitHub Codespaces support
- Reproducible builds
- No installation hassles

---

### 4. Python-Based Instruction Emulator

**Innovation**: Hybrid Unicorn + Capstone + custom BIOS stubs

**Architecture**:
```
Unicorn Engine (CPU execution)
         │
         ├─► Capstone (disassembly)
         │
         └─► Custom BIOS stubs (INT 0x10, INT 0x13)
                    │
                    └─► Flat text trace output
```

**Benefits**:
- Step-by-step execution visibility
- Accurate real-mode emulation
- Deterministic (reproducible)
- Easy log analysis
- No QEMU overhead

---

### 5. Intelligent Register Tracking

**Innovation**: Trace only shows registers modified by each instruction

**Algorithm**:
```python
for each instruction:
    1. Disassemble with Capstone
    2. Extract operand register references
    3. Read register values before execution
    4. Execute instruction
    5. Compare register values after
    6. Log only changed registers
```

**Result**: Concise, readable traces

```
Bad (shows all registers):
0x7c01|xor ax, ax|ax=0|bx=0|cx=0|dx=0|si=0|di=0|sp=0|bp=0

Good (shows only changed):
0x7c01|xor ax, ax|ax=0
```

---

### 6. Automatic Disk Geometry Detection

**Innovation**: Multi-level detection matching QEMU behavior

**Detection Priority**:
```
1. Manual override from CLI
2. Floppy type override
3. Auto-detect standard sizes
4. Parse MBR partition table
5. Fallback defaults
```

**Ensures**:
- Bootloader runs identically in emulator and QEMU
- No manual geometry configuration needed
- Supports all disk types

---

## Summary

This x86 real-mode bootloader project demonstrates:

1. **Modern C in Bootloaders**: Using gcc-ia16 for true 16-bit code generation
2. **Complete Toolchain**: From source to bootable disk image
3. **Educational Value**: Clear implementation of FAT16 filesystem
4. **Professional Workflow**: Containerization, CI/CD, debugging tools
5. **Emulation Platform**: Detailed execution visibility and testing

The architecture balances simplicity (for educational purposes) with technical correctness (real FAT16 parsing, actual BIOS services), making it an excellent reference implementation for x86 boot processes.

