#!/usr/bin/env python3
"""
x86 Real Mode Bootloader Emulator using Unicorn Engine and Capstone

This emulator loads a disk image and emulates the bootloader from the first 512 bytes,
logging every instruction execution with relevant registers and memory accesses.
"""

import sys
import struct
import argparse
from pathlib import Path
from collections import OrderedDict

from unicorn import * # type: ignore
from unicorn.x86_const import * # type: ignore

from capstone import * # type: ignore
from capstone.x86_const import * # type: ignore

class BootloaderEmulator:
    """Emulator for x86 real mode bootloaders using Unicorn Engine"""

    def __init__(self, disk_image_path, max_instructions=1000000, trace_file="trace.txt", verbose=True,
                 geometry=None, floppy_type=None, drive_number=0x80):
        """
        Initialize the emulator

        Args:
            disk_image_path: Path to disk image file (bootloader loaded from first 512 bytes)
            max_instructions: Maximum number of instructions to execute
            trace_file: Output file for instruction trace
            verbose: Enable verbose console output
            geometry: Manual CHS geometry as (cylinders, heads, sectors_per_track) tuple
            floppy_type: Standard floppy type ('360K', '720K', '1.2M', '1.44M', '2.88M')
            drive_number: BIOS drive number (0x00-0x7F for floppy, 0x80+ for HDD)
        """
        self.disk_image_path = Path(disk_image_path)
        self.max_instructions = max_instructions
        self.trace_file = trace_file
        self.verbose = verbose
        self.drive_number = drive_number
        self.manual_geometry = geometry
        self.floppy_type = floppy_type

        # CHS geometry (will be detected later)
        self.cylinders = 0
        self.heads = 0
        self.sectors_per_track = 0
        self.geometry_method = "Unknown"

        # Boot sector is loaded at 0x7C00
        self.boot_address = 0x7C00

        # Memory configuration for real mode (1MB)
        self.memory_base = 0x0000
        self.memory_size = 0x100000  # 1 MB

        # Initialize Unicorn for x86 16-bit real mode
        print(f"[*] Initializing Unicorn Engine (x86 16-bit real mode)...")
        self.uc = Uc(UC_ARCH_X86, UC_MODE_16)

        # Initialize Capstone for disassembly
        self.cs = Cs(CS_ARCH_X86, CS_MODE_16)
        self.cs.detail = True  # Enable detailed instruction info

        # Execution tracking
        self.instruction_count = 0
        self.trace_output = None
        self.last_exception = None
        self.screen_output = ""

        # Disk emulation

        self.setup_memory()
        self.load_disk_image()
        self.load_bootloader()

    def setup_memory(self):
        """Set up memory regions for the emulator"""
        print(f"[*] Setting up memory...")

        # Map main memory (1 MB for real mode)
        self.uc.mem_map(self.memory_base, self.memory_size, UC_PROT_ALL)

        # Zero out memory
        self.mem_write(self.memory_base, b'\x00' * self.memory_size)

        print(f"  - Mapped {self.memory_size // 1024} KB at 0x{self.memory_base:08X}")

    def detect_geometry(self):
        """
        Detect disk geometry following QEMU's algorithm:
        1. Manual override (if specified)
        2. Floppy type override (if specified)
        3. Floppy auto-detect (if drive < 0x80 and size matches)
        4. MBR partition table (extract from ending CHS)
        5. Fallback: 16 heads, 63 sectors/track (QEMU default)
        """
        # Standard floppy geometries (size_bytes: (cylinders, heads, sectors, name))
        FLOPPY_TYPES = {
            '360K':  (40, 2, 9,  360 * 1024),
            '720K':  (80, 2, 9,  720 * 1024),
            '1.2M':  (80, 2, 15, 1200 * 1024),
            '1.44M': (80, 2, 18, 1440 * 1024),
            '2.88M': (80, 2, 36, 2880 * 1024),
        }

        total_sectors = self.disk_size // 512

        # Method 1: Manual geometry override
        if self.manual_geometry:
            self.cylinders, self.heads, self.sectors_per_track = self.manual_geometry
            self.geometry_method = "Manual override"
            return

        # Method 2: Floppy type override
        if self.floppy_type:
            c, h, s, _ = FLOPPY_TYPES[self.floppy_type]
            self.cylinders = c
            self.heads = h
            self.sectors_per_track = s
            self.geometry_method = f"Floppy type {self.floppy_type}"
            return

        # Method 3: Floppy auto-detect (if drive is floppy and size matches)
        if self.drive_number < 0x80:
            for floppy_name, (c, h, s, size) in FLOPPY_TYPES.items():
                if self.disk_size == size:
                    self.cylinders = c
                    self.heads = h
                    self.sectors_per_track = s
                    self.geometry_method = f"Auto-detected floppy {floppy_name}"
                    return

        # Method 4: MBR partition table (QEMU's guess_disk_lchs algorithm)
        # Read first 512 bytes (MBR)
        if len(self.disk_image) >= 512:
            mbr = self.disk_image[:512]

            # Check for valid MBR signature (0x55AA at offset 510-511)
            if mbr[510] == 0x55 and mbr[511] == 0xAA:
                # Examine partition entries (4 entries starting at offset 0x1BE)
                for i in range(4):
                    offset = 0x1BE + (i * 16)
                    entry = mbr[offset:offset + 16]

                    # Check if partition entry has valid data (non-zero partition type)
                    part_type = entry[4]
                    if part_type != 0:
                        # Extract ending CHS values
                        end_head = entry[5]
                        end_sector = entry[6] & 0x3F  # Lower 6 bits
                        end_cyl_high = (entry[6] & 0xC0) << 2
                        end_cyl_low = entry[7]
                        end_cyl = end_cyl_high | end_cyl_low

                        # Calculate geometry from ending CHS
                        heads = end_head + 1
                        sectors = end_sector

                        # Validate (QEMU checks: cylinders between 1 and 16383)
                        if sectors > 0 and heads > 0:
                            cylinders = total_sectors // (heads * sectors)
                            if 1 <= cylinders <= 16383:
                                self.cylinders = cylinders
                                self.heads = heads
                                self.sectors_per_track = sectors
                                self.geometry_method = "MBR partition table"
                                return

        # Method 5: Fallback geometry (QEMU's guess_chs_for_size)
        # Default: 16 heads, 63 sectors/track
        self.heads = 16
        self.sectors_per_track = 63
        self.cylinders = total_sectors // (self.heads * self.sectors_per_track)
        if total_sectors % (self.heads * self.sectors_per_track) != 0:
            self.cylinders += 1
        self.geometry_method = "Fallback (QEMU default: 16H/63S)"

    def load_disk_image(self):
        """Load disk image"""
        print(f"[*] Loading disk image from {self.disk_image_path}...")

        if not self.disk_image_path.exists():
            print(f"Error: Disk image not found: {self.disk_image_path}")
            sys.exit(1)

        with open(self.disk_image_path, 'rb') as f:
            self.disk_image = f.read()

        self.disk_size = len(self.disk_image)
        print(f"  - Disk image size: {self.disk_size} bytes ({self.disk_size // 1024} KB)")

        # Detect disk geometry
        self.detect_geometry()
        print(f"[*] Disk geometry:")
        print(f"  - Cylinders: {self.cylinders}")
        print(f"  - Heads: {self.heads}")
        print(f"  - Sectors/Track: {self.sectors_per_track}")
        print(f"  - Total Sectors: {self.disk_size // 512}")
        print(f"  - Method: {self.geometry_method}")

        if self.disk_size < 512:
            print(f"Error: Disk image too small (must be at least 512 bytes)")
            sys.exit(1)

    def mem_write(self, address: int, data: bytes):
        self.uc.mem_write(address, data)
        self.uc.ctl_remove_cache(address, address + len(data))

    def load_bootloader(self):
        """Load the bootloader from the first 512 bytes of disk image at 0x7C00"""
        print(f"[*] Loading bootloader from disk image...")

        # Load boot sector from first 512 bytes of disk image
        bootloader_code = self.disk_image[:512]
        print(f"  - Loaded boot sector from disk image (512 bytes)")

        # Verify boot signature (0xAA55 at offset 510-511)
        signature = struct.unpack('<H', bootloader_code[510:512])[0]
        if signature == 0xAA55:
            print(f"  ✓ Valid boot signature: 0x{signature:04X}")
        else:
            print(f"  ⚠ Warning: Invalid boot signature: 0x{signature:04X} (expected 0xAA55)")

        # Load bootloader at 0x7C00
        self.mem_write(self.boot_address, bootloader_code)
        print(f"  - Loaded at 0x{self.boot_address:04X}")

    def setup_cpu_state(self):
        """Initialize CPU registers for boot"""
        print(f"[*] Setting up CPU state...")

        # Set instruction pointer to boot sector address
        self.uc.reg_write(UC_X86_REG_IP, self.boot_address)

        # Set up segments (all start at 0 in real mode)
        self.uc.reg_write(UC_X86_REG_CS, 0x0000)
        self.uc.reg_write(UC_X86_REG_DS, 0x0000)
        self.uc.reg_write(UC_X86_REG_ES, 0x0000)
        self.uc.reg_write(UC_X86_REG_SS, 0x0000)

        # Set up stack at boot sector location
        self.uc.reg_write(UC_X86_REG_SP, self.boot_address)

        # Real mode typically boots with DL = drive number
        self.uc.reg_write(UC_X86_REG_DL, self.drive_number)

        # Clear other registers
        for reg in [UC_X86_REG_AX, UC_X86_REG_BX, UC_X86_REG_CX,
                    UC_X86_REG_SI, UC_X86_REG_DI, UC_X86_REG_BP]:
            self.uc.reg_write(reg, 0x0000)

        print(f"  - CS:IP: 0x{0x0000:04X}:0x{self.boot_address:04X}")
        print(f"  - SS:SP: 0x{0x0000:04X}:0x{self.boot_address:04X}")
        print(f"  - DL: 0x{self.drive_number:02X} (drive number)")

    def get_register_value(self, reg_name) -> int:
        """Get register value by name"""
        reg_map = {
            'ah': UC_X86_REG_AH, 'al': UC_X86_REG_AL, 'ax': UC_X86_REG_AX,
            'bh': UC_X86_REG_BH, 'bl': UC_X86_REG_BL, 'bx': UC_X86_REG_BX,
            'ch': UC_X86_REG_CH, 'cl': UC_X86_REG_CL, 'cx': UC_X86_REG_CX,
            'dh': UC_X86_REG_DH, 'dl': UC_X86_REG_DL, 'dx': UC_X86_REG_DX,
            'si': UC_X86_REG_SI, 'di': UC_X86_REG_DI,
            'bp': UC_X86_REG_BP, 'sp': UC_X86_REG_SP,
            'cs': UC_X86_REG_CS, 'ds': UC_X86_REG_DS,
            'es': UC_X86_REG_ES, 'ss': UC_X86_REG_SS,
            'ip': UC_X86_REG_IP, 'flags': UC_X86_REG_EFLAGS,
        }

        reg_name_lower = reg_name.lower()
        if reg_name_lower in reg_map:
            return self.uc.reg_read(reg_map[reg_name_lower])
        raise KeyError(f"Register not found: '{reg_name_lower}'")

    def _get_regs(self, instr, include_write=False):
        """Extract relevant registers from instruction operands using Capstone metadata"""
        regs = OrderedDict()
        operands = instr.operands

        if instr.id != X86_INS_NOP:
            # Check operands using Capstone's access metadata
            for i in range(len(operands)):
                op = operands[i]

                # Register operands - use access metadata to determine read/write
                if op.type == X86_OP_REG:
                    # Check if operand is read (not write-only)
                    is_read = (op.access & CS_AC_READ) != 0
                    is_write_only = (op.access == CS_AC_WRITE)

                    if is_read or (is_write_only and include_write):
                        regs[self.reg_name(op.value.reg)] = None

                # Memory operands - track base and index registers
                elif op.type == X86_OP_MEM:
                    mem = op.value.mem
                    if mem.segment != 0:
                        regs[self.reg_name(mem.segment)] = None
                    if mem.base != 0:
                        regs[self.reg_name(mem.base)] = None
                    if mem.index != 0:
                        regs[self.reg_name(mem.index)] = None

            # Add implicitly read registers
            for reg in instr.regs_read:
                regs[self.reg_name(reg)] = None

            # Optionally add written registers
            if include_write:
                for reg in instr.regs_write:
                    regs[self.reg_name(reg)] = None

        return regs
    
    def reg_name(self, reg_id: int):
        name = self.cs.reg_name(reg_id)
        if name is None:
            return None
        # HACK: capstone returns "esp" in 16-bit mode
        if name == "esp":
            return "sp"
        elif name == "eip":
            return "ip"
        return name

    def compute_memory_address(self, instr):
        """Compute memory address for memory operands"""
        for op in instr.operands:
            if op.type == X86_OP_MEM:
                mem = op.value.mem

                # Get segment (default to DS if not specified)
                segment = 0
                if mem.segment != 0:
                    segment = self.get_register_value(self.reg_name(mem.segment))
                else:
                    # Default segment is DS for most operations
                    segment = self.get_register_value("DS")

                # Get base register
                base = 0
                if mem.base != 0:
                    base = self.get_register_value(self.reg_name(mem.base))

                # Get index register
                index = 0
                if mem.index != 0:
                    index = self.get_register_value(self.reg_name(mem.index))

                # Calculate effective address: segment * 16 + base + index + displacement
                effective_addr = (segment << 4) + base + (index * mem.scale) + mem.disp

                return effective_addr, mem.disp

        return None, None

    def hook_code(self, uc: Uc, address, size, user_data):
        """Hook called before each instruction execution"""
        try:
            self.instruction_count += 1

            # Read instruction bytes
            try:
                code = uc.mem_read(address, 15)
            except UcError:
                code = b""

            # Disassemble instruction
            try:
                instr = next(self.cs.disasm(code, address, 1))
                code = code[:instr.size]
            except StopIteration:
                instr = None  # Unsupported instruction

            # Build trace line: address|instruction|registers
            line = f"0x{address:04x}|{code.hex().ljust(10)}|"

            if instr is not None:
                # Add disassembled instruction
                line += instr.mnemonic
                if instr.op_str:
                    line += " "
                    line += instr.op_str

                # Add ALL relevant register values (before instruction execution)
                for reg in self._get_regs(instr):
                    reg_value = self.get_register_value(reg)
                    if reg_value is not None:
                        line += f"|{reg}=0x{reg_value:x}"

                # Add memory address and value if accessing memory
                mem_addr, disp = self.compute_memory_address(instr)
                if mem_addr is not None:
                    try:
                        # Determine size of memory access
                        mem_size = 2  # Default to word (16-bit)
                        for op in instr.operands:
                            if op.type == X86_OP_MEM:
                                mem_size = op.size
                                break

                        # Read memory value
                        if mem_size == 1:
                            mem_val = uc.mem_read(mem_addr, 1)[0]
                            line += f"|mem[0x{mem_addr:x}]=0x{mem_val:02x}"
                        elif mem_size == 2:
                            mem_bytes = uc.mem_read(mem_addr, 2)
                            mem_val = struct.unpack('<H', mem_bytes)[0]
                            line += f"|mem[0x{mem_addr:x}]=0x{mem_val:04x}"
                        elif mem_size == 4:
                            mem_bytes = uc.mem_read(mem_addr, 4)
                            mem_val = struct.unpack('<I', mem_bytes)[0]
                            line += f"|mem[0x{mem_addr:x}]=0x{mem_val:08x}"
                    except:
                        # Memory not readable yet
                        pass

                # Special handling for CALL - show return address
                if instr.id == X86_INS_CALL:
                    ret_address = address + instr.size
                    line += f"|return_address=0x{ret_address:x}"

                # Special handling for interrupts
                elif instr.id == X86_INS_INT:
                    # Get interrupt number from operand
                    if len(instr.operands) > 0 and instr.operands[0].type == X86_OP_IMM:
                        int_num = instr.operands[0].value.imm
                        line += f"|int=0x{int_num:x}"
            else:
                line += f"??? (code: {code.hex()}, size: 0x{size:x})"

            line += "\n"

            # Write to trace file
            if self.trace_output:
                self.trace_output.write(line)

            # Optionally print to console (all instructions in verbose mode)
            if self.verbose:
                print(line.rstrip())

            # Check instruction limit
            if self.instruction_count >= self.max_instructions:
                print(f"\n[*] Reached maximum instruction limit ({self.max_instructions})")
                uc.emu_stop()

            if code == b"\xeb\xfe":
                print("\n[*] Infinite loop detected!")
                uc.emu_stop()

        except (KeyboardInterrupt, SystemExit):
            print(f"\n[!] Interrupted by user")
            uc.emu_stop()
        except Exception as e:
            print(f"\n[!] Error in hook_code: {e}")
            import traceback
            traceback.print_exc()
            uc.emu_stop()

    def hook_interrupt(self, uc: Uc, intno, user_data):
        """Hook called on interrupt instructions"""
        ip = uc.reg_read(UC_X86_REG_IP)

        if intno == 0x10:
            # Video Services
            self.handle_int10(uc)
        elif intno == 0x11:
            # Get Equipment List
            self.handle_int11(uc)
        elif intno == 0x12:
            # Get Memory Size
            self.handle_int12(uc)
        elif intno == 0x13:
            # Disk Services
            self.handle_int13(uc)
        elif intno == 0x15:
            # System Services
            self.handle_int15(uc)
        elif intno == 0x16:
            # Keyboard Services
            self.handle_int16(uc)
        else:
            if self.verbose:
                print(f"[INT] Unhandled interrupt 0x{intno:02X} at 0x{ip:04X}")
            uc.emu_stop()

    def handle_int10(self, uc: Uc):
        """Handle INT 0x10 - Video Services"""
        ah = (uc.reg_read(UC_X86_REG_AX) >> 8) & 0xFF

        if ah == 0x0E:
            # Teletype output
            al = uc.reg_read(UC_X86_REG_AX) & 0xFF
            if al == 0x0d:
                char = "\r"
            elif al == 0x0a:
                char = "\n"
            else:
                char = chr(al) if 32 <= al < 127 else f"\\x{al:02x}"
            if self.verbose:
                print(f"[INT 0x10] Teletype output: '{char}'")
                self.screen_output += char
        else:
            if self.verbose:
                print(f"[INT 0x10] Unhandled function AH=0x{ah:02X}")
            uc.emu_stop()

    def handle_int13(self, uc: Uc):
        """Handle INT 0x13 - Disk Services"""
        ah = (uc.reg_read(UC_X86_REG_AX) >> 8) & 0xFF
        dl = uc.reg_read(UC_X86_REG_DX) & 0xFF

        if ah == 0x00:
            # Reset disk system
            if self.verbose:
                print(f"[INT 0x13] Reset disk system for drive 0x{dl:02X}")
            # Clear CF to indicate success
            flags = uc.reg_read(UC_X86_REG_EFLAGS)
            uc.reg_write(UC_X86_REG_EFLAGS, flags & ~0x0001)

        elif ah == 0x01:
            # Get disk status
            if self.verbose:
                print(f"[INT 0x13] Get disk status for drive 0x{dl:02X}")
            # Return status 0 (no error)
            uc.reg_write(UC_X86_REG_AX, 0)
            flags = uc.reg_read(UC_X86_REG_EFLAGS)
            uc.reg_write(UC_X86_REG_EFLAGS, flags & ~0x0001)

        elif ah == 0x02:
            # Read sectors (CHS addressing)
            al = uc.reg_read(UC_X86_REG_AX) & 0xFF  # Number of sectors
            ch = (uc.reg_read(UC_X86_REG_CX) >> 8) & 0xFF  # Cylinder (low 8 bits)
            cl = uc.reg_read(UC_X86_REG_CX) & 0xFF  # Sector (bits 0-5) | Cylinder high (bits 6-7)
            dh = (uc.reg_read(UC_X86_REG_DX) >> 8) & 0xFF  # Head

            # Parse CHS values
            cylinder = ch | ((cl & 0xC0) << 2)  # Cylinder is 10 bits
            sector = cl & 0x3F  # Sector is bits 0-5 (1-based)
            head = dh

            # Buffer address from ES:BX
            es = uc.reg_read(UC_X86_REG_ES)
            bx = uc.reg_read(UC_X86_REG_BX)
            buffer_addr = (es << 4) + bx

            if self.verbose:
                print(f"[INT 0x13] Read sectors (CHS) for drive 0x{dl:02X}")
                print(f"  - CHS: C={cylinder} H={head} S={sector}, Sectors={al}")
                print(f"  - Buffer: 0x{es:04X}:0x{bx:04X} (0x{buffer_addr:05X})")

            try:
                # Convert CHS to LBA: LBA = (C * heads + H) * sectors_per_track + (S - 1)
                lba = (cylinder * self.heads + head) * self.sectors_per_track + (sector - 1)

                if self.verbose:
                    print(f"  - Converted to LBA: {lba}")

                # Read from disk image
                disk_offset = lba * 512
                bytes_to_read = al * 512

                if disk_offset + bytes_to_read <= len(self.disk_image):
                    data = self.disk_image[disk_offset:disk_offset + bytes_to_read]
                    self.mem_write(buffer_addr, data)

                    if self.verbose:
                        print(f"  ✓ Read {bytes_to_read} bytes from LBA {lba} to 0x{buffer_addr:05X}")
                        print(f"  - Data (32 bytes): {data[:32].hex(' ')}")

                    # Clear CF to indicate success, set AL to sectors read
                    flags = uc.reg_read(UC_X86_REG_EFLAGS)
                    uc.reg_write(UC_X86_REG_EFLAGS, flags & ~0x0001)
                    uc.reg_write(UC_X86_REG_AX, (uc.reg_read(UC_X86_REG_AX) & 0xFF00) | al)
                else:
                    if self.verbose:
                        print(f"  ⚠ Read beyond disk image!")
                    # Set CF to indicate error
                    flags = uc.reg_read(UC_X86_REG_EFLAGS)
                    uc.reg_write(UC_X86_REG_EFLAGS, flags | 0x0001)
                    uc.reg_write(UC_X86_REG_AX, (uc.reg_read(UC_X86_REG_AX) & 0x00FF) | 0x0400)  # AH=04 (sector not found)

            except Exception as e:
                if self.verbose:
                    print(f"  ⚠ Error reading disk: {e}")
                # Set CF to indicate error
                flags = uc.reg_read(UC_X86_REG_EFLAGS)
                uc.reg_write(UC_X86_REG_EFLAGS, flags | 0x0001)
                uc.reg_write(UC_X86_REG_AX, (uc.reg_read(UC_X86_REG_AX) & 0x00FF) | 0x0100)  # AH=01 (error)

        elif ah == 0x08:
            # Get drive parameters
            if self.verbose:
                print(f"[INT 0x13] Get drive parameters for drive 0x{dl:02X}")

            # Return detected geometry
            # CX = sectors per track (bits 0-5) | cylinder high bits (bits 6-7) | cylinder low (bits 8-15)
            # DH = max head number (heads - 1, 0-indexed)
            # DL = number of drives

            max_cylinder = self.cylinders - 1
            max_head = self.heads - 1
            sectors = self.sectors_per_track

            # Build CX register: sectors in low 6 bits, cylinder in upper 10 bits
            cx = sectors | ((max_cylinder & 0x300) >> 2) | ((max_cylinder & 0xFF) << 8)
            uc.reg_write(UC_X86_REG_CX, cx)
            uc.reg_write(UC_X86_REG_DX, (dl & 0xFF) | ((max_head & 0xFF) << 8))

            if self.verbose:
                print(f"  - Returning geometry: C={self.cylinders}, H={self.heads}, S={self.sectors_per_track}")
                print(f"  - CX=0x{cx:04X}, DH=0x{max_head:02X}")

            # Clear CF to indicate success
            flags = uc.reg_read(UC_X86_REG_EFLAGS)
            uc.reg_write(UC_X86_REG_EFLAGS, flags & ~0x0001)

        elif ah == 0x42:
            # Extended read - LBA
            if self.verbose:
                print(f"[INT 0x13] Extended read for drive 0x{dl:02X}")

            # Read Disk Address Packet from DS:SI
            si = uc.reg_read(UC_X86_REG_SI)
            ds = uc.reg_read(UC_X86_REG_DS)
            packet_addr = (ds << 4) + si

            try:
                packet = uc.mem_read(packet_addr, 16)

                # Parse packet
                size = packet[0]
                sectors = struct.unpack('<H', packet[2:4])[0]
                offset = struct.unpack('<H', packet[4:6])[0]
                segment = struct.unpack('<H', packet[6:8])[0]
                lba = struct.unpack('<Q', packet[8:16])[0]

                if self.verbose:
                    print(f"  - LBA: {lba}, Sectors: {sectors}, Buffer: 0x{segment:04X}:0x{offset:04X}")

                # Calculate source and destination
                disk_offset = lba * 512
                buffer_addr = (segment << 4) + offset
                bytes_to_read = sectors * 512

                # Read from disk image
                if disk_offset + bytes_to_read <= len(self.disk_image):
                    data = self.disk_image[disk_offset:disk_offset + bytes_to_read]
                    self.mem_write(buffer_addr, data)

                    if self.verbose:
                        print(f"  ✓ Read {bytes_to_read} bytes from LBA {lba} to 0x{buffer_addr:05X}")

                    # Clear CF to indicate success
                    flags = uc.reg_read(UC_X86_REG_EFLAGS)
                    uc.reg_write(UC_X86_REG_EFLAGS, flags & ~0x0001)
                else:
                    if self.verbose:
                        print(f"  ⚠ Read beyond disk image!")
                    # Set CF to indicate error
                    flags = uc.reg_read(UC_X86_REG_EFLAGS)
                    uc.reg_write(UC_X86_REG_EFLAGS, flags | 0x0001)

            except Exception as e:
                if self.verbose:
                    print(f"  ⚠ Error reading disk: {e}")
                # Set CF to indicate error
                flags = uc.reg_read(UC_X86_REG_EFLAGS)
                uc.reg_write(UC_X86_REG_EFLAGS, flags | 0x0001)
        elif ah == 0x15:
            # Get disk type
            if self.verbose:
                print(f"[INT 0x13] Get disk type for drive 0x{dl:02X}")
            # AH=03 means fixed disk installed
            uc.reg_write(UC_X86_REG_AX, (uc.reg_read(UC_X86_REG_AX) & 0x00FF) | 0x0300)
            flags = uc.reg_read(UC_X86_REG_EFLAGS)
            uc.reg_write(UC_X86_REG_EFLAGS, flags & ~0x0001)

        elif ah == 0x41:
            # Check INT 13 extensions present
            if self.verbose:
                print(f"[INT 0x13] Check extensions present for drive 0x{dl:02X}")
            # BX should contain 0x55AA to indicate support
            bx = uc.reg_read(UC_X86_REG_BX)
            if bx == 0x55AA:
                # Extensions present: return AH=0x30 (v3.0)
                uc.reg_write(UC_X86_REG_AX, (uc.reg_read(UC_X86_REG_AX) & 0x00FF) | 0x3000)
                # CX = capabilities
                uc.reg_write(UC_X86_REG_CX, 0x0003)  # Bits 0 and 1 set (basic support)
                flags = uc.reg_read(UC_X86_REG_EFLAGS)
                uc.reg_write(UC_X86_REG_EFLAGS, flags & ~0x0001)
            else:
                # Extension not supported
                flags = uc.reg_read(UC_X86_REG_EFLAGS)
                uc.reg_write(UC_X86_REG_EFLAGS, flags | 0x0001)

        else:
            if self.verbose:
                print(f"[INT 0x13] Unhandled function AH=0x{ah:02X}")
            uc.emu_stop()

    def handle_int11(self, uc: Uc):
        """Handle INT 0x11 - Get Equipment List"""
        if self.verbose:
            print(f"[INT 0x11] Get equipment list")
        # AX = equipment list word
        # Bit 0: Floppy drive installed
        # Bit 1: Math coprocessor
        # Bit 2: PS/2 pointing device
        # Bits 3-5: Number of serial ports
        # Bit 6: Game port
        # Bits 7-9: Number of parallel ports
        # Bits 10-11: Video mode (00=EGA/VGA, 01=40-column color, 10=80-column color, 11=monochrome)
        # Bit 12: PS/2 mouse installed
        # Bit 13: Extended memory

        # Default: no floppy, no coprocessor, VGA (80-col color)
        equipment = 0x0000
        equipment |= (0b10 << 10)  # 80-column color video
        uc.reg_write(UC_X86_REG_AX, equipment)

    def handle_int12(self, uc: Uc):
        """Handle INT 0x12 - Get Memory Size"""
        if self.verbose:
            print(f"[INT 0x12] Get memory size")
        # AX = memory size in KB (conventional memory, typically 640KB)
        memory_size_kb = 640
        uc.reg_write(UC_X86_REG_AX, memory_size_kb)

    def handle_int15(self, uc: Uc):
        """Handle INT 0x15 - System Services"""
        ah = (uc.reg_read(UC_X86_REG_AX) >> 8) & 0xFF

        if ah == 0x88:
            # Get extended memory size
            if self.verbose:
                print(f"[INT 0x15] Get extended memory size")
            # AX = extended memory in KB (above 1MB)
            uc.reg_write(UC_X86_REG_AX, 0)  # No extended memory
            flags = uc.reg_read(UC_X86_REG_EFLAGS)
            uc.reg_write(UC_X86_REG_EFLAGS, flags & ~0x0001)

        elif ah == 0xC0:
            # Get system configuration
            if self.verbose:
                print(f"[INT 0x15] Get system configuration")
            # ES:BX = pointer to configuration table
            # For now, return error
            flags = uc.reg_read(UC_X86_REG_EFLAGS)
            uc.reg_write(UC_X86_REG_EFLAGS, flags | 0x0001)

        elif ah == 0x53:
            # APM BIOS functions
            if self.verbose:
                print(f"[INT 0x15] APM BIOS function AH=0x{ah:02X}")
            # Return error (unsupported)
            flags = uc.reg_read(UC_X86_REG_EFLAGS)
            uc.reg_write(UC_X86_REG_EFLAGS, flags | 0x0001)

        else:
            if self.verbose:
                print(f"[INT 0x15] Unhandled function AH=0x{ah:02X}")
            uc.emu_stop()

    def handle_int16(self, uc: Uc):
        """Handle INT 0x16 - Keyboard Services"""
        ah = (uc.reg_read(UC_X86_REG_AX) >> 8) & 0xFF

        if ah == 0x00:
            # Read keystroke
            if self.verbose:
                print(f"[INT 0x16] Read keystroke")
            # For emulation, simulate pressing Enter (0x1C)
            uc.reg_write(UC_X86_REG_AX, 0x1C0D)  # AL=0x0D (CR), AH=0x1C (scancode)

        elif ah == 0x01:
            # Check for keystroke
            if self.verbose:
                print(f"[INT 0x16] Check for keystroke")
            # ZF=1 if no key available (set ZF)
            flags = uc.reg_read(UC_X86_REG_EFLAGS)
            uc.reg_write(UC_X86_REG_EFLAGS, flags | 0x0040)  # Set ZF

        elif ah == 0x02:
            # Get shift flags
            if self.verbose:
                print(f"[INT 0x16] Get shift flags")
            uc.reg_write(UC_X86_REG_AX, 0)  # No modifiers

        else:
            if self.verbose:
                print(f"[INT 0x16] Unhandled function AH=0x{ah:02X}")
            uc.emu_stop()

    def hook_mem_invalid(self, uc: Uc, access, address, size, value, user_data):
        """Hook called on invalid memory access"""
        access_type = "READ" if access == UC_MEM_READ else "WRITE" if access == UC_MEM_WRITE else "EXEC"
        print(f"\n[!] Invalid memory access: {access_type} at 0x{address:08X} (size: {size})")
        self.last_exception = f"Invalid memory {access_type}"
        return False

    def hook_ivt_access(self, uc: Uc, access, address, size, value, _user_data):
        """Hook called on IVT region (0x0000-0x03FF) memory access"""
        # Calculate interrupt vector number (each vector is 4 bytes)
        int_num = address // 4

        # Get current IP for context
        ip = uc.reg_read(UC_X86_REG_IP)

        # Format access type
        access_type = "READ" if access == UC_MEM_READ else "WRITE"

        # Format the trace line
        line = f"[IVT {access_type}] 0x{address:04X} | size={size} | int={int_num:02X} | value=0x{value:X} | ip=0x{ip:04X}\n"

        # Write to trace file unconditionally
        if self.trace_output:
            self.trace_output.write(line)

        # Also print to console if verbose
        if self.verbose:
            print(line.strip())

        return True

    def run(self):
        """Run the emulator"""
        print("\n" + "="*80)
        print(f"Starting emulation (trace file: {self.trace_file})...")
        print("="*80 + "\n")

        # Open trace file
        try:
            self.trace_output = open(self.trace_file, 'w')
            print(f"[*] Writing trace to {self.trace_file}")
        except Exception as e:
            print(f"[!] Error opening trace file: {e}")
            return

        # Add hooks
        self.uc.hook_add(UC_HOOK_CODE, self.hook_code)
        self.uc.hook_add(UC_HOOK_INTR, self.hook_interrupt)
        self.uc.hook_add(
            UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED,
            self.hook_mem_invalid
        )

        # Add IVT-range-specific memory hook (0x0000-0x03FF)
        self.uc.hook_add(
            UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE,
            self.hook_ivt_access,
            begin=0x0000,
            end=0x03FF
        )

        try:
            # Start emulation from boot address
            # In real mode, use CS:IP addressing (CS << 4 + IP)
            start_address = (self.uc.reg_read(UC_X86_REG_CS) << 4) + self.boot_address

            # Run until we hit a HLT or error
            # We'll use a very high end address and rely on instruction limit
            end_address = 0xFFFFFFFF

            self.uc.emu_start(start_address, end_address)

        except UcError as e:
            error_ip = self.uc.reg_read(UC_X86_REG_IP)
            print(f"\n[!] Emulation error at IP=0x{error_ip:04X}: {e}")

            # Decode error
            if e.errno == UC_ERR_INSN_INVALID:
                print(f"    Invalid instruction")
            elif e.errno == UC_ERR_READ_UNMAPPED:
                print(f"    Read from unmapped memory")
            elif e.errno == UC_ERR_WRITE_UNMAPPED:
                print(f"    Write to unmapped memory")
            elif e.errno == UC_ERR_FETCH_UNMAPPED:
                print(f"    Fetch from unmapped memory")

        except KeyboardInterrupt:
            print(f"\n\n[!] Interrupted by user")

        finally:
            if self.trace_output:
                self.trace_output.close()
            self.print_summary()

    def print_summary(self):
        """Print execution summary"""
        print("\n" + "="*80)
        print("Emulation Summary")
        print("="*80)
        print(f"Total instructions executed: {self.instruction_count}")

        # Get final register state
        ip = self.uc.reg_read(UC_X86_REG_IP)
        cs = self.uc.reg_read(UC_X86_REG_CS)
        print(f"Final CS:IP: 0x{cs:04X}:0x{ip:04X}")

        print(f"\nFinal register state:")
        regs = [
            ('AX', UC_X86_REG_AX), ('BX', UC_X86_REG_BX),
            ('CX', UC_X86_REG_CX), ('DX', UC_X86_REG_DX),
            ('SI', UC_X86_REG_SI), ('DI', UC_X86_REG_DI),
            ('BP', UC_X86_REG_BP), ('SP', UC_X86_REG_SP),
        ]

        for name, reg in regs:
            value = self.uc.reg_read(reg)
            print(f"  {name}: 0x{value:04X}")

        print(f"\nSegment registers:")
        segs = [
            ('CS', UC_X86_REG_CS), ('DS', UC_X86_REG_DS),
            ('ES', UC_X86_REG_ES), ('SS', UC_X86_REG_SS),
        ]
        for name, reg in segs:
            value = self.uc.reg_read(reg)
            print(f"  {name}: 0x{value:04X}")

        # Show some memory around the boot sector
        print(f"\nMemory at boot sector (0x{self.boot_address:04X}):")
        try:
            mem = self.uc.mem_read(self.boot_address, 64)
            for i in range(0, 64, 16):
                offset = self.boot_address + i
                hex_bytes = ' '.join(f'{b:02X}' for b in mem[i:i+16])
                ascii_repr = ''.join(chr(b) if 32 <= b < 127 else '.' for b in mem[i:i+16])
                print(f"  0x{offset:04X}: {hex_bytes:48s} | {ascii_repr}")
        except Exception as e:
            print(f"  Error reading memory: {e}")

        print(f"\n[*] Trace written to {self.trace_file}")
        print(f"    Total instructions: {self.instruction_count}")
        print(f"\n[*] Screen output:\n{self.screen_output}")


def main():
    parser = argparse.ArgumentParser(
        description='Emulate x86 real mode bootloader with instruction tracing'
    )
    parser.add_argument(
        'disk_image',
        type=str,
        help='Path to disk image file (bootloader loaded from first 512 bytes)'
    )
    parser.add_argument(
        '-m', '--max-instructions',
        type=int,
        default=1000000,
        help='Maximum number of instructions to execute (default: 1000000)'
    )
    parser.add_argument(
        '-o', '--output',
        type=str,
        default='trace.txt',
        help='Output trace file (default: trace.txt)'
    )
    parser.add_argument(
        '-q', '--quiet',
        action='store_true',
        help='Reduce verbosity (only show first 50 instructions)'
    )
    parser.add_argument(
        '-g', '--geometry',
        type=str,
        metavar='C,H,S',
        help='Manual CHS geometry (cylinders,heads,sectors) e.g., 120,16,63'
    )
    parser.add_argument(
        '-f', '--floppy-type',
        type=str,
        choices=['360K', '720K', '1.2M', '1.44M', '2.88M'],
        help='Standard floppy disk type (implies --drive-number 0x00)'
    )
    parser.add_argument(
        '-d', '--drive-number',
        type=str,
        default='0x80',
        help='BIOS drive number (default: 0x80 for HDD, use 0x00 for floppy)'
    )

    args = parser.parse_args()

    # Check if disk image exists
    if not Path(args.disk_image).exists():
        print(f"Error: Disk image not found: {args.disk_image}")
        sys.exit(1)

    # Parse geometry if provided
    geometry = None
    if args.geometry:
        try:
            parts = args.geometry.split(',')
            if len(parts) != 3:
                raise ValueError("Geometry must be in format C,H,S")
            geometry = tuple(int(p.strip()) for p in parts)
        except ValueError as e:
            print(f"Error: Invalid geometry format: {e}")
            sys.exit(1)

    # Parse drive number
    try:
        drive_number = int(args.drive_number, 0)  # Supports 0x prefix
        if args.floppy_type and drive_number >= 0x80:
            drive_number = 0x00  # Override to floppy if floppy type specified
    except ValueError:
        print(f"Error: Invalid drive number: {args.drive_number}")
        sys.exit(1)

    # Create and run emulator
    emulator = BootloaderEmulator(
        disk_image_path=args.disk_image,
        max_instructions=args.max_instructions,
        trace_file=args.output,
        verbose=not args.quiet,
        geometry=geometry,
        floppy_type=args.floppy_type,
        drive_number=drive_number
    )

    emulator.setup_cpu_state()
    emulator.run()


if __name__ == '__main__':
    main()
