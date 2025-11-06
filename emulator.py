#!/usr/bin/env python3
"""
x86 Real Mode Bootloader Emulator using Unicorn Engine and Capstone

This emulator loads a bootloader binary and emulates it step-by-step,
logging every instruction execution with relevant registers and memory accesses.
"""

import sys
import struct
import argparse
from pathlib import Path
from collections import OrderedDict

try:
    from unicorn import *
    from unicorn.x86_const import *
except ImportError:
    print("Error: unicorn not installed. Install with: pip install unicorn")
    sys.exit(1)

try:
    from capstone import *
    from capstone.x86_const import *
except ImportError:
    print("Error: capstone not installed. Install with: pip install capstone")
    sys.exit(1)


class BootloaderEmulator:
    """Emulator for x86 real mode bootloaders using Unicorn Engine"""

    def __init__(self, binary_path, max_instructions=10000, trace_file="trace.txt", verbose=True, disk_image=None):
        """
        Initialize the emulator

        Args:
            binary_path: Path to the bootloader binary file
            max_instructions: Maximum number of instructions to execute
            trace_file: Output file for instruction trace
            verbose: Enable verbose console output
            disk_image: Optional path to disk image file to attach
        """
        self.binary_path = Path(binary_path)
        self.max_instructions = max_instructions
        self.trace_file = trace_file
        self.verbose = verbose
        self.disk_image_path = Path(disk_image) if disk_image else None

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

        # Disk emulation
        self.disk_image = None
        self.disk_size = 0

    def setup_memory(self):
        """Set up memory regions for the emulator"""
        print(f"[*] Setting up memory...")

        # Map main memory (1 MB for real mode)
        self.uc.mem_map(self.memory_base, self.memory_size, UC_PROT_ALL)

        # Zero out memory
        self.uc.mem_write(self.memory_base, b'\x00' * self.memory_size)

        print(f"  - Mapped {self.memory_size // 1024} KB at 0x{self.memory_base:08X}")

    def load_disk_image(self):
        """Load disk image if provided"""
        if not self.disk_image_path:
            return

        print(f"[*] Loading disk image from {self.disk_image_path}...")

        if not self.disk_image_path.exists():
            print(f"  ⚠ Warning: Disk image not found: {self.disk_image_path}")
            return

        with open(self.disk_image_path, 'rb') as f:
            self.disk_image = f.read()

        self.disk_size = len(self.disk_image)
        print(f"  - Disk image size: {self.disk_size} bytes ({self.disk_size // 1024} KB)")

    def load_bootloader(self):
        """Load the bootloader binary at 0x7C00"""
        print(f"[*] Loading bootloader from {self.binary_path}...")

        # If we have a disk image, load boot sector from it
        if self.disk_image:
            if len(self.disk_image) >= 512:
                bootloader_code = self.disk_image[:512]
                print(f"  - Loaded boot sector from disk image")
            else:
                print(f"  ⚠ Warning: Disk image too small, loading from binary file")
                with open(self.binary_path, 'rb') as f:
                    bootloader_code = f.read()
        else:
            with open(self.binary_path, 'rb') as f:
                bootloader_code = f.read()

        print(f"  - Bootloader size: {len(bootloader_code)} bytes")

        # Verify boot signature (0xAA55 at offset 510-511)
        if len(bootloader_code) >= 512:
            signature = struct.unpack('<H', bootloader_code[510:512])[0]
            if signature == 0xAA55:
                print(f"  ✓ Valid boot signature: 0x{signature:04X}")
            else:
                print(f"  ⚠ Warning: Invalid boot signature: 0x{signature:04X} (expected 0xAA55)")

        # Load bootloader at 0x7C00
        self.uc.mem_write(self.boot_address, bootloader_code)
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
        self.uc.reg_write(UC_X86_REG_DL, 0x80)  # 0x80 for hard disk

        # Clear other registers
        for reg in [UC_X86_REG_AX, UC_X86_REG_BX, UC_X86_REG_CX,
                    UC_X86_REG_SI, UC_X86_REG_DI, UC_X86_REG_BP]:
            self.uc.reg_write(reg, 0x0000)

        print(f"  - CS:IP: 0x{0x0000:04X}:0x{self.boot_address:04X}")
        print(f"  - SS:SP: 0x{0x0000:04X}:0x{self.boot_address:04X}")
        print(f"  - DL: 0x80 (drive number)")

    def get_register_value(self, reg_name):
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
        return None

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
                        regs[instr.reg_name(op.value.reg)] = None

                # Memory operands - track base and index registers
                elif op.type == X86_OP_MEM:
                    mem = op.value.mem
                    if mem.segment != 0:
                        regs[instr.reg_name(mem.segment)] = None
                    if mem.base != 0:
                        regs[instr.reg_name(mem.base)] = None
                    if mem.index != 0:
                        regs[instr.reg_name(mem.index)] = None

            # Add implicitly read registers
            for reg in instr.regs_read:
                regs[instr.reg_name(reg)] = None

            # Optionally add written registers
            if include_write:
                for reg in instr.regs_write:
                    regs[instr.reg_name(reg)] = None

        return regs

    def compute_memory_address(self, instr):
        """Compute memory address for memory operands"""
        for op in instr.operands:
            if op.type == X86_OP_MEM:
                mem = op.value.mem

                # Get segment (default to DS if not specified)
                segment = 0
                if mem.segment != 0:
                    segment = self.get_register_value(instr.reg_name(mem.segment))
                else:
                    # Default segment is DS for most operations
                    segment = self.uc.reg_read(UC_X86_REG_DS)

                # Get base register
                base = 0
                if mem.base != 0:
                    base = self.get_register_value(instr.reg_name(mem.base))

                # Get index register
                index = 0
                if mem.index != 0:
                    index = self.get_register_value(instr.reg_name(mem.index))

                # Calculate effective address: segment * 16 + base + index + displacement
                effective_addr = (segment << 4) + base + (index * mem.scale) + mem.disp

                return effective_addr, mem.disp

        return None, None

    def hook_code(self, uc, address, size, user_data):
        """Hook called before each instruction execution"""
        try:
            self.instruction_count += 1

            # Read instruction bytes
            try:
                code = uc.mem_read(address, min(size, 15))
            except UcError:
                code = b""

            # Disassemble instruction
            try:
                instr = next(self.cs.disasm(code, address, 1))
            except StopIteration:
                instr = None  # Unsupported instruction

            # Build trace line: address|instruction|registers
            line = f"0x{address:04x}|"

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

            # Optionally print to console
            if self.verbose and self.instruction_count <= 50:
                print(line.rstrip())

            # Check instruction limit
            if self.instruction_count >= self.max_instructions:
                print(f"\n[*] Reached maximum instruction limit ({self.max_instructions})")
                uc.emu_stop()

        except (KeyboardInterrupt, SystemExit):
            print(f"\n[!] Interrupted by user")
            uc.emu_stop()
        except Exception as e:
            print(f"\n[!] Error in hook_code: {e}")
            import traceback
            traceback.print_exc()
            uc.emu_stop()

    def hook_interrupt(self, uc, intno, user_data):
        """Hook called on interrupt instructions"""
        ip = uc.reg_read(UC_X86_REG_IP)

        if intno == 0x10:
            # Video Services
            self.handle_int10(uc)
        elif intno == 0x13:
            # Disk Services
            self.handle_int13(uc)
        else:
            if self.verbose:
                print(f"[INT] Unhandled interrupt 0x{intno:02X} at 0x{ip:04X}")

    def handle_int10(self, uc):
        """Handle INT 0x10 - Video Services"""
        ah = (uc.reg_read(UC_X86_REG_AX) >> 8) & 0xFF

        if ah == 0x0E:
            # Teletype output
            al = uc.reg_read(UC_X86_REG_AX) & 0xFF
            char = chr(al) if 32 <= al < 127 else f"\\x{al:02x}"
            if self.verbose:
                print(f"[INT 0x10] Teletype output: '{char}'")
        else:
            if self.verbose:
                print(f"[INT 0x10] Unhandled function AH=0x{ah:02X}")

    def handle_int13(self, uc):
        """Handle INT 0x13 - Disk Services"""
        ah = (uc.reg_read(UC_X86_REG_AX) >> 8) & 0xFF
        dl = uc.reg_read(UC_X86_REG_DX) & 0xFF

        if ah == 0x02:
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

            if not self.disk_image:
                if self.verbose:
                    print(f"  ⚠ No disk image attached!")
                # Set CF to indicate error
                flags = uc.reg_read(UC_X86_REG_EFLAGS)
                uc.reg_write(UC_X86_REG_EFLAGS, flags | 0x0001)
                uc.reg_write(UC_X86_REG_AX, (uc.reg_read(UC_X86_REG_AX) & 0x00FF) | 0x0100)  # AH=01 (error)
                return

            try:
                # Convert CHS to LBA: LBA = (C * heads_per_cylinder + H) * sectors_per_track + (S - 1)
                # Assume standard geometry: 2 heads, 80 sectors per track
                heads_per_cylinder = 2
                sectors_per_track = 80

                lba = (cylinder * heads_per_cylinder + head) * sectors_per_track + (sector - 1)

                if self.verbose:
                    print(f"  - Converted to LBA: {lba}")

                # Read from disk image
                disk_offset = lba * 512
                bytes_to_read = al * 512

                if disk_offset + bytes_to_read <= len(self.disk_image):
                    data = self.disk_image[disk_offset:disk_offset + bytes_to_read]
                    uc.mem_write(buffer_addr, data)

                    if self.verbose:
                        print(f"  ✓ Read {bytes_to_read} bytes from LBA {lba} to 0x{buffer_addr:05X}")

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

            # Return fake geometry: 80 sectors per track, 2 heads
            # CX = sectors per track (bits 0-5) | cylinder (bits 6-15)
            # DH = max head number
            uc.reg_write(UC_X86_REG_CX, 0x0050)  # 80 sectors
            uc.reg_write(UC_X86_REG_DX, (uc.reg_read(UC_X86_REG_DX) & 0xFF) | 0x0100)  # 1 head (0-indexed)

            # Clear CF to indicate success
            flags = uc.reg_read(UC_X86_REG_EFLAGS)
            uc.reg_write(UC_X86_REG_EFLAGS, flags & ~0x0001)

        elif ah == 0x42:
            # Extended read - LBA
            if self.verbose:
                print(f"[INT 0x13] Extended read for drive 0x{dl:02X}")

            if not self.disk_image:
                if self.verbose:
                    print(f"  ⚠ No disk image attached!")
                # Set CF to indicate error
                flags = uc.reg_read(UC_X86_REG_EFLAGS)
                uc.reg_write(UC_X86_REG_EFLAGS, flags | 0x0001)
                return

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
                    uc.mem_write(buffer_addr, data)

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
        else:
            if self.verbose:
                print(f"[INT 0x13] Unhandled function AH=0x{ah:02X}")

    def hook_mem_invalid(self, uc, access, address, size, value, user_data):
        """Hook called on invalid memory access"""
        access_type = "READ" if access == UC_MEM_READ else "WRITE" if access == UC_MEM_WRITE else "EXEC"
        print(f"\n[!] Invalid memory access: {access_type} at 0x{address:08X} (size: {size})")
        self.last_exception = f"Invalid memory {access_type}"
        return False

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


def main():
    parser = argparse.ArgumentParser(
        description='Emulate x86 real mode bootloader with instruction tracing'
    )
    parser.add_argument(
        'binary',
        type=str,
        help='Path to bootloader binary file'
    )
    parser.add_argument(
        '-m', '--max-instructions',
        type=int,
        default=10000,
        help='Maximum number of instructions to execute (default: 10000)'
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
        '-d', '--disk',
        type=str,
        help='Disk image file to attach (e.g., boot.img)'
    )

    args = parser.parse_args()

    # Check if binary exists
    if not Path(args.binary).exists():
        print(f"Error: Binary file not found: {args.binary}")
        sys.exit(1)

    # Create and run emulator
    emulator = BootloaderEmulator(
        binary_path=args.binary,
        max_instructions=args.max_instructions,
        trace_file=args.output,
        verbose=not args.quiet,
        disk_image=args.disk
    )

    emulator.setup_memory()
    emulator.load_disk_image()
    emulator.load_bootloader()
    emulator.setup_cpu_state()
    emulator.run()


if __name__ == '__main__':
    main()
