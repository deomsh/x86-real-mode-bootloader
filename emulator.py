#!/usr/bin/env python3
"""
x86 Real Mode Bootloader Emulator using icicle-emu

This emulator loads a bootloader binary and emulates it step-by-step,
logging every instruction execution and memory access.
"""

import sys
import struct
import argparse
import json
from pathlib import Path

try:
    import icicle
except ImportError:
    print("Error: icicle-emu not installed. Install with: pip install icicle-emu")
    sys.exit(1)


class BootloaderEmulator:
    """Emulator for x86 real mode bootloaders"""

    def __init__(self, binary_path, max_instructions=10000, verbose=True, trace_file=None):
        """
        Initialize the emulator

        Args:
            binary_path: Path to the bootloader binary file
            max_instructions: Maximum number of instructions to execute
            verbose: Enable verbose output
            trace_file: Optional file path to save execution trace (JSON format)
        """
        self.binary_path = Path(binary_path)
        self.max_instructions = max_instructions
        self.verbose = verbose
        self.trace_file = trace_file

        # Boot sector is loaded at 0x7C00
        self.boot_address = 0x7C00

        # Memory configuration
        self.memory_size = 0x100000  # 1 MB for real mode

        # Initialize VM
        print(f"[*] Initializing x86_64 emulator (real mode compatible)...")
        self.vm = icicle.Icicle('x86_64', jit=False, tracing=True)

        # Track memory accesses and execution trace
        self.memory_accesses = []
        self.instruction_count = 0
        self.trace = []

    def setup_memory(self):
        """Set up memory regions for the emulator"""
        print(f"[*] Setting up memory...")

        # Map main memory (0x0000 - 0xFFFFF) - 1 MB real mode address space
        self.vm.mem_map(0x0000, self.memory_size, icicle.MemoryProtection.ExecuteReadWrite)

        # Zero out memory
        zero_mem = b'\x00' * self.memory_size
        self.vm.mem_write(0x0000, zero_mem)

        print(f"  - Mapped {self.memory_size // 1024} KB at 0x00000000")

    def load_bootloader(self):
        """Load the bootloader binary at 0x7C00"""
        print(f"[*] Loading bootloader from {self.binary_path}...")

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
        self.vm.mem_write(self.boot_address, bootloader_code)
        print(f"  - Loaded at 0x{self.boot_address:04X}")

    def setup_cpu_state(self):
        """Initialize CPU registers for boot"""
        print(f"[*] Setting up CPU state...")

        # Set instruction pointer to boot sector address
        self.vm.reg_write('rip', self.boot_address)

        # Set up stack at a safe location (below boot sector)
        self.vm.reg_write('rsp', self.boot_address)

        # Real mode typically boots with DL = drive number (0x80 for hard disk, 0x00 for floppy)
        self.vm.reg_write('rdx', 0x80)

        # Clear other registers
        for reg in ['rax', 'rbx', 'rcx', 'rsi', 'rdi', 'rbp']:
            self.vm.reg_write(reg, 0x0000)

        print(f"  - RIP: 0x{self.boot_address:04X}")
        print(f"  - RSP: 0x{self.boot_address:04X}")
        print(f"  - RDX: 0x0080 (drive number)")

    def disassemble_at_pc(self):
        """Get a simple representation of the instruction at PC"""
        pc = self.vm.pc
        try:
            # Read up to 15 bytes (max x86 instruction length)
            code_bytes = self.vm.mem_read(pc, 15)
            # Format as hex bytes
            hex_bytes = ' '.join(f'{b:02X}' for b in code_bytes[:8])
            return hex_bytes
        except Exception as e:
            return f"<error reading memory: {e}>"

    def get_register_state(self):
        """Get current state of main registers"""
        try:
            regs = {}
            for reg in ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp', 'rip']:
                regs[reg] = self.vm.reg_read(reg)
            return regs
        except Exception as e:
            return {"error": str(e)}

    def format_registers(self, regs):
        """Format registers for display"""
        if "error" in regs:
            return f"<error: {regs['error']}>"

        return (f"RAX:{regs['rax']:08X} RBX:{regs['rbx']:08X} "
                f"RCX:{regs['rcx']:08X} RDX:{regs['rdx']:08X} "
                f"RSI:{regs['rsi']:08X} RDI:{regs['rdi']:08X} "
                f"RBP:{regs['rbp']:08X} RSP:{regs['rsp']:08X} "
                f"RIP:{regs['rip']:08X}")

    def log_instruction(self, step_num):
        """Log the current instruction about to be executed"""
        pc = self.vm.pc
        code = self.disassemble_at_pc()
        regs = self.get_register_state()

        # Add to trace if trace file is enabled
        if self.trace_file:
            trace_entry = {
                'step': step_num,
                'pc': pc,
                'bytes': code,
                'registers': regs
            }
            self.trace.append(trace_entry)

        print(f"\n[Step {step_num:05d}] PC: 0x{pc:08X}")
        print(f"  Bytes: {code}")
        print(f"  Regs:  {self.format_registers(regs)}")

    def check_memory_access(self, old_regs, new_regs):
        """Detect memory accesses by monitoring register changes"""
        # This is a simplified approach - in practice you'd need more sophisticated tracing
        # For demonstration, we check if stack pointer changed (indicating push/pop)
        if old_regs['rsp'] != new_regs['rsp']:
            if old_regs['rsp'] > new_regs['rsp']:
                size = old_regs['rsp'] - new_regs['rsp']
                print(f"  Memory: PUSH - wrote {size} bytes to stack at 0x{new_regs['rsp']:08X}")
            else:
                size = new_regs['rsp'] - old_regs['rsp']
                print(f"  Memory: POP  - read {size} bytes from stack at 0x{old_regs['rsp']:08X}")

    def run(self):
        """Run the emulator step by step"""
        print("\n" + "="*80)
        print("Starting emulation...")
        print("="*80)

        try:
            for step in range(self.max_instructions):
                self.instruction_count = step + 1

                # Log current instruction
                if self.verbose or step < 50:  # Always show first 50 steps
                    self.log_instruction(step + 1)

                # Save register state before execution
                old_regs = self.get_register_state()
                old_pc = self.vm.pc

                # Execute one instruction
                try:
                    self.vm.step(1)
                except Exception as e:
                    exception_code = self.vm.exception_code
                    print(f"\n[!] Exception during execution: {exception_code}")
                    print(f"    Details: {e}")

                    # Check for specific exception types
                    if exception_code == icicle.ExceptionCode.Halt:
                        print(f"\n[*] CPU halted after {step + 1} instructions")
                        break
                    elif exception_code == icicle.ExceptionCode.InvalidInstruction:
                        print(f"[!] Invalid instruction encountered at 0x{old_pc:08X}")
                        break
                    elif exception_code == icicle.ExceptionCode.SoftwareBreakpoint:
                        print(f"[*] Software breakpoint hit at 0x{old_pc:08X}")
                        break
                    elif exception_code in [icicle.ExceptionCode.ReadUnmapped,
                                           icicle.ExceptionCode.WriteUnmapped,
                                           icicle.ExceptionCode.ExecViolation]:
                        print(f"[!] Memory access violation")
                        break
                    else:
                        print(f"[!] Unhandled exception, stopping emulation")
                        break

                # Get new register state
                new_regs = self.get_register_state()
                new_pc = self.vm.pc

                # Check for memory accesses
                if self.verbose or step < 50:
                    self.check_memory_access(old_regs, new_regs)

                # Check if we're stuck in an infinite loop
                if new_pc == old_pc:
                    print(f"\n[!] Infinite loop detected at 0x{old_pc:08X}")
                    print(f"    Executed {step + 1} instructions")
                    break

                # Check for common exit conditions
                if new_pc == 0:
                    print(f"\n[*] Jumped to address 0x00000000, likely end of execution")
                    break

            else:
                print(f"\n[*] Reached maximum instruction limit ({self.max_instructions})")

        except KeyboardInterrupt:
            print(f"\n\n[!] Interrupted by user")

        finally:
            self.print_summary()
            self.save_trace()

    def print_summary(self):
        """Print execution summary"""
        print("\n" + "="*80)
        print("Emulation Summary")
        print("="*80)
        print(f"Total instructions executed: {self.instruction_count}")
        print(f"Final PC: 0x{self.vm.pc:08X}")
        print(f"\nFinal register state:")
        regs = self.get_register_state()
        for reg, value in regs.items():
            if reg != "error":
                print(f"  {reg.upper():3s}: 0x{value:016X}")

        # Show some memory around the boot sector
        print(f"\nMemory at boot sector (0x{self.boot_address:04X}):")
        try:
            mem = self.vm.mem_read(self.boot_address, 64)
            for i in range(0, 64, 16):
                offset = self.boot_address + i
                hex_bytes = ' '.join(f'{b:02X}' for b in mem[i:i+16])
                ascii_repr = ''.join(chr(b) if 32 <= b < 127 else '.' for b in mem[i:i+16])
                print(f"  0x{offset:04X}: {hex_bytes:48s} | {ascii_repr}")
        except Exception as e:
            print(f"  Error reading memory: {e}")

    def save_trace(self):
        """Save execution trace to file if specified"""
        if not self.trace_file:
            return

        print(f"\n[*] Saving trace to {self.trace_file}...")
        try:
            trace_data = {
                'metadata': {
                    'binary': str(self.binary_path),
                    'boot_address': hex(self.boot_address),
                    'total_instructions': self.instruction_count,
                    'max_instructions': self.max_instructions
                },
                'trace': self.trace
            }

            with open(self.trace_file, 'w') as f:
                json.dump(trace_data, f, indent=2)

            print(f"  ✓ Trace saved ({len(self.trace)} instruction entries)")
        except Exception as e:
            print(f"  ✗ Error saving trace: {e}")


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
        '-q', '--quiet',
        action='store_true',
        help='Reduce verbosity (only show first 50 instructions)'
    )
    parser.add_argument(
        '-o', '--output',
        type=str,
        help='Output trace to file (JSON format)'
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
        verbose=not args.quiet,
        trace_file=args.output
    )

    emulator.setup_memory()
    emulator.load_bootloader()
    emulator.setup_cpu_state()
    emulator.run()


if __name__ == '__main__':
    main()
