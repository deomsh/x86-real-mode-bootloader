;
; iboot.nasm: independent boot code (MBR, FAT16 boot sectors and FAT32 boot sector)
; by pts@fazekas.hu at Thu Dec 26 01:51:51 CET 2024
;
; Compile with: nasm -O0 -w+orphan-labels -f bin -o iboot.bin iboot.nasm
; Minimum NASM version required to compile: 0.98.39
;
; Differences between iboot.nasm (this file, independent) and boot.nasm:
;
; * This file is frozen, new development goes to boot.nasm only.
; * This file contains boot sector code which is independent of the MBR
;   code, i.e. it can work even if the MBR code is replaced with another
;   implementation conforming to the load protocol.
; * In boot.nasm, the boot sector code does calls into the MBR code (for
;   code reuse, and to make the total shorter), thus they have to be
;   replaced together.
;
; See fat16m.nasm for more docs and TODOs.
;
; MS-DOS 4.01--6.22 (and PC-DOS 4.01--7.1) boot process from HDD:
;
; * The BIOS loads the MBR (HDD sector 0 LBA) to 0x7c00 and jumps to
;   0:0x7c00. The BIOS passes .drive_number (typically 0x80) in register DL.
;   See also https://pushbx.org/ecm/doc/ldosboot.htm#protocol-rombios-sector
; * The MBR contains the boot code and the partition table (up to 4 primary
;   partitions).
; * The boot code in the MBR finds the first active partition, and loads its
;   boot sector (sector 0 of the partition) to jumps to 0:0x7c00. The boot
;   code in the MBR passes .drive_number in register DL.
;   See also https://pushbx.org/ecm/doc/ldosboot.htm#protocol-mbr-sector
; * In case of MS-DOS and PC-DOS the boot sector is the very first sector of
;   a FAT12 or FAT16 file system, and it starts with a jump instruction,
;   then it contains the FAT filesystem headers (i.e. BIOS Parameter Block,
;   BPB), then it contains the boot code.
; * The boot code in the boot sector (msboot, MS-DOS source:
;   boot/msboot.asm) finds io.sys in the root directory (and it saves the
;   directory entry to 0x500), msdos.sys (and it saves the directory entry
;   to 0x520), loads the first 3 sectors of io.sys (i.e. msload) to 0x700,
;   and jumps to 0x70:0. msboot passes .drive_number in DL,
;   .media_descriptor (media byte) in CH, sector number of the first cluster
;   (cluster 2) in AX:BX.
;   See also https://pushbx.org/ecm/doc/ldosboot.htm#protocol-sector-msdos6
; * msload (MS-DOS source: bios/msload.asm) loads the rest of io.sys
;   (msbio.bin) to 0x700 (using the start cluster number put at 0x51a by
;   msboot), and jumps to 0x70:0. The file start offset of msbio.bin within
;   io.sys depends on the DOS version. It's the \xe9 (jmp near) byte of the
;   first \x0d\x0a\x00\xe9 string within the first 0x600 bytes of io.sys.
;   msload passes DL, CH, AX and BX as above.
; * The first 3 bytes of msbio.bin (START$) jump to the INIT function.
; * The INIT function (part of MS-DOS source: bios/msinit.asm) loads
;   msdos.sys (using the start cluster number put at 0x53a by msboot). It
;   starts with the cluster number in the root directory (already load by
;   msboot to word [0x53a] == word [0x520+0x1a]).
; * DOS processes config.sys, loading additional drivers.
; * DOS loads command.com.
; * command.com processes autoexec.bat.
; * command.com displays the prompt (e.g. `C>` or `C:\>`), and waits for
;   user input.
;
; The boot code in this file can boot from a HDD, but not from a floppy
; disk, because:
;
; * Reading a FAT12 FAT is not implemented here, and most floppies have
;   a FAT12 filesystem.
; * Disk initialization parameter table (DPT,
;   https://stanislavs.org/helppc/int_1e.html) initialization is skipped,
;   for example, .sectors_per_track is not set in the DPT.
;

bits 16
cpu 8086
;org 0x7c00  ; Independent.

%macro assert_fofs 1
  times +(%1)-($-$$) times 0 nop
  times -(%1)+($-$$) times 0 nop
%endm
%macro assert_at 1
  times +(%1)-$ times 0 nop
  times -(%1)+$ times 0 nop
%endm

PSTATUS:  ; Partition status.
.ACTIVE equ 0x80

CHS_OR_LBA:
.CHS equ 0x90
.LBA equ 0x0e  ; 0x0c may also indicate LBA.

BOOT_SIGNATURE equ 0xaa55  ; dw.

%macro fat_header 9  ; %1: .reserved_sector_count value; %2: .sector_count value; %3: .fat_count, %4: .sectors_per_cluster, %5: fat_sectors_per_fat, %6: fat_rootdir_sector_count, %7: fat_32 (0 for FAT16, 1 for FAT32), %8: partition_1_sec_ofs; %9: fat_chs_or_lba.
; More info about FAT12, FAT16 and FAT32: https://en.wikipedia.org/wiki/Design_of_the_FAT_file_system
;
.header:	jmp strict short .boot_code
.chs_or_lba:	db (%9)  ; nop  ; 0x90 for CHS. Another possible value is 0x0e (or 0xc) for LBA. Windows 95 OSR2, Windows 98 and Windows ME boot sector code uses it for enabling LBA in msload, which passes it on to msbio.
assert_at .header+3
.oem_name:	db 'MSDOS5.0'
assert_at .header+0xb
.bytes_per_sector: dw 0x200  ; The value 0x200 is hardcoded in boot_sector.boot_code, both explicitly and implicitly.
assert_at .header+0xd
.sectors_per_cluster: db (%4)
assert_at .header+0xe
.reserved_sector_count: dw (%1)+(%8)
assert_at .header+0x10
.fat_count:	db (%3)  ; Must be 1 or 2. MS-DOS 6.22 supports only 2. Windows 95 DOS mode supports 1 or 2.
assert_at .header+0x11
.rootdir_entry_count: dw (%6)<<4  ; Each FAT directory entry is 0x20 bytes. Each sector is 0x200 bytes.
assert_at .header+0x13
%if (%7)>0 || (((%2)+(%8))&~0xffff)
.sector_count_zero: dw 0  ; See true value in .sector_count.
%else
.sector_count_zero: dw (%2)+(%8)
%endif
assert_at .header+0x15
.media_descriptor: db 0xf8  ; 0xf8 for HDD.
assert_at .header+0x16
%if (%7)>0  ; FAT32.
.sectors_per_fat: dw 0
%else
.sectors_per_fat: dw (%5)
%endif
assert_at .header+0x18
; FreeDOS 1.2 `dir c:' needs a correct value for .sectors_per_track and
; .head_count. MS-DOS 6.22 and FreeDOS 1.3 ignore these values (after boot).
.sectors_per_track: dw 1  ; Track == cylinder. Dummy nonzero value to pacify mtools(1). Will be overwritten with value from BIOS int 13h AH == 8.
assert_at .header+0x1a
.head_count: dw 1  ; Dummy nonzero value to pacify mtools(1). Will be overwritten with value from BIOS int 13h AH == 8.
assert_at .header+0x1c
.hidden_sector_count: dd 0  ; Occupied by MBR and previous partitions. Will be overwritten with value from the partition entry: partition start sector offset. !! Does MS-DOS 6.22 use it outside boot (probably no)? Does FreeDOS use it (probably no).
assert_at .header+0x20
.sector_count: dd (%2)+(%8)
assert_at .header+0x24
.fstype_fat1x: equ .header+0x36
.fstype_fat32: equ .header+0x52
.drive_number_fat1x: equ .header+0x24
.drive_number_fat32: equ .header+0x40
%if (%7)>0  ; FAT32.
; B1G-4K based on: rm -f fat32.img && mkfs.vfat -a -C -D 0 -f 1 -F 32 -i abcd1234 -r 128 -R 17 -s 8 -S 512 -h 63 --invariant fat32.img 1049604
; -R >=16 for Windows NT installation, it modifies sector 8 when making the partition bootable.
.sectors_per_fat_fat32: dd (%5)
assert_at .header+0x28
.mirroring_flags: dw 0  ; As created by mkfs.vfat.
assert_at .header+0x2a
.version: dw 0
assert_at .header+0x2c
.rootdir_start_cluster: dd 2
assert_at .header+0x30
.fsinfo_sec_ofs: dw 1+(%8)
assert_at .header+0x32
.first_boot_sector_copy_sec_ofs: dw 6+(%8)  ; 6 was created by mkfs.vfat, also for Windows XP. 4 would also work. There are up to 3 sectors here. Windows XP puts some extra boot code to sector 8 (of 16).
assert_at .header+0x34
.reserved:	dd 0, 0, 0
assert_at .header+0x40
.drive_number: db 0x80
assert_at .header+0x41
.reserved2:	db 0
assert_at .header+0x42
.extended_boot_signature: db 0x29
assert_at .header+0x43
.volume_id: dd 0x1234abcd  ; 1234-ABCD.
assert_at .header+0x47
.volume_label:	db 'NO NAME    '
assert_at .header+0x52
.fstype:	db 'FAT32   '
assert_at .header+0x5a
%else  ; Non-FAT32.
; Based on: truncate -s 2155216896 hda.img  # !! Magic size value for QEMU, see what.txt.
; Based on: rm -f fat16.img && mkfs.vfat -a -C -D 0 -f 1 -F 16 -i abcd1234 -r 128 -R 57 -s 64 -S 512 -h 63 --invariant fat16.img 2096766
assert_at .header+0x24
.drive_number: db 0x80
assert_at .header+0x25
.var_unused: db 0  ;.var_read_head: db 0  ; Can be used as a temporary variable in .boot_code.
assert_at .header+0x26
.extended_boot_signature: db 0x29
assert_at .header+0x27
.volume_id: dd 0x1234abcd  ; 1234-ABCD.
assert_at .header+0x2b
.volume_label:	db 'NO NAME    '
assert_at .header+0x36
%if (%7)<0
.fstype:	db 'FAT12   '
%else
.fstype:	db 'FAT16   '
%endif
assert_at .header+0x3e
%endif
.boot_code:
%endm

assert_fofs 0
mbr_for_independent:  ; Master Boot record, sector 0 (LBA) of the drive.
; More info about the MBR: https://wiki.osdev.org/MBR_(x86)
; More info about the MBR: https://en.wikipedia.org/wiki/Master_boot_record
; More info about the MBR: https://en.wikipedia.org/wiki/Master_boot_record#BIOS_to_MBR_interface
; More info about the MBR: https://en.wikipedia.org/wiki/Master_boot_record#MBR_to_VBR_interface
; More info about the MBR: https://pushbx.org/ecm/doc/ldosboot.htm#protocol-rombios-sector
; MBR code: https://web.archive.org/web/20100117123431/https://mirror.href.com/thestarman/asm/mbr/Win2kmbr.htm
; MBR code: https://github.com/egormkn/mbr-boot-manager/blob/master/mbr.asm
; MBR code: https://prefetch.net/blog/2006/09/09/digging-through-the-mbr/
; MBR code: https://web.archive.org/web/20080312222741/http://ata-atapi.com/hiwmbr.htm
; It is unusual to have a FAT filesystem header in an MBR, but that's our main innovation to make `mdir -i hda.img` work.
fat_header 1, 0, 2, 1, 1, 1, 1, 0x3f, 0x90  ; !! fat_reserved_sector_count, fat_sector_count, fat_fat_count, fat_sectors_per_cluster, fat_sectors_per_fat, fat_rootdir_sector_count, fat_32, partition_1_sec_ofs, fat_chs_or_lba.
.org: equ -0x7e00+.header
		times 0x5a-($-.header) db '+'  ; Pad FAT16 headers to the size of FAT32, for uniformity.
;.boot_code:
.var_change: equ .header-2  ; db.
.var_bs_cyl_sec: equ .header-4  ; dw. CX value (cyl and sec) for int 13h AH == 2 and AH == 4.
.var_bs_drive_number: equ .header-5  ; db. DH value (drive number) for int 13h AH == 2 and AH == 4.
.var_bs_head: equ .header-6  ; db. DL value (head) for int 13h AH == 2 and AH == 4.
; This MBR .boot_code is smarter than typical MBR .boot code, because it
; ignores the CHS values in the partition table (and uses the LBA values
; instead), so that it remains independent of various LBA-to-CHS mappings in
; emulators such as QEMU.
;
; !! Does the Windows 95 MBR (`ms-sys -9`) also ignore the CHS value in the partition entry?
; !! Use EBIOS and LBA if available, to boot from partitions starting above 8 GiB.
		cli
		xor ax, ax
		mov si, 0x7c00
		mov ss, ax
		mov sp, si
		sti
		cld
		push ss
		pop ds
		push ss
		pop es
		mov di, -.org+.header
		mov bp, di  ; BP := 0x600 (address of relocated MBR).
		mov cx, 0x100
		rep movsw  ; Copy MBR from 0:0x7c00 to 0:0x600.
		jmp 0:-.org+.after_code_copy
		; Fall through, but within the copy.
.after_code_copy:
		mov ah, 0x41  ; Check extensions (EBIOS). DL already contains the drive number.
		mov bx, 0x55aa
		int 0x13  ; BIOS syscall.
		jc .done_ebios	 ; No EBIOS.
		cmp bx, 0xaa55
		jne .done_ebios	 ; No EBIOS.
		ror cl, 1
		jnc .done_ebios	 ; No EBIOS.
		mov [bp-.header+.read_sector+1], al  ; Self-modifying code: change the `jmp short .read_sector_chs' at `.read_sector' to `jmp short .read_sector_lba'. (AL is still 0 here.)
%if 0  ; Needs to be propagated to be useful.
		mov byte [bp-.header+.chs_or_lba], CHS_OR_LBA.LBA  ; Indicate to msload and msbio in MS-DOS v7 to use LBA.
%endif
.done_ebios:	xor di, di  ; Workaround for buggy BIOS. Also the 0 value will be used later.
		mov ah, 8  ; Read drive parameters.
		mov [bp-.header+.drive_number], dl  ; .drive_number passed to the MBR .boot_code by the BIOS in DL.
		push dx
		int 0x13  ; BIOS syscall.
		jc .jc_fatal1
		and cx, byte 0x3f
		mov [bp-.header+.sectors_per_track], cx
		mov dl, dh
		mov dh, 0
		inc dx
		mov [bp-.header+.head_count], dx
		mov ah, 1  ; Get status of last drive operation. Needed after the AH == 8 call.
		pop dx  ; mov dl, [bp-.header+.drive_number]
		int 0x13  ; BIOS syscall.

		mov si, -.org+.partition_1-0x10
		mov cx, 4  ; Try at most 4 partitions (that's how many fit to the partition table).
.next_partition:
		add si, byte 0x10
		cmp byte [si], PSTATUS.ACTIVE
		loopne .next_partition
		jne .fatal1
		; Now: SI points to the first active partition entry.
		mov ax, [si+8]    ; Low  word of sector offset (LBA) of the first sector of the partition.
		mov dx, [si+8+2]  ; High word of Sector offset (LBA) of the first sector of the partition.
		mov bx, sp  ; BX := 0x7c00. That's where we load the partition boot sector to.
		push di  ; .var_change := 0. DI is still 0.
		call .read_sector_chs  ; Ruins AX, CX and DX. Sets CX to CHS cyl_sec value. Sets DH to CHS head value. Sets DL to drive number.
		cmp word [0x7dfe], BOOT_SIGNATURE
		jne .fatal1
.jc_fatal1:	jc .fatal1  ; This never matches after the BOOT_SIGNATURE check, but it matches after `jc .jc_fatal1'.
		push cx  ; mov [bx-.header+.var_bs_cyl_sec], cx  ; Save it for a subsequent .write_boot_sector.
		push dx  ; mov [bx-.header+.var_bs_head], dh  ; mov [bx-.header+.var_bs_drive_number], dl  ; Save it for a subsequent .write_boot_sector.
		; Now fix some FAT12, FAT16 or FAT32 BPB fields
		; (.drive_number, .hidden_sector_count, .sectors_per_track
		; and .head_count) in the in-memory boot sector just loaded.
		;
		; This is to help our boot_sector.boot_code (and make room
		; for more code in our boot_sector), and also to help other
		; operating systems to boot (e.g. if a `sys c:' command has
		; overwritten our boot_sector.boot_code).
		;
		; We are a bit careful, and we don't fix anything if the BPB
		; doesn't indicate a FAT filesystem. That's because the user
		; may have created a different filesystem since the initial
		; boot.
		;
		; !! Write the changes back to the on-disk boot sector (and
		;    also to the on-disk MBR), in case an operating system
		;    reads it again. For example, `dir c:' in FreeDOS 1.0,
		;    1.1 and 1.2 (but not 1.3) needs a correct
		;    boot_sector.sectors_per_track and
		;    boot_sector.head_count, even if not booted from our HDD.
		; !! Write CHS values in the partition table back to the
		;    on-disk MBR. This is to make FreeDOS kernel display
		;    fewer warnings at boot time.
		;
		; !! Add code to reinstall our mbr.header and mbr.boot_code
		;    after an installer has overwritten it.
		mov cx, 1
		push si
		mov si, -.org+.drive_number
		mov ax, 'FA'
		cmp [bx-.header+.fstype_fat1x], ax
		jne .no_fat1
		cmp word [bx-.header+.fstype_fat1x+2], 'T1'  ; Match 'FAT12' and 'FAT16'.
		je .fix_fat1
.no_fat1:	cmp [bx-.header+.fstype_fat32], ax
		jne .done_fatfix
		cmp word [bx-.header+.fstype_fat32+2], 'T3'  ; Match 'FAT32'. PC DOS 7.1 detects FAT32 by `cmp word [bx-.header+.sectors_per_fat], 0 ++ je .fat32'. More info: https://pushbx.org/ecm/doc/ldosboot.htm#protocol-sector-ibmdos
		jne .done_fatfix
.fix_fat32:	lea di, [bx-.header+.drive_number_fat32]
		call .change_bpb
		jmp short .fix_fat
.fix_fat1:	lea di, [bx-.header+.drive_number_fat1x]
		call .change_bpb
.fix_fat:	pop si
		push si
		add si, byte 8
		lea di, [bx-.header+.hidden_sector_count]
		mov cl, 4  ; 4 bytes.
		call .change_bpb  ; Copy to dword [bx-.header+.hidden_sector_count+2].
		mov si, -.org+.sectors_per_track
		lea di, [bx-.header+.sectors_per_track]
		mov cl, 4  ; 4 bytes.
		call .change_bpb  ; Copy to word [bx-.header+sectors_per_track] and then word [bx-.header+.head_count].
		pop si  ; Pass it to boot_sector.boot_code according to the load protocol.
.done_fatfix:	;mov dl, [bp-.header+.drive_number]  ; No need for mov, DL still contains the drive number. Pass .drive_number to the boot sector .boot_code in DL.
		cmp [bx-.header+.var_change], ch  ; CH == 0.
		je .done_write
; Writes the boot sector at BX back to the partition.
; Inputs: ES:BX: buffer address, DL: .drive_number.
; Ruins: AX, flags.
;
; We do this in case an operating system reads it again. For example, `dir
; c:' in FreeDOS 1.0, 1.1 and 1.2 (but not 1.3) needs a correct
; boot_sector.sectors_per_track and boot_sector.head_count, even if not
; booted from our HDD.
.write_boot_sector:
		mov ax, 0x301  ; AL == 1 means: read 1 sector.
		pop dx  ; Restore [bx-.header+.var_bs_head] to DH and [bx-.header+.var_bs_drive_number] to DL (unnecessary).
		pop cx  ; Restore [bx-.header+.var_bs_cyl_sec] to CX.
		int 0x13  ; BIOS syscall to write sectors.
		; Ignore failure in CL.
.done_write:	;mov byte [si], PSTATUS.ACTIVE  ; Fake active partition for boot sector. Not needed, we've already checked above.
		; Also pass pointer to the booting partition in DS:SI.
		;times 2 pop di  ; No need: the boot sector will set its own SS:SP.
		jmp 0:0x7c00  ; Jump to boot sector .boot_code.
		; Not reached.
.fatal1:	mov si, -.org+.errmsg_os
; Prints NUL-terminated message starting at SI, and halts. Ruins many registers.
.fatal:
.next_msg_byte:	lodsb
		test al, al  ; Found terminating NUL?
		jz .halt
		mov ah, 0xe
		mov bx, 7
		int 0x10
		jmp short .next_msg_byte
.halt:		cli
.hang:		hlt
		jmp short .hang
; Changes the BPB in the boot sector just loaded.
; Inputs: SI: source buffer; DI: destination buffer; CX: number of bytes to change, must be positive.
; OutputS: CX: 0.
; Ruins: SI, DI.
.change_bpb:	cmpsb
		je .change_bpb_cont
		dec si
		dec di
		movsb
		inc byte [bx-.header+.var_change]
%if 0  ; Just for debugging.
		push ax
		push bx
		mov ax, 0xe00|'*'
		mov bx, 7
		int 0x10
		pop bx
		pop ax
%endif
.change_bpb_cont:
		loop .change_bpb
		ret

; Reads a single sector from the specified BIOS drive, using LBA (EBIOS) if available, otherwise falling back to CHS.
; Inputs: DX:AX: LBA sector number on the drive; ES:BX: points to read buffer.
; Output: DL: drive number. Halts on failures.
; Ruins: AX, CX, DX (output), flags.
.read_sector:
		jmp short .read_sector_chs  ; Self-modifying code: EBIOS autodetection may change this to `jmp short .read_sector_lba' by setting byte [bp-.header+.read_sector+1] := 0.
		; Fall through to .read_sector_lba.

; Reads a single sector from the specified BIOS drive, using LBA (EBIOS).
; Inputs: DX:AX: LBA sector number on the drive; ES:BX: points to read buffer.
; Output: DL: drive number. Halts on failures.
; Ruins: AH, CX, DX (output), flags.
.read_sector_lba:  ; Using EBIOS. !! Detect EBIOS.
		push si
		; Construct .dap (Disk Address Packet) for BIOS int 13h AH == 42, on the stack.
		xor cx, cx
		push cx  ; High word of .dap_lba_high.
		push cx  ; Low word of .dap_lba_high.
		push dx  ; High word of .dap_lba.
		push ax  ; Low word of .dap_lba.
		push es  ; .dap_mem_seg.
		push bx  ; .dap_mem_ofs.
		inc cx
		push cx  ; .dap_sector_count := 1.
		mov cl, 0x10
		push cx  ; .dap_size := 0x10.
		mov si, sp
		mov ah, 0x42
		mov dl, [bp-.header+.drive_number]  ; !! This offset depends on the filesystem type (FAT16 or FAT32). %if fat_32.
		int 0x13  ; BIOS syscall to read sectors using EBIOS.
.jc_fatal_disk:	mov si, -.org+.errmsg_disk
		jc .fatal
		add sp, cx  ; Pop the .dap and keep CF (indicates error).
		pop si
		ret

; Reads a single sector from the specified BIOS drive, using CHS.
; Inputs: DX:AX: LBA sector number on the drive; ES:BX: points to read buffer.
; Output: DL: drive number; CX: CHS cyl_sec value; DH: CHS head value. Halts on failures.
; Ruins: AX, CX (output), DH (output), flags.
.read_sector_chs:
		; Converts sector offset (LBA) value in DX:AX to BIOS-style
		; CHS value in CX and DH. Ruins DL, AX and flag. This is
		; heavily optimized for code size.
		xchg ax, cx
		xchg ax, dx
		xor dx, dx
		div word [bp-.header+.sectors_per_track]  ; We assume that .sectors_per_track is between 1 and 63.
		xchg ax, cx
		div word [bp-.header+.sectors_per_track]
		inc dx  ; Like `inc dl`, but 1 byte shorter. Sector numbers start with 1.
		xchg cx, dx  ; CX := sec value.
		div word [bp-.header+.head_count]  ; We assume that .head_count is between 1 and 255.
		; Now AX is the cyl value (BIOS allows between 0 and 1023),
		; DX is the head value (between 0 and 254), thus the DL is
		; also the head value, CX is the sec value (BIOS allows
		; between 1 and 63), thus CL is also the sec value. Also the
		; high 6 bits of AH (and AX) are 0, because BIOS allows cyl
		; value less than 1024. (Thus `ror ah, 1` below works.)
		;
		; BIOS int 13h AH == 2 wants the head value in DH, the low 8
		; bits of the cyl value in CH, and it wants CL ==
		; (cyl>>8<<6)|head. Thus we copy DL to DH (cyl value), AL to
		; CH (low 8 bits of the cyl value), AH to CL (sec value),
		; and or the 2 bits of AH (high 8 bits of the cyl value)
		; shifted to CL.
		mov dh, dl
		mov ch, al
		ror ah, 1
		ror ah, 1
		or cl, ah
		mov dl, [bp-.header+.drive_number]  ; !! This offset depends on the filesystem type (FAT16 or FAT32). %if fat_32.
		mov ax, 0x201  ; AL == 1 means: read 1 sector.
		int 0x13  ; BIOS syscall to read sectors.
		jc .jc_fatal_disk
.ret:		ret

.errmsg_disk:	db 'Disk error', 0	
.errmsg_os:	db 'No OS', 0
		;Other typical error message: db 'Missing operating system', 0
		;Other typical error message: db 'Invalid partition table', 0
		;Other typical error message: db 'Error loading operating system', 0

		times 0x1b8-($-.header) db '-'  ; Padding.
assert_at .header+0x1b8
.disk_id_signature: dd 0x9876edcb
assert_at .header+0x1bc
.reserved_word_0: dw 0
.partition_1:
assert_at .header+0x1be  ; Partition 1.
		times 4*0x10 db 0 ; Partition table consisting of 4 primary partitions.
assert_at .header+0x1fe
.boot_signature: dw BOOT_SIGNATURE
assert_at .header+0x200

; ---

%macro fat_boot_sector_common 0
.org: equ -0x7c00+.header
;.boot_code:
		mov bp, -.org+.header
		cli
		xor ax, ax
		mov ss, ax
		mov sp, bp
%if 0  ; Our mbr.boot_code has already done it. We save space here by omitting it.
		les bx, [si+8]  ; Boot code in MBR has made DS:SI point to the partition entry. +8 is the start sector offset (LBA).
		mov [bp-.header+.hidden_sector_count], bx
		mov [bp-.header+.hidden_sector_count+2], es  ; High word of the partition start sector offset (LBA).
%endif

		mov ds, ax
		;mov es, ax  ; We set ES := 0 later for FAT16. FAT32 doesn't need it.
		cld
		sti

%if 0  ; Our mbr.boot_code has already done it. We save space here by omitting it.
		xor di, di  ; Workaround for buggy BIOS.
		mov ah, 8  ; Read drive parameters.
		mov [bp-.header+.drive_number], dl  ; .drive_number passed to the boot sector .boot_code by the MBR .boot_code in DL.
		int 0x13  ; BIOS syscall.
		jc .jmp_fatal
		and cx, byte 0x3f
		mov [bp-.header+.sectors_per_track], cx
		mov dl, dh
		mov dh, 0
		inc dx
		mov [bp-.header+.head_count], dx
		mov ah, 1  ; Get status of last drive operation. Needed after the AH == 8 call.
		mov dl, [bp-.header+.drive_number]
		int 0x13  ; BIOS syscall.
%endif

%if 0  ; Not needed when booting from HDD.
		; The disk initialization parameter table (or diskette
		; parameter table) is used by BIOS when reading and writing
		; floppy disks. It's a global table, DOS changes the pointer
		; to it (int 1eh) before each flopppy disk read or write.
		;
		; More info:
		;
		; * https://retrocomputing.stackexchange.com/questions/30690/view-and-modify-active-diskette-parameter-table
		; * https://stanislavs.org/helppc/int_1e.html
		; * https://fd.lod.bz/rbil/interrup/bios/1e.html
		; * http://www.ctyme.com/intr/rb-2445.htm
		cli
		mov byte [bp-.header+.new_dipt+9], 0xf  ; Set floppy head bounce delay in disk initialization parameter table. (in milliseconds to 0xf) Why? https://retrocomputing.stackexchange.com/q/31099
		mov cx, [bp-.header+.sectors_per_track]
		mov [bp-.header+.new_dipt+4], cl  ; Set sectors-per-track in disk initialization parameter table.
		mov [bx+2], ds
		mov word [bx], -.org+.new_dipt  ; Update pointer to disk initialization parameter table.
		sti
		mov ah, 0  ; Reset disk system.
		mov dl, 0  ; Reset floppies only.
		int 0x13  ; BIOS syscall.
		jnc .ok
.jmp_fatal:	jmp near .fatal
.ok:
%endif
%endm  ; fat_boot_sector_common

; --- FAT32 boot sector (currently it doesn't work, it needs precomputation).
;
; Features and requirements: !! Update.
;
; * It is able to boot MS-DOS v7 (Windows 95 OSR2, Windows 98 FE, Windows 98
;   SE, the unofficial MS-DOS 8.0 based on Windows ME: MSDOS8.ISO on
;   http://www.multiboot.ru/download/) io.sys and IBM PC DOS 7.1 ibmbio.com
;   and ibmdos.com. Earlier versions of MS-DOS and IBM PC DOS don't support
;   FAT32.
; * It uses EBIOS LBA (available since 1995--1996 in PC BIOS on actual
;   hardware), it cannot fall back to older CHS.
; * All the boot code fits to the boot sector (512 bytes). No need for
;   loading a sector 2 or 3 like how Windows 95--98--ME--XP boots.
; * It works with a 8086 CPU (no need for 386). (It's 25 bytes longer than
;   the 386 implementation).
; * It can only boot from HDD, there is no floppy disk support. (That would
;   need CHS sector reading and DPT modifications.) Also typical floppy
;   disks are too small for a FAT32 filesystem.
; * It needs a custom sys.com (see below) to make a HDD bootable.
;
; History: !! Update.

; * Based on the FreeDOS FAT32 boot sector.
; * Modified heavily by Eric Auer and Jon Gentle in July 2003.
; * Modified heavily by Tinybit in February 2004.
; * Snapshotted code starting at *Entry_32* in stage2/grldrstart.S in
;   grub4dos-0.4.6a-2024-02-26, by pts.
; * Adapted to the MS-DOS v7 load protocol (moved away from the
;   GRLDR--NTLDR load protocol) by pts in January 2025.
;
; You can use and copy source code and binaries under the terms of the
; GNU Public License (GPL), version 2 or newer. See www.gnu.org for more.
;
; To install this boot sector boot code to a boot sector, a custom sys.com
; must do the following:
;
; * Replace the first 3 bytes of the boot sector with 0xeb, 0x58, 0x90 (jump
;   and nop).
; * Keep bytes between offset 3 and 0x5a (first inclusive, last exclusive).
;   This contains the FAT32 filesystem headers, including the .oem_name,
;   the BPB and the EBPB.
; * (All values are stored as little endian.)
; * Set .drive_number if it's not 0x80 (first HDD). Usually it is.
; * Precompute the clusters_sec_ofs_value (4 bytes).
; * Copy the low word of clusters_sec_ofs value to offset 0x5b
;   (.cso_init_low).
; * Copy the high word of clusters_sec_ofs value to offset 0x5e
;   (.cso_init_high).
; * Set the .hidden_sector_count value (dword at 0x1c) to the start sector
;   offset (LBA) of the patition. This is not needed for the boot sector
;   code , but some operating systems may use it for booting or accessing
;   the filesystem. (!! which)
; * Set the .sectors_per_track value (word at 0x18) to the CHS cyls value,
;   according to the disk geometry. This is not needed for the boot sector
;   code (because it used EBIOS LBA), but some operating systems may use it
;   for booting or accessing the filesystem. (!! which)
; * Set the .head_count value (word at 0x1a) to the CHS cyls value,
;   according to the disk geometry. This is not needed for the boot sector
;   code (because it used EBIOS LBA), but some operating systems may use it
;   for booting or accessing the filesystem. (!! which)
; * Write the 512 bytes back to the boot sector.
;
; Memory layout:
;
; * 0...0x400: Interrupt table.
; * 0x400...0x500: BIOS data area.
; * 0x500...0x700: Unused.
; * 0x700...0xf00: 4 sectors loaded from io.sys.
; * 0xf80...0x1180: Sector read from the FAT32 FAT. The reason for 0xf80 is that it is >= 0xf00, and es can be conveniently intiailized as `mov es, [bp-.header+.media_descriptor]`.
; * 0x1100..0x7b00: Unused.
; * 0x7b00...0x7c00: Stack used by this boot sector.
; * 0x7c00...0x7e00: This boot sector.

assert_fofs 0x200
boot_sector_fat32:
		fat_header 1, 0, 2, 1, 1, 1, 1, 0, 0xe  ; !! fat_reserved_sector_count, fat_sector_count, fat_fat_count, fat_sectors_per_cluster, fat_sectors_per_fat, fat_rootdir_sector_count, fat_32, partition_1_sec_ofs, fat_chs_or_lba.
%if 1  ; size optimization: Precompute most of this (and for FAT16 as well) at filesystem creation time.
; !!! Test this boot code, maybe it doesn't even work.
		mov di, -1  ; Precomputed .var_clusters_sec_ofs (low word) by the custom sys.com.
.cso_init_low: equ $-2
		mov si, -1  ; Precomputed .var_clusters_sec_ofs+2 (high word) by the custom sys.com.
.cso_init_high: equ $-2
%endif
		fat_boot_sector_common
.var_single_cached_fat_sec_ofs: equ .boot_code  ; dd. Last accessed FAT sector offset (LBA) (overwriting unused bytes).
.var_fat_sec_ofs: equ .boot_code+4  ; dd. Sector offset (LBA) of the first FAT in this FAT filesystem, from the beginning of the drive (overwriting unused bytes). Only used if .fat_sectors_per_cluster<4.
.var_clusters_sec_ofs: equ .header-4  ; dd. Sector offset (LBA) of the clusters (i.e. cluster 2) in this FAT filesystem, from the beginning of the drive. This is also the start of the data.

		; MS-DOS 4.01, MS-DOS 6.22 and IBM PC DOS 7.1 boot sector
		; all receive the drive number in .drive_number, and they
		; ignore the initial value of DL (which the MBR boot code
		; typically sets to the drive number).
		;
		; To save space, we do the same here.
		;mov [bp-.header+.drive_number], dl

		; Figure out where FAT and data areas start.
%if 0  ; Too much code, see precomputed.
		xchg dx, ax  ; DX := AX; AX := junk.
		mov ax, [bp-.header+.reserved_sector_count]
		add ax, [bp-.header+.hidden_sector_count]
		adc dx, [bp-.header+.hidden_sector_count+2]
		mov [bp-.header+.var_fat_sec_ofs], ax
		mov [bp-.header+.var_fat_sec_ofs+2], dx
		xor cx, cx
		mov cl, [bp-.header+.fat_count]  ; 1 or 2.
.add_fat:	add ax, [bp-.header+.sectors_per_fat_fat32]
		adc dx, [bp-.header+.sectors_per_fat_fat32+2]
		loop .add_fat
		push si
		push di  ; dword [bp-.header+.var_clusters_sec_ofs] := DX:AX.
%else
		push si
		push di  ; dword [bp-.header+.var_clusters_sec_ofs] := SI:DI.
%endif

%if 0  ; Too much code, this doesn't fit. Without this subsequent floppy access in MS-DOS v7 may not work. (TODO(pts): Double check, not in an emulator.)
		mov bx, 0x1e<<2
		lds si, [bx]  ; int 1eh vector (DPT).
		push ds  ; Segment of dword [.var_orig_int13_vector].
		push si  ; Offset of dword [.var_orig_int13_vector].
		push ss  ; Will be discarded by MS-DOS v7 msload. Push segment 0 for compatibility. In practice, msload in MS-DOS v7 ignores this value.
		;mov bx, 0x1e<<2  ; No need, already true.
		push bx  ; Will be discarded by MS-DOS v7 msload. Push offset 0x78 == (0x1e<<2) for compatibility. In practice, msload in MS-DOS v7 ignores this value.

		push es
		pop ds  ; DS := ES (0).
%endif

		; Search the root directory for a kernel file.
		mov ax, [bp-.header+.rootdir_start_cluster]
		mov dx, [bp-.header+.rootdir_start_cluster+2]
                ; Now: DX:AX == the sector offset (LBA) of the root directory in this FAT filesystem.
		mov bh, 3  ; BH := missing-filename-bitset (io.sys and msdos.sys).

		mov es, [bp-.header+.jmp_far_inst+3]  ; mov es, 0x700>>4. Load root directory and kernel (io.sys) starting at 0x70:0 (== 0x700).
		mov [bp-.header+.var_single_cached_fat_sec_ofs], ds   ; Set to 0, i.e. cache empty.
		mov [bp-.header+.var_single_cached_fat_sec_ofs+2], ds ; Set to 0, i.e. cache empty.

.next_rootdir_cluster:
		push dx
		push ax  ; Save cluster number (DX:AX).
		call .cluster_to_lba  ; Also sets CL to [bp-.header+.sectors_per_cluster].
		jc .fatal1
		; Now: CL is sectors per cluster; DX:AX is sector offset (LBA).
.read_rootdir_sector:
                ; Now: DX:AX == the next sector offset (LBA) of the root directory in this FAT filesystem; CL: number of root directory sectors remaining in the current cluster.
		call .read_disk
		xor di, di  ; Points to next directory entry to compare filename against.
.next_entry:  ; Search for kernel file name, and find start cluster.
		push cx  ; Save.
		push di  ; Save.
		mov si, -.org+.io_sys
		mov cx, 11  ; .io_sys_end-.io_sys
		repe cmpsb
		jne .not_io_sys
		cmp [es:di-11+0x1c+2], cl  ; 0x1c is the offset of the dword-sized file size in the FAT directory entry.
		je .do_io_sys_or_ibmbio_com  ; Jump if file size of io.sys is shorter than 0x10000 bytes. This is true for MS-DOS v6 (e.g. 6.22), false for MS-DOS v7 (e.g. Windows 95).
		mov byte [bp-.header+.jmp_far_inst+2], 2  ; MS-DOS v7 load protocol wants `jmp 0x70:0x200', we set the 2 here.
		and bh, ~2  ; No need for msdos.sys.
.do_io_sys_or_ibmbio_com:
		mov si, 0x500+0x1a  ; Load protocol: io.sys expects directory entry of io.sys at 0x500.
		and bh, ~1
		jmp short .copy_entry
.not_io_sys:
		pop di
		push di
		inc cx  ; Skip over NUL.
		add si, cx  ; Assumes that .ibmbio_com follows .io_sys. mov si, -.org+.ibmbio_com
		mov cl, 11  ; .io_sys_end-.io_sys
		repe cmpsb
		je .do_io_sys_or_ibmbio_com
		pop di
		push di
		add si, cx  ; Assumes that .ibmdos_com follows .ibmbio_com. Like this, but 1 byte shorter: mov si, -.org+.ibmdos_com
		mov cl, 11  ; .ibmdos_com_end-.ibmdos_com  ; CH is already 0.
		repe cmpsb
		jne .not_ibmdos_com
		and bh, ~2
		mov si, 0x520+0x1a  ; Load protocol: io.sys expects directory entry of msdos.sys at 0x520.
.copy_entry:	; MS-DOS <=6.22 and IBM PC DOS 7.1 only use 2 words of the
		; 0x20-byte FAT directory entries copied to 0x500 (io.sys)
		; and 0x520 (msdos.sys); the low (+0x1a) and high (+0x14)
		; words of the file start cluster number. The latter is only
		; used for FAT32. So we only copy those words here.
		mov cx, [es:di-11+0x1a]  ; Copy low word of file start cluster number.
		mov [si], cx  ; Save to [0x500+0x1a] or [0x520+0x1a].
		mov cx, [es:di-11+0x14]  ; Copy high word of file start cluster number.
		mov [si+0x14-0x1a], cx  ; Save to [0x500+0x14] or [0x520+0x14].
		;jmp short .entry_done  ; Fall through.
.not_ibmdos_com:
		; Fall through to .entry_done.
.entry_done:	pop di  ; Restore.
		pop cx  ; Restore CL := number of root directory sectors remaining in the current cluster.
		;test bh, bh  ; Not needed, ZF is already correct because of `jne' or `and dh, ~...'.
		jz .found_both_sys_files
		lea di, [di+0x20]  ; DI := address of next directory entry.
		cmp di, [bp-.header+.bytes_per_sector]  ; 1 byte shorter than `cmp di, 0x200'.
		jne .next_entry ; next directory entry
		dec cl
		jnz .read_rootdir_sector ; loop over sectors in cluster
		pop ax
		pop dx  ; Restore cluster number (DX:AX).
		call .next_cluster
		jmp short .next_rootdir_cluster  ; read next cluster

.fatal1:	mov si, -.org+.errmsg_missing   ; EOC in rootdir cluster. This means that kernel file was not found.
; Prints NUL-terminated message starting at SI, and halts. Ruins many registers.
.fatal:
.next_msg_byte:	lodsb
		test al, al  ; Found terminating NUL?
		jz .halt
		mov ah, 0xe
		mov bx, 7
		int 0x10
		jmp short .next_msg_byte
.halt:		cli
.hang:		hlt
		jmp short .hang

.found_both_sys_files:  ; Kernel directory entry is found.
		pop dx
		pop ax  ; Discard cluster number (DX:AX).
		mov dx, [0x500+0x14]  ; Get cluster number high word.
		mov ax, [0x500+0x1a]  ; Get cluster number low word.
		push dx
		push ax  ; Save for .jump_to_msload.
		; Read msload (first few sectors) of the kernel (io.sys).
		mov ch, 4  ; Load up to 4 sectors. MS-DOS 7.x (Windows 95, Windows 98) and 8.0 (Windows ME) need >=4, MS-DOS 3.30..6.22 work with >=3.
.next_kernel_cluster:
		push dx
		push ax  ; Save cluster number (DX:AX).
		call .cluster_to_lba  ; Also sets CL to [bp-.header+.sectors_per_cluster].
		jnc .read_kernel_sector
		; EOC encountered before we could read 4 sectors.
		mov si, -.org+.errmsg_sys
		jmp short .fatal
.read_kernel_sector:  ; Now: CL is sectors per cluster; DX:AX is sector offset (LBA).
		call .read_disk
		mov bx, es
		lea bx, [bx+0x20]
		mov es, bx
		dec ch
		jnz .cont_kernel_cluster
.jump_to_msload:
		pop dx
		pop ax  ; Discard current cluster number. This will make the pops pop from the correct offset.
		; Fill registers according to MS-DOS v6 and v7 load protocol.
		mov dl, [bp-.header+.drive_number]
		; Fill registers according to MS-DOS v7 load protocol: https://pushbx.org/ecm/doc/ldosboot.htm#protocol-sector-msdos7
		pop di
		pop si  ; SI:DI == first cluster of load file in FAT32. This is used by MS-DOS v7 (e.g. Windows 95 OSR2), but IBM PC DOS 7.01 uses word [0x514] (high word) and word [0x51a] (low word) instead. (DI == first cluster of load file if FAT12 or FAT16.)
		; Fill registers according to MS-DOS v6 load protocol: https://pushbx.org/ecm/doc/ldosboot.htm#protocol-sector-msdos6
		mov ch, [bp-.header+.media_descriptor]  ; https://retrocomputing.stackexchange.com/q/31129 . IBM PC DOS 7.1 boot sector seems to set it, propagating it to the DRVFAT variable, propagating it to DiskRD. Does it actually use it? MS-DOS 6.22 fails to boot if this is not 0xf8 for HDD (Is it true? Does it accept 0xf0 as well? Or anything?). MS-DOS 4.01 io.sys GOTHRD (in bios/msinit.asm) uses it, as media byte. MS-DOS 4.01 io.sys GOTHRD (in bios/msinit.asm) uses it, as media byte.
		pop bx  ; mov bx, [bp-.header+.var_clusters_sec_ofs]
		pop ax  ; mov ax, [bp-.header+.var_clusters_sec_ofs+2]  ; IBMP PC DOS 7.1 needs AX:BX to have the value of .var_clusters_sec_ofs. MS-DOS v7 gets it from dword [ss:bp-4] instead.
		; Fill registers according to MS-DOS v7 load protocol: https://pushbx.org/ecm/doc/ldosboot.htm#protocol-sector-msdos7
		; True by design: SS:BP -> boot sector with (E)BPB, typically at linear 0x7c00.
		push ax
		push bx  ; dword [ss:bp-4] = (== dword [bp-.header+.var_clusters_sec_ofs]) first data sector of first cluster, including hidden sectors.
		; True by design: SS:BP -> boot sector with (E)BPB, typically at linear 0x7c00.
		; (It's not modified by this boot sector.) Diskette Parameter Table (DPT) may be relocated, possibly modified. The DPT is pointed to by the interrupt 1eh vector. If dword [ss:sp] = 0000_0078h (far pointer to IVT 1eh entry), then dword [ss:sp+4] -> original DPT
		; !! Currently not: word [ss:bp+0x1ee] points to a message table. The format of this table is described in lDebug's source files msg.asm and boot.asm, around uses of the msdos7_message_table variable.
		;
		; Pass orig DPT (int 13h vector value) to MS-DOS v6 and IBM
		; PC DOS 7.0 in DS:SI. MS-DOS v7 and IBM PC DOS 7.1 expect
		; it on the stack instead (we've already pushed it, as dword
		; [.var_orig_int13_vector] above): they pop 4 bytes from the
		; stack, and then they pop offset (word [SS:SP+4]), then
		; segment ((word [SS:SP+6])) of the original DPT.
		; https://stanislavs.org/helppc/int_1e.html
		;
		; !! Unfortunately we've omitted the code above to push it
		; for MS-DOS v7.
		;lds si, [bp-.header+.var_orig_int13_vector]  ; This would be used only by MS-DOS v6, but that doesn't support FAT32 anyway. Unfortunately SI already contains the high word of the start cluster number of load file.
.jmp_far_inst:	jmp 0x70:0  ; Jump to boot code (msload) loaded from io.sys. Self-modifying code: the offset 0 has been changed to 0x200 for MS-DOS v7.
.cont_kernel_cluster:
		dec cl  ; Consume 1 sector from the cluster.
		jnz .read_kernel_sector
		pop ax
		pop dx  ; Restore cluster number (DX:AX).
		call .next_cluster
		jmp short .next_kernel_cluster

; Given a cluster number, find the number of the next cluster in the FAT32
; chain. Needs .var_fat_sec_ofs.
; Inputs: DX:AX: cluster number.
; Outputs: DX:AX: next cluster number; SI: ruined.
.next_cluster:
		push es  ; Save.
		mov si, ax
		and si, byte 0x7f  ; Assumes word [bp-.header+.bytes_per_sector] == 0x200.
		shl si, 1
		shl si, 1
		push cx
		mov cx, 7  ; Will shift DX:AX right by 7. Assumes word [bp-.header+.bytes_per_sector] == 0x200.
.shr7_again:	shr dx, 1
		rcr ax, 1
		loop .shr7_again
		pop cx
		add ax, [bp-.header+.var_fat_sec_ofs]
		adc dx, [bp-.header+.var_fat_sec_ofs+2]
		mov es, [bp-.header+.media_descriptor]  ; Tricky way to `mov es, 0xf8'. Only works for FAT32 because itoverlaps .sectors_per_fat, and that is 0 for FAT32 only.
		; Now: DX:AX is the sector offset (LBA), BX is the byte offset within the sector.
		; Is it the last accessed and already buffered FAT sector?
		cmp ax, [bp-.header+.var_single_cached_fat_sec_ofs]
		jne .fat_read_sector_now
		cmp dx, [bp-.header+.var_single_cached_fat_sec_ofs+2]
		je .fat_sector_read
.fat_read_sector_now:
		mov [bp-.header+.var_single_cached_fat_sec_ofs], ax
		mov [bp-.header+.var_single_cached_fat_sec_ofs+2], dx  ; Mark sector DX:AX as buffered.
		call .read_disk ; read sector DX:AX to buffer.
.fat_sector_read:
		mov ax, [es:si] ; read next cluster number
		mov dx, [es:si+2]
		and dh, 0xf  ; Mask out top 4 bits, because FAT32 FAT pointers are only 28 bits.
		pop es  ; Restore.
		ret

; Converts cluster number to the sector offset (LBA).
; Inputs: DX:AX - target cluster; .var_clusters_sec_ofs, .sectors_per_cluster.
; Outputs on EOC: CF=1.
; Outputs on non-EOC: CF=0; DX:AX: sector offset (LBA); CL: .sectors_per_cluster value.
.cluster_to_lba:
		sub ax, byte 2
		sbb dx, byte 0
		cmp dx, 0x0fff
		jne .1
		cmp ax, strict word 0xfff8-2  ; Make it fail for 0, 1 and >=0xffffff8 (FAT32 minimum special cluster number).
.1:		jb .no_eoc
		stc
		ret
.no_eoc:	; Sector := (cluster-2) * clustersize + data_start.
		mov cl, [bp-.header+.sectors_per_cluster]
		push cx  ; Save for CH.
		jmp short .maybe_shift
.next_shift:	shl ax, 1
		rcl dx, 1
.maybe_shift:	shr cl, 1
		jnz .next_shift
		pop cx  ; Restore for CH.
		add ax, [bp-.header+.var_clusters_sec_ofs]
		adc dx, [bp-.header+.var_clusters_sec_ofs+2]  ; Also CF := 0 for regular data.
		ret

; Reads a sector from disk, using LBA or CHS.
; Inputs: DX:AX: sector offset (LBA); ES: ES:0 points to the destination buffer.
; Outputs: DX:AX incremented by 1, for next sector; SI: ruined.
; Ruins: flags.
.read_disk:
		push ax  ; Save.
		push cx  ; Save.
		push dx  ; Save.
; Reads a single sector from the specified BIOS drive, using LBA (EBIOS).
; Inputs: DX:AX: LBA sector number on the drive; ES:0: points to read buffer.
; Output: DL: drive number. Halts on failures.
; Ruins: AH, CX, DX (output), SI, flags.
.read_sector_lba:  ; Using EBIOS. !! Detect EBIOS.
		; Construct .dap (Disk Address Packet) for BIOS int 13h AH == 42, on the stack.
		xor cx, cx
		push cx  ; High word of .dap_lba_high.
		push cx  ; Low word of .dap_lba_high.
		push dx  ; High word of .dap_lba.
		push ax  ; Low word of .dap_lba.
		push es  ; .dap_mem_seg.
		push cx  ; .dap_mem_ofs.
		inc cx
		push cx  ; .dap_sector_count := 1.
		mov cl, 0x10
		push cx  ; .dap_size := 0x10.
		mov si, sp
		mov ah, 0x42
		mov dl, [bp-.header+.drive_number]  ; This offset depends on the filesystem type (FAT16 or FAT32). %if fat_32.
		int 0x13  ; BIOS syscall to read sectors using EBIOS.
		jc .fatal1
		add sp, cx  ; Pop the .dap and keep CF (indicates error).
; End of .read_sector_lba.
		pop dx  ; Restore.
		pop cx  ; Restore.
		pop ax  ; Restore.
		add ax, byte 1  ; Next sector.
		adc dx, byte 0
		ret

.errmsg_missing: db 'No '  ; Overlaps the following .io_sys.
.io_sys:	db 'IO      SYS', 0
.errmsg_sys: equ $-4  ; Just write 'SYS', 0.
.ibmbio_com:	db 'IBMBIO  COM'  ; Must be followed by .msdos_sys in memory. ibmbio.com in IBM PC DOS 7.1 supports FAT32.
.ibmbio_com_end:
.ibmdos_com:	db 'IBMDOS  COM'  ; Must follow .ibmdos_com in memory. ibmdos.com in IBM PC DOS 7.1 supports FAT32.
.ibmdos_com_end:

		times 0x1fe-($-.header) db '-'  ; Padding.
.boot_signature: dw BOOT_SIGNATURE
assert_at .header+0x200

; --- MS-PC-DOS-v4-v5-v6-v7 universal, independent FAT16 boot sector.
;
; Features and requirements:
;
; * !! Test it.
; * This boot sector is independent, i.e. it works from any MBR which sets
;   DL to the BIOS drive number.
; * Requirements: The following BPB fields are correctly populated:
;   .media_desciptor, .hidden_sector_count (partition sector offset (LBA)),
;   .sectors_per_track (CHS cyls) and .head_count (CHS heads).
; * This boot sector supports CHS only (no EBIOS, no LBA).
; * It is able to boot io.sys+msdos.sys from MS-DOS 4.01--6.22. Tested with:
;   4.01, 5.00 and 6.22.
; * It is able to boot ibmbio.com+ibmdos.com from IBM PC DOS 4.01--7.1.
;   Tested with: 7.0 and 7.1.
; * It is able to boot io.sys from Windows 95 RTM (OSR1), Windows 95 OSR 2,
;   Windows 98 FE, Windows 98 SE, and the unofficial MS-DOS 8.0 (MSDOS8.ISO
;   on http://www.multiboot.ru/download/) based on Windows ME.
; * With some additions (in the future), it may be able to boot FreeDOS
;   (kernel.sys), SvarDOS (kernel.sys), EDR-DOS (drbio.sys), Windows NT 3.x
;   (ntldr), Windows NT 4.0 (ntldr), Windows 2000 (ntldr), Windows XP
;   (ntldr).
; * It autodetects EBIOS (LBA) and uses it if available. Otherwise it falls
;   back to CHS. LBA is for >8 GiB HDDs, CHS is for maximum compatibility
;   with old (before 1996) PC BIOS. This autodetection is implemented in the
;   MBR boot code.
; * All the boot code fits to the boot sector (512 bytes) and the MBR (512
;   bytes). No need for loading a sector 2 or 3 like how Windows
;   95--98--ME--XP boots.
; * It works with a 8086 CPU (no need for 386).
; * It can boot from HDD as well as floppy disk. But please note that
;   typical floppy disks (smaller than 2 MiB) are too small for a FAT16
;   filesystem (at least 2 MiB: 0x1000 clusters with 0x200 bytes each).
;
; History:

; * Based on the FreeDOS FAT32 boot sector.
; * Modified heavily by Eric Auer and Jon Gentle in July 2003.
; * Modified heavily by Tinybit in February 2004.
; * Snapshotted code starting at *Entry_32* in stage2/grldrstart.S in
;   grub4dos-0.4.6a-2024-02-26, by pts.
; * Adapted to the MS-DOS v7 load protocol (moved away from the
;   GRLDR--NTLDR load protocol), and added MS-DOS v6 load protocol support
;   by pts in January 2025.
; * Changed from FAT32 to FAT16 by pts in January 2025.
; * Changed from MBR-dependent to independent by pts in January 2025.
;
; You can use and copy source code and binaries under the terms of the
; GNU Public License (GPL), version 2 or newer. See www.gnu.org for more.
;
; Memory layout:
;
; * 0...0x400: Interrupt table.
; * 0x400...0x500: BIOS data area.
; * 0x500...0x700: Unused.
; * 0x700...0xf00: 4 sectors loaded from io.sys.
; * 0xf00...0x1000: Unused.
; * 0x1000...0x1200: Sector read from the FAT16 FAT.
; * 0x1200...0x7b00: Unused.
; * 0x7b00...0x7c00: Stack used by this boot sector.
; * 0x7c00...0x7e00: This boot sector.

assert_fofs 0x400
boot_sector_fat16:
		fat_header 1, 0, 2, 1, 1, 1, 0, 0, 0x90  ; !! fat_reserved_sector_count, fat_sector_count, fat_fat_count, fat_sectors_per_cluster, fat_sectors_per_fat, fat_rootdir_sector_count, fat_32, partition_1_sec_ofs, fat_chs_or_lba.
		fat_boot_sector_common
.var_fat_sec_ofs: equ .boot_code+4  ; dd. Sector offset (LBA) of the first FAT in this FAT filesystem, from the beginning of the drive (overwriting unused bytes). Only used if .fat_sectors_per_cluster<4.
.var_single_cached_fat_sec_ofs_low: equ .boot_code+8  ; dw. Last accessed FAT sector offset (LBA), low word (overwriting unused bytes). Some invalid value if not populated.
.var_clusters_sec_ofs: equ .header-4  ; dd. Sector offset (LBA) of the clusters (i.e. cluster 2) in this FAT filesystem, from the beginning of the drive. This is also the start of the data.
.var_orig_int13_vector: equ .header-8  ; dd. segment:offset. Old DPT pointer.

		mov [bp-.header+.drive_number], dl  ; BIOS or MBR has passed drive number in DL.

		; Copy the disk initialization parameter table (.dipt, DPT).
		mov bx, 0x1e<<2  ; int 1eh vector (DPT).
		lds si, [bx]
		push si
		mov di, 0x522  ; Windows 95--98--ME also copy to here. https://stanislavs.org/helppc/bios_data_area.html also lists it.
		mov [es:bx], di  ; Change int 1eh vector (DPT).
		mov [es:bx+2], es
		mov cx, 0xb
		rep movsb  ; Size of the DPT.
		pop si  ; Will be pushed below.
		mov byte [es:di-2], 0xf  ; Set floppy head bounce delay == head settle time, in milliseconds, to 0xf: https://stanislavs.org/helppc/int_1e.html ; https://retrocomputing.stackexchange.com/q/31099/3494
		mov cx, [bp-.header+.sectors_per_track]
		mov [es:di-7], cl  ; Set sectors_per_track in the DPT.

		; Figure out where FAT and data areas start.
%if 0  ; There isn't enough space to compute this here.
		xchg dx, ax  ; DX := AX (0); AX := junk. AX has been set to 0 by fat_boot_sector_common.
		mov ax, [bp-.header+.reserved_sector_count]
		add ax, [bp-.header+.hidden_sector_count]
		adc dx, [bp-.header+.hidden_sector_count+2]
		mov [bp-.header+.var_fat_sec_ofs], ax
		dec ax
		mov [bp-.header+.var_single_cached_fat_sec_ofs_low], ax  ; Cache not populated yet.
		inc ax
		mov [bp-.header+.var_fat_sec_ofs+2], dx
		xor cx, cx
		mov cl, [bp-.header+.fat_count]  ; 1 or 2.
.add_fat:	add ax, [bp-.header+.sectors_per_fat]
		adc dx, byte 0
		loop .add_fat
                ; Now: DX:AX == the sector offset (LBA) of the root directory in this FAT filesystem.
		mov bx, [bp-.header+.rootdir_entry_count]
		mov di, bx
		add di, byte 0xf
		mov cl, 4  ; Assuming word [bp-.header+.bytes_per_sector] == 0x200.
		shr di, cl
		xor cx, cx
		add di, ax
		adc cx, dx
                push cx
                push di  ; dword [bp-.header+.var_clusters_sec_ofs] := CX:DI (final value).
                mov cx, bx
		mov bx, 0x1e<<2  ; int 1eh vector (DPT).
%else  ; !! Precompute the 000 values below in the `sys' tool.
		mov ax, 000  ; High word of dword [bp-.header+.var_clusters_sec_ofs]
		push ax
		mov ax, 000  ; Low  word of dword [bp-.header+.var_clusters_sec_ofs].
		push ax
		mov cx, 000  ; Number of root directory entries.
		mov dx, 000  ; High word of the sector offset (LBA) of the root directory in this FAT filesystem.
		mov ax, 000  ; Low  word of the sector offset (LBA) of the root directory in this FAT filesystem.
%endif

		push ds  ; Segment of dword [.var_orig_int13_vector].
		push si  ; Offset of dword [.var_orig_int13_vector].
		push ss  ; Will be discarded by MS-DOS v7 msload. Push segment 0 for compatibility. In practice, msload in MS-DOS v7 ignores this value.
		;mov bx, 0x1e<<2  ; No need, already true.
		push bx  ; Will be discarded by MS-DOS v7 msload. Push offset 0x78 == (0x1e<<2) for compatibility. In practice, msload in MS-DOS v7 ignores this value.

		push es
		pop ds  ; DS := ES (0).
		mov es, [bp-.header+.jmp_far_inst+3]  ; mov es, 0x700>>4. Load root directory and kernel (io.sys) starting at 0x70:0 (== 0x700).

		; Search the root directory for a kernel file.
                ; Now: DX:AX == the sector offset (LBA) of the root directory in this FAT filesystem; CX: number of root directory entries.
		mov bh, 3  ; BH := missing-filename-bitset (io.sys and msdos.sys).
.read_rootdir_sector:
                ; Now: DX:AX == the next sector offset (LBA) of the root directory in this FAT filesystem; CX: number of root directory entries remaining.
		call .read_disk_inc
		xor di, di  ; Points to next directory entry to compare filename against.
.next_entry:  ; Search for kernel file name, and find start cluster.
		push cx  ; Save.
		push di  ; Save.
		mov si, -.org+.io_sys
		mov cx, 11  ; .io_sys_end-.io_sys
		repe cmpsb
		jne .not_io_sys
		cmp [es:di-11+0x1c+2], cl  ; 0x1c is the offset of the dword-sized file size in the FAT directory entry.
		je .do_io_sys_or_ibmbio_com  ; Jump if file size of io.sys is shorter than 0x10000 bytes. This is true for MS-DOS v6 (e.g. 6.22), false for MS-DOS v7 (e.g. Windows 95).
		mov byte [bp-.header+.jmp_far_inst+2], 2  ; MS-DOS v7 load protocol wants `jmp 0x70:0x200', we set the 2 here.
		and bh, ~2  ; No need for msdos.sys.
.do_io_sys_or_ibmbio_com:
		mov si, 0x500+0x1a  ; Load protocol: io.sys expects directory entry of io.sys at 0x500.
		and bh, ~1
		jmp short .copy_entry
.not_io_sys:
		pop di
		push di
		inc cx  ; Skip over NUL.
		add si, cx  ; Assumes that .ibmbio_com follows .io_sys. mov si, -.org+.ibmbio_com
		mov cl, 11  ; .io_sys_end-.io_sys
		repe cmpsb
		je .do_io_sys_or_ibmbio_com
		pop di
		push di
		add si, cx  ; Assumes that .msdos_sys follows .ibmbio_com. Like this, but 1 byte shorter: mov si, -.org+.msdos_sys
		mov cl, 11  ; .msdos_sys_end-.msdos_sys  ; CH is already 0.
		repe cmpsb
		jne .not_msdos_sys
.do_msdos_sys_or_ibmdos_com:
		and bh, ~2
		mov si, 0x520+0x1a  ; Load protocol: io.sys expects directory entry of msdos.sys at 0x520.
.copy_entry:	; MS-DOS <=6.22 and IBM PC DOS 7.1 only use 2 words of the
		; 0x20-byte FAT directory entries copied to 0x500 (io.sys)
		; and 0x520 (msdos.sys); the low (+0x1a) and high (+0x14)
		; words of the file start cluster number. The latter is only
		; used for FAT32. So we only copy those words here.
		mov cx, [es:di-11+0x1a]  ; Copy low word of file start cluster number.
		mov [si], cx  ; Save to [0x500+0x1a] or [0x520+0x1a].
		jmp short .entry_done
.not_msdos_sys:
		pop di
		push di
		add si, cx  ; Assumes that .ibmdos_com follows .msdos_sys. mov si, -.org+.ibmdos_com
		mov cl, 11  ; .io_sys_end-.io_sys
		repe cmpsb
		je .do_msdos_sys_or_ibmdos_com
		; Fall through to .entry_done.
.entry_done:	pop di  ; Restore.
		pop cx  ; Restore the remaining number of rootdir sectors to read.
		;test bh, bh  ; Not needed, ZF is already correct because of `jne' or `and dh, ~...'.
		jz .found_both_sys_files
		loop .try_next_entry
		mov si, -.org+.errmsg_missing   ; No more root directory entries. This means that kernel file was not found.
		jmp short .fatal
.try_next_entry:
		lea di, [di+0x20]  ; DI := address of next directory entry.
		cmp di, [bp-.header+.bytes_per_sector]  ; 1 byte shorter than `cmp di, 0x200'.
		jne .next_entry ; next directory entry
		jmp short .read_rootdir_sector

.found_both_sys_files:  ; Kernel directory entry is found.
		mov di, [0x500+0x1a]  ; Get cluster number.
		; DI will be used by the MS-DOS v7 load protocol later.
		mov ax, di
		; Read msload (first few sectors) of the kernel (io.sys).
		mov ch, 4  ; Load up to 4 sectors. MS-DOS 7.x (Windows 95, Windows 98) and 8.0 (Windows ME) need >=4, MS-DOS 3.30..6.22 work with >=3.
		; Load kernel (io.sys) starting at 0x70:0 (== 0x700). Will be used by .read_disk.
.next_kernel_cluster:  ; Now: AX: next cluster number; DX: ruined; BX: ruined; CH: number of remaining sectors to read; CL: ruined.
		push ax  ; Save cluster number.
.cluster_to_lba:  ; Converts cluster number to the sector offset (LBA).
		dec ax
		dec ax
		cmp ax, strict word 0xfff8-2  ; Make it fail for 0, 1 and >=0xfff8 (FAT16 minimum special cluster number).
		jc .no_eoc
		; EOC encountered before we could read 4 sectors.
.fatal1:	mov si, -.org+.errmsg_sys
; Prints NUL-terminated message starting at SI, and halts. Ruins many registers.
.fatal:
.next_msg_byte:	lodsb
		test al, al  ; Found terminating NUL?
		jz .halt
		mov ah, 0xe
		mov bx, 7
		int 0x10
		jmp short .next_msg_byte
.halt:		cli
.hang:		hlt
		jmp .hang
		; Not reached.
.no_eoc:
		; Sector := (cluster-2) * clustersize + data_start.
		mov cl, [bp-.header+.sectors_per_cluster]
		push cx  ; Save for CH.
		mov ch, 0
		mul cx
		pop cx  ; Restore for CH.
		add ax, [bp-.header+.var_clusters_sec_ofs]
		adc dx, [bp-.header+.var_clusters_sec_ofs+2]  ; Also CF := 0 for regular data.
.read_kernel_sector:  ; Now: CL is sectors per cluster; DX:AX is sector offset (LBA).
		call .read_disk_inc
		mov bx, es
		lea bx, [bx+0x20]
		mov es, bx
		dec ch
		jnz .cont_kernel_cluster
.jump_to_msload:
		pop ax  ; Discard current cluster number.
		; Fill registers according to MS-DOS v6 load protocol.
		mov bx, [bp-.header+.var_clusters_sec_ofs]
		mov ax, [bp-.header+.var_clusters_sec_ofs+2]
		; Fill registers according to MS-DOS v7 load protocol: https://pushbx.org/ecm/doc/ldosboot.htm#protocol-sector-msdos7
		; True by design: SS:BP -> boot sector with (E)BPB, typically at linear 0x7c00.
		; True by design: dword [ss:bp-4] = (== dword [bp-.header+.var_clusters_sec_ofs]) first data sector of first cluster, including hidden sectors.
		; !! Currently not: word [ss:bp+0x1ee] points to a message table. The format of this table is described in lDebug's source files https://hg.pushbx.org/ecm/ldebug/file/66e2ad622d18/source/msg.asm#l1407 and https://hg.pushbx.org/ecm/ldebug/file/66e2ad622d18/source/boot.asm#l2577 .
		; Fill registers according to MS-DOS v6 load protocol.
		mov dl, [bp-.header+.drive_number]  ; MS-DOS v7 (such as Windows 98 SE) expects the drive number in the BPB (.drive_number_fat1x and .drive_number_fat32) instead.
		; Fill registers according to MS-DOS v7 load protocol: https://pushbx.org/ecm/doc/ldosboot.htm#protocol-sector-msdos7
		; Already filled: DI == first cluster of load file if FAT12 or FAT16. (SI:DI == first cluster of load file if FAT32.)
		; Fill registers according to MS-DOS v6 load protocol: https://pushbx.org/ecm/doc/ldosboot.htm#protocol-sector-msdos6
		mov ch, [bp-.header+.media_descriptor]  ; https://retrocomputing.stackexchange.com/q/31129 . IBM PC DOS 7.1 boot sector seems to set it, propagating it to the DRVFAT variable, propagating it to DiskRD. Does it actually use it? MS-DOS 6.22 fails to boot if this is not 0xf8 for HDD (Is it true? Does it accept 0xf0 as well? Or anything?). MS-DOS 4.01 io.sys GOTHRD (in bios/msinit.asm) uses it, as media byte. MS-DOS 4.01 io.sys GOTHRD (in bios/msinit.asm) uses it, as media byte.
		; Pass orig DPT (int 13h vector value) to MS-DOS v6 and IBM
		; PC DOS 7.0 in DS:SI. MS-DOS v7 and IBM PC DOS 7.1 expect
		; it on the stack instead (we've already pushed it, as dword
		; [.var_orig_int13_vector] above): they pop 4 bytes from the
		; stack, and then they pop offset (word [SS:SP+4]), then
		; segment ((word [SS:SP+6])) of the original DPT.
		; https://stanislavs.org/helppc/int_1e.html
		lds si, [bp-.header+.var_orig_int13_vector]
.jmp_far_inst:	jmp 0x70:0  ; Jump to boot code (msload) loaded from io.sys. Self-modifying code: the offset 0 has been changed to 0x200 for MS-DOS v7.
.cont_kernel_cluster:
		dec cl  ; Consume 1 sector from the cluster.
		jnz .read_kernel_sector
		pop ax  ; Restore cluster number.
.next_cluster:  ; Find the number of the next cluster in the FAT16.
		; Now: AX: cluster number.
		push bx  ; Save.
		push es  ; Save.
		mov bx, 0x1000>>4  ; Load FAT sector to 0x1000.
		mov es, bx
		xchg bx, ax  ; BX := AX; AX := junk.
		mov ax, [bp-.header+.var_fat_sec_ofs]
		mov dx, [bp-.header+.var_fat_sec_ofs+2]
		add al, bh
		adc ah, 0
		adc dx, byte 0
		; Now: DX:AX is the sector offset (LBA), BL<<1 is the byte offset within the sector.
		; Is it the last accessed and already buffered FAT sector?
		cmp ax, [bp-.header+.var_single_cached_fat_sec_ofs_low]
		je .fat_sector_read
.fat_read_sector_now:
		mov [bp-.header+.var_single_cached_fat_sec_ofs_low], ax
		call .read_disk_inc  ; read sector DX:AX to buffer.
.fat_sector_read:
		mov bh, 0x1000>>9  ; 0x1000 is FAT sector buffer address. Must be an integer (i.e. 0xf00 won't work).
		shl bx, 1
		mov ax, [bx]  ; Read next cluster number from FAT16. !! Implement FAT12 reading.
		pop es  ; Restore.
		pop bx  ; Restore.
		; Now: AX: next cluster number; DX: ruined.
		jmp short .next_kernel_cluster

; Reads a sector from disk, using CHS.
; Inputs: DX:AX: sector offset (LBA); ES: ES:0 points to the destination buffer.
; Outputs: DX:AX incremented by 1, for next sector.
; Ruins: flags.
.read_disk_inc:
		push ax  ; Save.
		push bx  ; Save.
		push cx  ; Save.
		push dx  ; Save.
		; Converts sector offset (LBA) value in DX:AX to BIOS-style
		; CHS value in CX and DH. Ruins DL, AX and flag. This is
		; heavily optimized for code size.
		xchg ax, cx
		xchg ax, dx
		xor dx, dx
		div word [bp-.header+.sectors_per_track]  ; We assume that .sectors_per_track is between 1 and 63.
		xchg ax, cx
		div word [bp-.header+.sectors_per_track]
		inc dx  ; Like `inc dl`, but 1 byte shorter. Sector numbers start with 1.
		xchg cx, dx  ; CX := sec value.
		div word [bp-.header+.head_count]  ; We assume that .head_count is between 1 and 255.
		; Now AX is the cyl value (BIOS allows between 0 and 1023),
		; DX is the head value (between 0 and 254), thus the DL is
		; also the head value, CX is the sec value (BIOS allows
		; between 1 and 63), thus CL is also the sec value. Also the
		; high 6 bits of AH (and AX) are 0, because BIOS allows cyl
		; value less than 1024. (Thus `ror ah, 1` below works.)
		;
		; BIOS int 13h AH == 2 wants the head value in DH, the low 8
		; bits of the cyl value in CH, and it wants CL ==
		; (cyl>>8<<6)|head. Thus we copy DL to DH (cyl value), AL to
		; CH (low 8 bits of the cyl value), AH to CL (sec value),
		; and or the 2 bits of AH (high 8 bits of the cyl value)
		; shifted to CL.
		mov dh, dl
		mov ch, al
		ror ah, 1
		ror ah, 1
		or cl, ah
		mov ax, 0x201  ; AL == 1 means: read 1 sector.
		xor bx, bx  ; Use offset 0 in ES:BX.
		mov dl, [bp-.header+.drive_number]  ; This offset depends on the filesystem type (FAT16 or FAT32). %if fat_32.
		int 0x13  ; BIOS syscall to read sectors.
.jc_fatal_disk:	mov si, -.org+.errmsg_disk
		jc .fatal
		pop dx  ; Restore.
		pop cx  ; Restore.
		pop bx  ; Restore.
		pop ax  ; Restore.
		add ax, byte 1  ; Next sector.
		adc dx, byte 0
		ret

.errmsg_disk:	db 'Disk error', 0
.errmsg_missing: db 'No '  ; Overlaps the following .io_sys.
.io_sys:	db 'IO      SYS', 0  ; Must be followed by .ibmbio_com in memory.
.io_sys_end:
.errmsg_sys: equ $-4  ; Just write 'SYS', 0.
.ibmbio_com:	db 'IBMBIO  COM'  ; Must be followed by .msdos_sys in memory.
.ibmbio_com_end:
.msdos_sys:	db 'MSDOS   SYS'  ; Must be followed by .ibmdos_com in memory.
.msdos_sys_end:
.ibmdos_com:	db 'IBMDOS  COM'  ; Must follow .ibmdos_com in memory.
.ibmdos_com_end:

		times 0x1fe-($-.header) db '-'  ; Padding.
.boot_signature: dw BOOT_SIGNATURE
assert_at .header+0x200

; --- MS-PC-DOS-v4-v5-v6-v7 universal, independent FAT12 boot sector.
;
; Features and requirements:
;
; * !! Write the sys tool and test it.
; * It can boot from HDD as well as floppy disk.
; * Maximum filesystem size: 31 MiB, because the sector count is stored in
;   16 bits. (The code would not fit if it used 32 bits.)
; * It needs a special sys tool to precompute some values (indicated as
;   `000` in the code).
; * This boot sector is independent, i.e. it works from any MBR which sets
;   DL to the BIOS drive number, and BIOS which sets DL when loading it
;   directly as a floppy boot sector.
; * Requirements: The following BPB fields are correctly populated:
;   .media_desciptor, .hidden_sector_count (partition sector offset (LBA)),
;   .sectors_per_track (CHS cyls) and .head_count (CHS heads).
; * This boot sector supports CHS only (no EBIOS, no LBA).
; * It is able to boot io.sys+msdos.sys from MS-DOS 4.01--6.22. Tested with:
;   4.01, 5.00 and 6.22.
; * It is able to boot ibmbio.com+ibmdos.com from IBM PC DOS 4.01--7.1.
;   Tested with: 7.0 and 7.1.
; * It is able to boot io.sys from Windows 95 RTM (OSR1), Windows 95 OSR 2,
;   Windows 98 FE, Windows 98 SE, and the unofficial MS-DOS 8.0 (MSDOS8.ISO
;   on http://www.multiboot.ru/download/) based on Windows ME.
; * With some additions (in the future), it may be able to boot FreeDOS
;   (kernel.sys), SvarDOS (kernel.sys), EDR-DOS (drbio.sys), Windows NT 3.x
;   (ntldr), Windows NT 4.0 (ntldr), Windows 2000 (ntldr), Windows XP
;   (ntldr).
; * It autodetects EBIOS (LBA) and uses it if available. Otherwise it falls
;   back to CHS. LBA is for >8 GiB HDDs, CHS is for maximum compatibility
;   with old (before 1996) PC BIOS. This autodetection is implemented in the
;   MBR boot code.
; * All the boot code fits to the boot sector (512 bytes) and the MBR (512
;   bytes). No need for loading a sector 2 or 3 like how Windows
;   95--98--ME--XP boots.
; * It works with a 8086 CPU (no need for 386).
;
; History:

; * Based on the FreeDOS FAT32 boot sector.
; * Modified heavily by Eric Auer and Jon Gentle in July 2003.
; * Modified heavily by Tinybit in February 2004.
; * Snapshotted code starting at *Entry_32* in stage2/grldrstart.S in
;   grub4dos-0.4.6a-2024-02-26, by pts.
; * Adapted to the MS-DOS v7 load protocol (moved away from the
;   GRLDR--NTLDR load protocol), and added MS-DOS v6 load protocol support
;   by pts in January 2025.
; * Changed from FAT32 to FAT16 by pts in January 2025.
; * Changed from MBR-dependent to independent by pts in January 2025.
; * Changed from FAT16 to simplified FAT12 by pts in January 2025.
;
; You can use and copy source code and binaries under the terms of the
; GNU Public License (GPL), version 2 or newer. See www.gnu.org for more.
;
; Memory layout:
;
; * 0...0x400: Interrupt table.
; * 0x400...0x500: BIOS data area.
; * 0x500...0x700: Unused.
; * 0x700...0xf00: 4 sectors loaded from io.sys.
; * 0xf00...0x1000: Unused.
; * 0x1000...0x7b00: Unused.
; * 0x7b00...0x7c00: Stack used by this boot sector.
; * 0x7c00...0x7e00: This boot sector.

assert_fofs 0x600
boot_sector_fat12:
		fat_header 1, 0, 2, 1, 1, 1, -1, 0, 0x90  ; !! fat_reserved_sector_count, fat_sector_count, fat_fat_count, fat_sectors_per_cluster, fat_sectors_per_fat, fat_rootdir_sector_count, fat_32, partition_1_sec_ofs, fat_chs_or_lba.
		fat_boot_sector_common
.var_fat_sec_ofs: equ .boot_code+4  ; Only the low word is used. dd. Sector offset (LBA) of the first FAT in this FAT filesystem, from the beginning of the drive (overwriting unused bytes). Only used if .fat_sectors_per_cluster<4.
;.var_single_cached_fat_sec_ofs_low: equ .boot_code+8  ; Removed. dw. Last accessed FAT sector offset (LBA), low word (overwriting unused bytes). Some invalid value if not populated.
.var_clusters_sec_ofs: equ .header-4  ; Only the low word is used. dd. Sector offset (LBA) of the clusters (i.e. cluster 2) in this FAT filesystem, from the beginning of the drive. This is also the start of the data.
.var_orig_int13_vector: equ .header-8  ; dd. segment:offset. Old DPT pointer.

		mov [bp-.header+.drive_number], dl  ; BIOS or MBR has passed drive number in DL.

		; Copy the disk initialization parameter table (.dipt, DPT).
		mov bx, 0x1e<<2  ; int 1eh vector (DPT).
		lds si, [bx]
		push si
		mov di, 0x522  ; Windows 95--98--ME also copy to here. https://stanislavs.org/helppc/bios_data_area.html also lists it.
		mov [es:bx], di  ; Change int 1eh vector (DPT).
		mov [es:bx+2], es
		mov cx, 0xb
		rep movsb  ; Size of the DPT.
		pop si  ; Will be pushed below.
		mov byte [es:di-2], 0xf  ; Set floppy head bounce delay == head settle time, in milliseconds, to 0xf: https://stanislavs.org/helppc/int_1e.html ; https://retrocomputing.stackexchange.com/q/31099/3494
		mov cx, [bp-.header+.sectors_per_track]
		mov [es:di-7], cl  ; Set sectors_per_track in the DPT.

		; Figure out where FAT and data areas start.
%if 0  ; There isn't enough space to compute this here.
		xchg dx, ax  ; DX := AX (0); AX := junk. AX has been set to 0 by fat_boot_sector_common.
		mov ax, [bp-.header+.reserved_sector_count]
		add ax, [bp-.header+.hidden_sector_count]
		adc dx, [bp-.header+.hidden_sector_count+2]
		mov [bp-.header+.var_fat_sec_ofs], ax
		dec ax
		;mov [bp-.header+.var_single_cached_fat_sec_ofs_low], ax  ; Cache not populated yet.
		inc ax
		mov [bp-.header+.var_fat_sec_ofs+2], dx
		xor cx, cx
		mov cl, [bp-.header+.fat_count]  ; 1 or 2.
.add_fat:	add ax, [bp-.header+.sectors_per_fat]
		adc dx, byte 0
		loop .add_fat
                ; Now: AX == the sector offset (LBA) of the root directory in this FAT filesystem.
		mov bx, [bp-.header+.rootdir_entry_count]
		mov di, bx
		add di, byte 0xf
		mov cl, 4  ; Assuming word [bp-.header+.bytes_per_sector] == 0x200.
		shr di, cl
		xor cx, cx
		add di, ax
		adc cx, dx
                push cx
                push di  ; dword [bp-.header+.var_clusters_sec_ofs] := CX:DI (final value).
                mov cx, bx
		mov bx, 0x1e<<2  ; int 1eh vector (DPT).
%else  ; !!! Precompute the 000 values below in the `sys' tool.
		;xor ax, ax ; Already 0. mov ax, 000  ; High word of dword [bp-.header+.var_clusters_sec_ofs]
		push ax  ; High word of dword [bp-.header+.var_clusters_sec_ofs] to 0.
		mov ax, 000  ; Low  word of dword [bp-.header+.var_clusters_sec_ofs].
		push ax
		;mov word [bp-.header+.var_fat_sec_ofs], 000  ; Hardcoded it to the `add' instruction below.
		mov cx, 000  ; Number of root directory entries.
		;mov dx, 000  ; Zero. High word of the sector offset (LBA) of the root directory in this FAT filesystem.
		mov ax, 000  ; Low word of the sector offset (LBA) of the root directory in this FAT filesystem.
%endif

		push ds  ; Segment of dword [.var_orig_int13_vector].
		push si  ; Offset of dword [.var_orig_int13_vector].
		push ss  ; Will be discarded by MS-DOS v7 msload. Push segment 0 for compatibility. In practice, msload in MS-DOS v7 ignores this value.
		;mov bx, 0x1e<<2  ; No need, already true.
		push bx  ; Will be discarded by MS-DOS v7 msload. Push offset 0x78 == (0x1e<<2) for compatibility. In practice, msload in MS-DOS v7 ignores this value.

		push es
		pop ds  ; DS := ES (0).
		mov es, [bp-.header+.jmp_far_inst+3]  ; mov es, 0x700>>4. Load root directory and kernel (io.sys) starting at 0x70:0 (== 0x700).

		; Search the root directory for a kernel file.
                ; Now: AX == the sector offset (LBA) of the root directory in this FAT filesystem; CX: number of root directory entries.
		mov bh, 3  ; BH := missing-filename-bitset (io.sys and msdos.sys).
.read_rootdir_sector:
                ; Now: AX == the next sector offset (LBA) of the root directory in this FAT filesystem; CX: number of root directory entries remaining.
		call .read_disk_inc
		xor di, di  ; Points to next directory entry to compare filename against.
.next_entry:  ; Search for kernel file name, and find start cluster.
		push cx  ; Save.
		push di  ; Save.
		mov si, -.org+.io_sys
		mov cx, 11  ; .io_sys_end-.io_sys
		repe cmpsb
		jne .not_io_sys
		cmp [es:di-11+0x1c+2], cl  ; 0x1c is the offset of the dword-sized file size in the FAT directory entry.
		je .do_io_sys_or_ibmbio_com  ; Jump if file size of io.sys is shorter than 0x10000 bytes. This is true for MS-DOS v6 (e.g. 6.22), false for MS-DOS v7 (e.g. Windows 95).
		mov byte [bp-.header+.jmp_far_inst+2], 2  ; MS-DOS v7 load protocol wants `jmp 0x70:0x200', we set the 2 here.
		and bh, ~2  ; No need for msdos.sys.
.do_io_sys_or_ibmbio_com:
		mov si, 0x500+0x1a  ; Load protocol: io.sys expects directory entry of io.sys at 0x500.
		and bh, ~1
		jmp short .copy_entry
.not_io_sys:	pop di
		push di
		inc cx  ; Skip over NUL.
		add si, cx  ; Assumes that .ibmbio_com follows .io_sys. mov si, -.org+.ibmbio_com
		mov cl, 11  ; .io_sys_end-.io_sys
		repe cmpsb
		je .do_io_sys_or_ibmbio_com
		pop di
		push di
		add si, cx  ; Assumes that .msdos_sys follows .ibmbio_com. Like this, but 1 byte shorter: mov si, -.org+.msdos_sys
		mov cl, 11  ; .msdos_sys_end-.msdos_sys  ; CH is already 0.
		repe cmpsb
		jne .not_msdos_sys
.do_msdos_sys_or_ibmdos_com:
		and bh, ~2
		mov si, 0x520+0x1a  ; Load protocol: io.sys expects directory entry of msdos.sys at 0x520.
.copy_entry:	; MS-DOS <=6.22 and IBM PC DOS 7.1 only use 2 words of the
		; 0x20-byte FAT directory entries copied to 0x500 (io.sys)
		; and 0x520 (msdos.sys); the low (+0x1a) and high (+0x14)
		; words of the file start cluster number. The latter is only
		; used for FAT32. So we only copy those words here.
		mov cx, [es:di-11+0x1a]  ; Copy low word of file start cluster number.
		mov [si], cx  ; Save to [0x500+0x1a] or [0x520+0x1a].
		jmp short .entry_done
.not_msdos_sys:
		pop di
		push di
		add si, cx  ; Assumes that .ibmdos_com follows .msdos_sys. mov si, -.org+.ibmdos_com
		mov cl, 11  ; .io_sys_end-.io_sys
		repe cmpsb
		je .do_msdos_sys_or_ibmdos_com
		; Fall through to .entry_done.
.entry_done:	pop di  ; Restore.
		pop cx  ; Restore the remaining number of rootdir sectors to read.
		;test bh, bh  ; Not needed, ZF is already correct because of `jne' or `and dh, ~...'.
		jz .found_both_sys_files
		loop .try_next_entry
		mov si, -.org+.errmsg_missing   ; No more root directory entries. This means that kernel file was not found.
		;jmp short .fatal
; Prints NUL-terminated message starting at SI, and halts. Ruins many registers.
.fatal:
		mov ah, 0xe
		mov bx, 7
.next_msg_byte:	lodsb
		test al, al  ; Found terminating NUL?
		jz .halt
		int 0x10
		jmp short .next_msg_byte
.halt:		cli
.hang:		hlt
		jmp .hang
		; Not reached.
.try_next_entry:
		lea di, [di+0x20]  ; DI := address of next directory entry.
		cmp di, [bp-.header+.bytes_per_sector]  ; 1 byte shorter than `cmp di, 0x200'.
		jne .next_entry ; next directory entry
		jmp near .read_rootdir_sector

.found_both_sys_files:  ; Kernel directory entry is found.
		mov di, [0x500+0x1a]  ; Get cluster number.
		; DI will be used by the MS-DOS v7 load protocol later.
		mov ax, di
		; Read msload (first few sectors) of the kernel (io.sys).
		mov ch, 4  ; Load up to 4 sectors. MS-DOS 7.x (Windows 95, Windows 98) and 8.0 (Windows ME) need >=4, MS-DOS 3.30..6.22 work with >=3.
		; Load kernel (io.sys) starting at 0x70:0 (== 0x700). Will be used by .read_disk.
.next_kernel_cluster:  ; Now: AX: next cluster number; BX: ruined; CH: number of remaining sectors to read; CL: ruined.
		push ax  ; Save cluster number.
.cluster_to_lba:  ; Converts cluster number to the sector offset (LBA).
		dec ax
		dec ax
		cmp ax, strict word 0xff8-2  ; Make it fail for 0, 1 and >=0xff8 (FAT12 minimum special cluster number).
		;jc .no_eoc
		; EOC encountered before we could read 4 sectors.
		mov si, -.org+.errmsg_sys  ; .fatal1.
		jnc .fatal
.no_eoc:	; Sector := (cluster-2) * clustersize + data_start.
		mov cl, [bp-.header+.sectors_per_cluster]
		push cx  ; Save for CH.
		mov ch, 0
		mul cx
		pop cx  ; Restore for CH.
		add ax, [bp-.header+.var_clusters_sec_ofs]
		;adc dx, [bp-.header+.var_clusters_sec_ofs+2]  ; Also CF := 0 for regular data.
.read_kernel_sector:  ; Now: CL is sectors per cluster; AX is sector offset (LBA).
		call .read_disk_inc
		mov bx, es
		lea bx, [bx+0x20]
		mov es, bx
		dec ch
		jz .jump_to_msload
.cont_kernel_cluster:
		dec cl  ; Consume 1 sector from the cluster.
		jnz .read_kernel_sector
		pop ax  ; Restore cluster number.
.next_cluster:  ; Find the number of the next cluster in the FAT12.
		; Now: AX: cluster number.
		push si  ; Save.
		push es  ; Save.
		push cx  ; Save.
		; This is the magic logic which calculates FAT12 FAT sector number (to AX) and byte offset within sector (to SI).
		mov si, ax
		xor cx, cx
		shr ax, 1
		add ax, si
		mov cx, ax
		rcr ax, 1
		and ch, 1  ; Keep low 9 bits in CX (will be swapped to SI).
		xchg cx, si  ; CX := cluster number; SI := byte offset of the pointer word.
		mov ch, cl  ; Keeping it for the low bit (parity).
		mov cl, 4  ; Bit shift amount of 4 for FAT12.
		mov al, ah
		mov ah, 0
		; Now: AX is the sector offset within the first FAT.
		; Now: SI is the byte offset of the pointer word or dword within the sector (can be 0x1ff, which indicates split word).
		; Now: CL is 4. It will be used as a shift amount on the low word of the byte offset.
		; Now: CH is the low byte of the cluster number (will be used for its low bit, parity) for FAT12, 0 for others.
		add ax, strict word 000  ; !!! The sys tool should substitute [bp+var.fat_sec_ofs] here.
		;adc dx, [bp+var.fat_sec_ofs+2]
		mov es, [bp-.header+.media_descriptor]  ; Tricky way to `mov es, 0xf8' etc. !! It doesn't work for FAT12.
		call .read_disk_inc
		push word [es:si]  ; Save low word of next cluster number.
		cmp si, 0x1ff
		jne .got_new_pointer
		call .read_disk_inc
		pop ax  ; Restore low word of next cluster number to AX.
		mov ah, [es:0]  ; Get high byte of next cluster number from the next sector.
		push ax  ; Make the following `pop ax' a nop.
.got_new_pointer:
		pop ax  ; Restore low word of next cluster number to AX.
		test ch, 1  ; Is FAT12 cluster number odd?
		jnz .odd
		shl ax, cl
.odd:		shr ax, cl
		; Now: AX is the number of next cluster.
		pop cx  ; Restore.
		pop es  ; Restore.
		pop si  ; Restore.
		; Now: AX: next cluster number.
		jmp short .next_kernel_cluster  ; !! Move .jump_to_msload down.

.jump_to_msload:
		pop ax  ; Discard current cluster number.
		; Fill registers according to MS-DOS v6 load protocol.
		mov bx, [bp-.header+.var_clusters_sec_ofs]
		xor ax, ax  ; mov ax, [bp-.header+.var_clusters_sec_ofs+2]
		; Fill registers according to MS-DOS v7 load protocol: https://pushbx.org/ecm/doc/ldosboot.htm#protocol-sector-msdos7
		; True by design: SS:BP -> boot sector with (E)BPB, typically at linear 0x7c00.
		; True by design: dword [ss:bp-4] = (== dword [bp-.header+.var_clusters_sec_ofs]) first data sector of first cluster, including hidden sectors.
		; !! Currently not: word [ss:bp+0x1ee] points to a message table. The format of this table is described in lDebug's source files https://hg.pushbx.org/ecm/ldebug/file/66e2ad622d18/source/msg.asm#l1407 and https://hg.pushbx.org/ecm/ldebug/file/66e2ad622d18/source/boot.asm#l2577 .
		; Fill registers according to MS-DOS v6 load protocol.
		mov dl, [bp-.header+.drive_number]  ; MS-DOS v7 (such as Windows 98 SE) expects the drive number in the BPB (.drive_number_fat1x and .drive_number_fat32) instead.
		; Fill registers according to MS-DOS v7 load protocol: https://pushbx.org/ecm/doc/ldosboot.htm#protocol-sector-msdos7
		; Already filled: DI == first cluster of load file if FAT12 or FAT16. (SI:DI == first cluster of load file if FAT32.)
		; Fill registers according to MS-DOS v6 load protocol: https://pushbx.org/ecm/doc/ldosboot.htm#protocol-sector-msdos6
		mov ch, [bp-.header+.media_descriptor]  ; https://retrocomputing.stackexchange.com/q/31129 . IBM PC DOS 7.1 boot sector seems to set it, propagating it to the DRVFAT variable, propagating it to DiskRD. Does it actually use it? MS-DOS 6.22 fails to boot if this is not 0xf8 for HDD (Is it true? Does it accept 0xf0 as well? Or anything?). MS-DOS 4.01 io.sys GOTHRD (in bios/msinit.asm) uses it, as media byte. MS-DOS 4.01 io.sys GOTHRD (in bios/msinit.asm) uses it, as media byte.
		; Pass orig DPT (int 13h vector value) to MS-DOS v6 and IBM
		; PC DOS 7.0 in DS:SI. MS-DOS v7 and IBM PC DOS 7.1 expect
		; it on the stack instead (we've already pushed it, as dword
		; [.var_orig_int13_vector] above): they pop 4 bytes from the
		; stack, and then they pop offset (word [SS:SP+4]), then
		; segment ((word [SS:SP+6])) of the original DPT.
		; https://stanislavs.org/helppc/int_1e.html
		lds si, [bp-.header+.var_orig_int13_vector]
.jmp_far_inst:	jmp 0x70:0  ; Jump to boot code (msload) loaded from io.sys. Self-modifying code: the offset 0 has been changed to 0x200 for MS-DOS v7.

; Reads a sector from disk, using CHS.
; Inputs: AX: sector offset (LBA); ES: ES:0 points to the destination buffer.
; Outputs: AX incremented by 1, for next sector.
; Ruins: flags.
.read_disk_inc:
		push ax  ; Save.
		push bx  ; Save.
		push cx  ; Save.
		push dx  ; Save.
		; Converts sector offset (LBA) value in AX to BIOS-style
		; CHS value in CX and DH. Ruins DL, AX and flag. This is
		; heavily optimized for code size.
		xor dx, dx
		div word [bp-.header+.sectors_per_track]  ; We assume that .sectors_per_track is between 1 and 63.
		inc dx  ; Like `inc dl`, but 1 byte shorter. Sector numbers start with 1.
		mov cx, dx  ; CX := sec value.
		xor dx, dx
		div word [bp-.header+.head_count]  ; We assume that .head_count is between 1 and 255.
		; Now AX is the cyl value (BIOS allows between 0 and 1023),
		; DX is the head value (between 0 and 254), thus the DL is
		; also the head value, CX is the sec value (BIOS allows
		; between 1 and 63), thus CL is also the sec value. Also the
		; high 6 bits of AH (and AX) are 0, because BIOS allows cyl
		; value less than 1024. (Thus `ror ah, 1` below works.)
		;
		; BIOS int 13h AH == 2 wants the head value in DH, the low 8
		; bits of the cyl value in CH, and it wants CL ==
		; (cyl>>8<<6)|head. Thus we copy DL to DH (cyl value), AL to
		; CH (low 8 bits of the cyl value), AH to CL (sec value),
		; and or the 2 bits of AH (high 8 bits of the cyl value)
		; shifted to CL.
		mov dh, dl
		mov ch, al
		ror ah, 1
		ror ah, 1
		or cl, ah
		mov ax, 0x201  ; AL == 1 means: read 1 sector.
		xor bx, bx  ; Use offset 0 in ES:BX.
		mov dl, [bp-.header+.drive_number]  ; This offset depends on the filesystem type (FAT16 or FAT32). %if fat_32.
		int 0x13  ; BIOS syscall to read sectors.
.jc_fatal_disk:	mov si, -.org+.errmsg_disk
		jc .fatal
		pop dx  ; Restore.
		pop cx  ; Restore.
		pop bx  ; Restore.
		pop ax  ; Restore.
		inc ax  ;add ax, byte 1  ; Next sector.
		;adc dx, byte 0
		ret

.errmsg_missing: db 'No '  ; Overlaps the following .io_sys.
.io_sys:	db 'IO      SYS', 0  ; Must be followed by .ibmbio_com in memory.
.io_sys_end:
.errmsg_sys: equ $-4  ; Just write 'SYS', 0.
.errmsg_disk: equ $-3  ; Just write 'YS', 0.  ; !! Add a 3-letter error message. There is room.
.ibmbio_com:	db 'IBMBIO  COM'  ; Must be followed by .msdos_sys in memory.
.ibmbio_com_end:
.msdos_sys:	db 'MSDOS   SYS'  ; Must be followed by .ibmdos_com in memory.
.msdos_sys_end:
.ibmdos_com:	db 'IBMDOS  COM'  ; Must follow .ibmdos_com in memory.
.ibmdos_com_end:

		times 0x1fe-($-.header) db '-'  ; Padding.
.boot_signature: dw BOOT_SIGNATURE
assert_at .header+0x200

; __END__
