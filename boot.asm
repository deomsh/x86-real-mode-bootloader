;
; File:
;                            boot.asm
; Description:
;                           DOS-C boot
;
;                       Copyright (c) 1997;
;                           Svante Frey
;                       All Rights Reserved
;
; This file is part of DOS-C.
;
; DOS-C is free software; you can redistribute it and/or
; modify it under the terms of the GNU General Public License
; as published by the Free Software Foundation; either version
; 2, or (at your option) any later version.
;
; DOS-C is distributed in the hope that it will be useful, but
; WITHOUT ANY WARRANTY; without even the implied warranty of
; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See
; the GNU General Public License for more details.
;
; You should have received a copy of the GNU General Public
; License along with DOS-C; see the file COPYING.  If not,
; write to the Free Software Foundation, 675 Mass Ave,
; Cambridge, MA 02139, USA.
;
;
;       +--------+ 1FE0:7E00
;       |BOOT SEC|
;       |RELOCATE|
;       |--------| 1FE0:7C00
;       |LBA PKT |
;       |--------| 1FE0:7BC0
;       |--------| 1FE0:7BA0
;       |BS STACK|
;       |--------|
;       |4KBRDBUF| used to avoid crossing 64KB DMA boundary
;       |--------| 1FE0:63A0
;       |        |
;       |--------| 1FE0:3000
;       | CLUSTER|
;       |  LIST  |
;       |--------| 1FE0:2000
;       |        |
;       |--------| 0000:7E00
;       |BOOT SEC| overwritten by max 128k FAT buffer
;       |ORIGIN  | and later by max 134k loaded kernel
;       |--------| 0000:7C00
;       |        |
;       |--------|
;       |KERNEL  | also used as max 128k FAT buffer
;       |LOADED  | before kernel loading starts
;       |--------| 0060:0000
;       |        |
;       +--------+


;%define ISFAT12         1
;%define ISFAT16         1


; Set segment type.
segment .text

%define BASE            0x7c00

; Let offset base be 0x7C00.
                org     BASE

; The boot sector's entry point.
; (gdb) break *0x7C00
; Jump to `real_start`.
Entry:          jmp     short real_start
; NOP instruction for the third byte, as required by FAT specification.
                nop

; The `jmp` and `nop` above take 3 bytes, followed by FAT info variables.
; These variables are initialized when running `SYS.COM` to install the boot
; sector.
;
; The offsets of the FAT info variables:
;       bp is initialized to 7c00h
%define bsOemName       bp+0x03      ; OEM label
%define bsBytesPerSec   bp+0x0b      ; bytes/sector
%define bsSecPerClust   bp+0x0d      ; sectors/allocation unit
%define bsResSectors    bp+0x0e      ; # reserved sectors
%define bsFATs          bp+0x10      ; # of fats
%define bsRootDirEnts   bp+0x11      ; # of root dir entries
%define bsSectors       bp+0x13      ; # sectors total in image
%define bsMedia         bp+0x15      ; media descrip: fd=2side9sec, etc...
%define sectPerFat      bp+0x16      ; # sectors in a fat
%define sectPerTrack    bp+0x18      ; # sectors/track
%define nHeads          bp+0x1a      ; # heads
%define nHidden         bp+0x1c      ; # hidden sectors
%define nSectorHuge     bp+0x20      ; # sectors if > 65536
%define drive           bp+0x24      ; drive number
%define extBoot         bp+0x26      ; extended boot signature
%define volid           bp+0x27
%define vollabel        bp+0x2b
%define filesys         bp+0x36

; Example of the first 62 bytes of the boot sector:
; 00: EB 3C 90 | 00 00 00 00 00 00 00 00 | 00 02 (512) | 01 | 01 00 |
; 10: 02 | E0 00 (224) | 40 0B (2880) | F0 | 09 00 | 12 00 | 02 00 | 00 00 00 00 |
; 20: 00 00 00 00 | 00 00 | 29 | 00 00 00 00 | 20 20 20 20 20
; 30: 20 20 20 20 20 20 | 46 41 54 31 32 20 20 20
;
; # bsOemName times 8 db 0
; (gdb) x/8xb 0x7C03 = x/8xb 0x27A03 = 0x0000000000000000
; # bsBytesPerSec dw 0
; (gdb) x/1dh 0x7C0B = x/1dh 0x27A0B = 512
; # bsSecPerClust db 0
; (gdb) x/1db 0x7C0D = x/1db 0x27A0D = 1
; # bsResSectors dw 0
; (gdb) x/1dh 0x7C0E = x/1dh 0x27A0E = 1
; # bsFATs db 0
; (gdb) x/1db 0x7C10 = x/1db 0x27A10 = 2
; # bsRootDirEnts dw 0
; (gdb) x/1dh 0x7C11 = x/1dh 0x27A11 = 224
; # bsSectors dw 0
; (gdb) x/1dh 0x7C13 = x/1dh 0x27A13 = 2880 for 1440KB.
; # bsMedia db 0
; (gdb) x/1xb 0x7C15 = x/1xb 0x27A15 = F0 for 3.5-inch 1440 KB or 2880 KB FD.
; # sectPerFat dw 0
; (gdb) x/1dh 0x7C16 = x/1dh 0x27A16 = 9
; # sectPerTrack dw 0
; (gdb) x/1dh 0x7C18 = x/1dh 0x27A18 = 18 for 1440 KB FD, 36 for 2880 KB FD.
; # nHeads dw 0
; (gdb) x/1dh 0x7C1A = x/1dh 0x27A1A = 2
; # nHidden dd 0
; (gdb) x/1dw 0x7C1C = x/1dw 0x27A1C = 0
; # nSectorHuge dd 0
; (gdb) x/1dw 0x7C20 = x/1dw 0x27A20 = 0
; # drive dw 0
; (gdb) x/1dh 0x7C24 = x/1dh 0x27A24 = 0
; # extBoot db 0
; (gdb) x/1xb 0x7C26 = x/1xb 0x27A26 = 0x29: The following three fields are present.
; # volid dd 0
; (gdb) x/1xw 0x7C27 = x/1xw 0x27A27 = 0x00000000
; # vollabel times 11 db 0
; (gdb) x/11xb 0x7C2B = x/11xb 0x27A2B = 0x2020202020202020202020
; # filesys times 8 db 0
; (gdb) x/8xb 0x7C36 = x/8xb 0x27A36 = 0x4641543132202020 (FAT12)
; Ends at 0x7C3E or 0x27A3E, exclusive.

; The user read buffer's segment.
; The starting address is 0x0060:0x0000 = 1.5KB.
; The user read buffer will store the kernel in the end.
; The reason to choose the starting address 1.5KB is because the first 1.5KB
; of the memory stores BIOS' interrupt vector table and other data thus should
; not be overwritten.
%define LOADSEG         0x0060

; The FAT buffer's offset.
; The FAT buffer stores the kernel file's cluster numbers.
; The starting address is 0x1FE0:0x2000 = 135.5KB.
%define FATBUF          0x2000          ; offset of temporary buffer for FAT
                                        ; chain

;       Some extra variables

;%define StoreSI         bp+3h          ;temp store

;-----------------------------------------------------------------------

; Allocate 59 bytes of zeros from $$+3 (0x7C03) up to $$+0x3E (0x7C3E)
; exclusive.
; `$` is `$$+3` because the `jmp` and `nop` instructions above take 3 bytes.
                times   0x3E-$+$$ db 0

; The offset of the variable storing the user read buffer's offset.
;
; using bp-Entry+loadseg_xxx generates smaller code than using just
; loadseg_xxx, where bp is initialized to Entry, so bp-Entry equals 0
%define loadsegoff_60   bp-Entry+loadseg_off
; The offset of the variable storing the user read buffer's segment.
%define loadseg_60      bp-Entry+loadseg_seg

; The offset of the LBA packet used by interrupt 0x13.
; 64B before 0x7C00.
%define LBA_PACKET       bp-0x40
; The offset of the field that stores the LBA packet's size.
%define LBA_SIZE       word [LBA_PACKET]    ; size of packet, should be 10h
; The offset of the field that stores the number of sectors to read.
%define LBA_SECNUM     word [LBA_PACKET+2]  ; number of sectors to read
; The offset of the field that stores the read buffer's offset.
%define LBA_OFF        LBA_PACKET+4         ; buffer to read/write to
; The offset of the field that stores the read buffer's segment.
%define LBA_SEG        LBA_PACKET+6
; The offset of the field that stores the 48-bit LBA sector number.
%define LBA_SECTOR_0   word [LBA_PACKET+8 ] ; LBA starting sector #
%define LBA_SECTOR_16  word [LBA_PACKET+10]
%define LBA_SECTOR_32  word [LBA_PACKET+12]
%define LBA_SECTOR_48  word [LBA_PACKET+14]

; `readDisk`'s read buffer's offset.
; The segment is 0x1FE0.
; 0x1FE0:0x63A0 = 0x261A0 = 152.40625KB, 6240B before 0x1FE0:0x7C00 (158.5KB).
%define READBUF 0x63A0 ; max 4KB buffer (min 2KB stack), == stacktop-0x1800
; The offset of the variable storing `readDisk`'s destination buffer's unfilled
; part's segment.
; 6244B before 0x7C00.
%define READADDR_OFF   BP-0x60-0x1804    ; pointer within user read buffer
; The offset of the variable storing `readDisk`'s destination buffer's unfilled
; part's offset.
; 6242B before 0x7C00.
%define READADDR_SEG   BP-0x60-0x1802

; The offset of the space after the LBA packet.
%define PARAMS LBA_PACKET+0x10
;%define RootDirSecs     PARAMS+0x0         ; # of sectors root dir uses

; The offset of the variable storing the first FAT's sector number.
%define fat_start       PARAMS+0x2         ; first FAT sector

; The offset of the variable storing the FAT root directory's sector number.
%define root_dir_start  PARAMS+0x6         ; first root directory sector

; The offset of the variable storing the FAT data region's sector number.
%define data_start      PARAMS+0x0a        ; first data sector


;-----------------------------------------------------------------------
;   ENTRY
;-----------------------------------------------------------------------

real_start:
; Code below aims to copy the boot sector from 0x0000:0x7C00 (0x7C00 = 31KB) to
; 0x1FE0:0x7C00 (0x27A00 = 158.5KB) because the region containing 0x7C00 will
; be used to store kernel instead.

; (gdb) break *0x7C3E
; Put 0 to IF to disable maskable interrupts.
                cli
; Put 0 to DF. When DF is 0, string operations increment SI and DI.
                cld
; Put 0 to AX.
; `xor ax, ax` generates 2 bytes machine code compared to `mov ax, 0` 3 bytes.
                xor     ax, ax
; Put 0 to DS.
                mov     ds, ax
; Put 0x7C00 to BP.
                mov     bp, BASE


                                        ; a reset should not be needed here
;               int     0x13            ; reset drive

;               int     0x12            ; get memory available in AX
;               mov     ax, 0x01e0
;               mov     cl, 6           ; move boot sector to higher memory
;               shl     ax, cl
;               sub     ax, 0x07e0

; Put 0x1FE0 to AX.
                mov     ax, 0x1FE0
; Put 0x1FE0 to ES.
                mov     es, ax
; Put 0x7C00 to SI.
                mov     si, bp
; Put 0x7C00 to DI.
                mov     di, bp
; Put 256 to CX, to be used as repeat times below.
                mov     cx, 0x0100
; Copy 2 bytes from [DS:SI] to [ES:DI], repeat 256 times.
; Each time SI and DI are incremented by 2, CX is decremented by 1.
                rep     movsw
; Jump to `cont` in the 0x1FE0 segment.
                jmp     word 0x1FE0:cont

; Variable storing the user read buffer's offset.
loadseg_off     dw      0
; Variable storing the user read buffer's segment.
loadseg_seg     dw      LOADSEG

cont:
; Code below aims read the FAT root directory's entries to the user read
; buffer.

; (gdb) break *0x27A5E
; Put 0x1FE0 to DS.
                mov     ds, ax
; Put 0x1FE0 to SS.
                mov     ss, ax
; Put 0x7BA0 (96B before 0x1FE0:0x7C00) to SP.
                lea     sp, [bp-0x60]
; Put 1 to IF to enable maskable interrupts.
                sti
;
; Note: some BIOS implementations may not correctly pass drive number
; in DL, however we work around this in SYS.COM by NOP'ing out the use of DL
; (formerly we checked for [drive]==0xff; update sys.c if code moves)
;
; Put the drive number in DL to [drive].
; DL was set by BIOS before loading the boot sector.
; DL = 00h: 1st floppy disk.
; DL = 01h: 2nd floppy disk.
; DL = 80h: 1st hard disk.
; DL = 81h: 2nd hard disk.
; DL = e0h: 1st CD.
                mov     [drive], dl     ; rely on BIOS drive number in DL

; Put 16 to the `LBA_SIZE` field.
                mov     LBA_SIZE, 10h
; Put the number of sectors to read to the `LBA_SECNUM` field.
                mov     LBA_SECNUM,1    ; initialise LBA packet constants
; Put `readDisk`'s read buffer's segment to the `LBA_SEG` field.
                mov     word [LBA_SEG],ds
; Put `readDisk`'s read buffer's offset to the `LBA_OFF` field.
                mov     word [LBA_OFF],READBUF


;       GETDRIVEPARMS:  Calculate start of some disk areas.
;
; Put lower 2 bytes of the number of hidden sectors to SI.
; E.g. SI = 0.
                mov     si, word [nHidden]
; Put higher 2 bytes of the number of hidden sectors to DI.
; E.g. DI = 0.
; Now DI:SI stores the number of hidden sectors.
                mov     di, word [nHidden+2]
; Add the number of reserved sectors to SI.
; If overflow, CF becomes 1.
; E.g. SI = 1.
                add     si, word [bsResSectors]
; Add CF to DI.
; Now DI:SI stores the number of hidden and reserved sectors, which is also the
; first FAT's sector number.
; E.g. DI = 0.
                adc     di, byte 0              ; DI:SI = first FAT sector

; Put lower 2 bytes of the first FAT's sector number to `[fat_start]`.
                mov     word [fat_start], si
; Put higher 2 bytes of the first FAT's sector number to `[fat_start+2]`.
                mov     word [fat_start+2], di

; Put the number of FATs to AL.
; E.g. AL = 2.
                mov     al, [bsFATs]
; Extend AL to AX.
; Now AX stores the number of FATs.
; E.g. AX = 2.
                cbw
; Multiply the number of FATs by the number of sectors per FAT.
; DX:AX = AX * [sectPerFat].
; Now DX:AX stores the number of FAT sectors.
; E.g. DX = 0. AX = 18.
                mul     word [sectPerFat]       ; DX:AX = total number of FAT sectors

; Add the number of FAT sectors to the number of hidden and reserved sectors.
; Now DI:SI stores the FAT root directory's sector number.
; E.g. SI = 19. DI = 0.
                add     si, ax
                adc     di, dx                  ; DI:SI = first root directory sector
; Put lower 2 bytes of the FAT root directory's sector number to
; `[root_dir_start]`.
                mov     word [root_dir_start], si
; Put higher 2 bytes of the FAT root directory's sector number to
; `[root_dir_start+2]`.
                mov     word [root_dir_start+2], di

                ; Calculate how many sectors the root directory occupies.
; Put the number of bytes per sector to BX.
; E.g. BX = 512.
                mov     bx, [bsBytesPerSec]
; Put 5 in CL, to be used as shfit count below.
                mov     cl, 5                   ; divide BX by 32
; Divide the number of bytes per sector by the number of bytes per directory
; entry.
; Now BX stores the number of directory entries per sector.
; E.g. BX = BX / 2^5 = BX / 32 = 512 / 32 = 16.
                shr     bx, cl                  ; BX = directory entries per sector

; Put the number of directory entries of the FAT root directory to AX.
; E.g. AX = 224.
                mov     ax, [bsRootDirEnts]
; Put 0 to DX.
                xor     dx, dx
; Divide the number of directory entries of the FAT root directory by the
; number of directory entries per sector.
; DX(remainder):AX(quotient) = DX:AX / BX.
; Now AX stores the number of sectors of the FAT root directory.
; E.g. DX:AX = DX:AX / BX = 224 / 16 = 0:14.
                div     bx

;               mov     word [RootDirSecs], ax  ; AX = sectors per root directory
; Push the number of sectors of the FAT root directory in AX.
                push    ax

; Add the number of sectors of the FAT root directory to the FAT root
; directory's sector number.
; If overflow, CF becomes 1.
; E.g. SI = SI + AX = 19 + 14 = 33.
                add     si, ax
; Add CF to DI.
; Now DI:SI stores the FAT data region's sector number.
; E.g. DI = 0.
                adc     di, byte 0              ; DI:SI = first data sector

; Put lower 2 bytes of the FAT data region's sector number to `[data_start]`.
                mov     [data_start], si
; Put higher 2 bytes of the FAT data region's sector number to
; `[data_start+2]`.
                mov     [data_start+2], di


;       FINDFILE: Searches for the file in the root directory.
;
;       Returns:
;                               AX = first cluster of file

                ; First, read the whole root directory
                ; into the temporary buffer.

; Put lower 2 bytes of the FAT root directory's sector number to AX.
                mov     ax, word [root_dir_start]
; Put higher 2 bytes of the FAT root directory's sector number to DX.
; DX:AX specifies the starting sector number for `readDisk` below.
                mov     dx, word [root_dir_start+2]
; Pop the number of sectors of the FAT root directory to DI.
; DI specifies the number of sectors to read for `readDisk` below.
; E.g. DI = 14.
                pop     di                      ; mov     di, word [RootDirSecs]
; Point ES:BX to the user read buffer.
; ES:BX specifies the destination buffer for `readDisk` below.
; (gdb) break *0x27ABF
                les     bx, [loadsegoff_60] ; es:bx = 60:0
; Read the FAT root directory's sectors to the user read buffer.
                call    readDisk

; Code below aims to find the directory entry of the kernel file.
;
; Point ES:DI to the user read buffer.
; (gdb) break *0x27AC5
                les     di, [loadsegoff_60] ; es:di = 60:0


                ; Search for KERNEL.SYS file name, and find start cluster.

; Put 11 to CX, to be used as repeat times below.
; 11 means 8+3 style file name.
next_entry:     mov     cx, 11
; Point SI to the kernel file name.
                mov     si, filename
; Push the user read buffer's offset in DI.
                push    di
; Compare byte [DS:SI] with byte [ES:DI], repeat at most 11 times.
; Each time SI and DI are incremented by 1.
; If all 11 characters are equal, ZF becomes 1.
                repe    cmpsb
; Pop the user read buffer's offset to DI.
; Now ES:DI points to the user read buffer.
                pop     di
; Put the directory entry's first cluster number to AX.
; A directory entry's byte 0x1A stores its first cluster number.
                mov     ax, [es:di+0x1A]; get cluster number from directory entry
; If the kernel file name is found, jump to `ffDone`.
                je      ffDone

; Increment DI by 32 to point to the next directory entry.
                add     di, byte 0x20   ; go to next directory entry
; Test whether the first byte of the file name is 0, which means end-of-entry.
                cmp     byte [es:di], 0 ; if the first byte of the name is 0,
; If it is not end-of-entry, jump to `next_entry`.
                jnz     next_entry      ; there is no more files in the directory

; If it is end-of-entry, jump to `boot_error`.
                jc      boot_error      ; fail if not found
ffDone:
; Push the kernel file's first cluster number in AX.
; (gdb) break *0x27AE3
                push    ax              ; store first cluster number


;       GETFATCHAIN:
;
;       Reads the FAT chain and stores it in a temporary buffer in the first
;       64 kb.  The FAT chain is stored an array of 16-bit cluster numbers,
;       ending with 0.
;
;       The file must fit in conventional memory, so it can't be larger than
;       640 kb. The sector size must be at least 512 bytes, so the FAT chain
;       can't be larger than 2.5 KB (655360 / 512 * 2 = 2560).
;
;       Call with:      AX = first cluster in chain

; Code below aims to load the first FAT to the user read buffer.
;
; Point ES:BX to the user read buffer.
; ES:BX specifies the destination buffer for `readDisk` below.
                les     bx, [loadsegoff_60]     ; es:bx=60:0
; Put the number of sectors per FAT to DI.
; DI specifies the number of sectors to read for `readDisk` below.
                mov     di, [sectPerFat]
; Put lower 2 bytes of the first FAT's sector number to AX.
                mov     ax, word [fat_start]
; Put higer 2 bytes of the first FAT's sector number to DX.
; DX:AX specifies the starting sector number for `readDisk` below.
                mov     dx, word [fat_start+2]
; Read the first FAT's sectors to the user read buffer.
                call    readDisk
; Pop the kernel file's first cluster number to AX.
; (gdb) break *0x27AF3
                pop     ax                      ; restore first cluster number

; Code below aims to put all the cluster numbers of the kernel file to the FAT
; buffer and put a 0 in the end.
                ; Set ES:DI to the temporary storage for the FAT chain.
; Put DS to ES.
; ES = 0x1FE0.
                push    ds
                pop     es
; Put the user read buffer's segment to DS.
; DS = 0x0060.
; SI will be set below to point to each cluster number of the kernel file.
                mov     ds, [loadseg_60]
; Put the FAT buffer's offset to DI.
; DI = 0x2000.
; Now ES:DI points to the FAT buffer.
                mov     di, FATBUF

; Put the current cluster number in AX to [ES:DI] in the FAT buffer.
next_clust:     stosw                           ; store cluster number
; Code below aims to get the next cluster number.
;
; Put the current cluster number in AX to SI.
                mov     si, ax                  ; SI = cluster number

%ifdef ISFAT12
                ; This is a FAT-12 disk.

; Each 12-bit cluster number is stored across 2 bytes.
; The bits layout of 2 consective cluster numbers (12 bits * 2 = 24 bits) in 3
; bytes is:
; 0 76543210
; 1 3210BA98
; 2 BA987654

; Multiply the current cluster number by 3.
fat_12:         add     si, si          ; multiply cluster number by 3...
                add     si, ax
; Divide the current cluster number by 2 to get the offset of the 2 bytes
; storing the next cluster number.
; If the current cluster number is odd, CF becomes 1.
                shr     si, 1           ; ...and divide by 2
; Put the 2 bytes storing the next cluster number in [DS:SI] to AX.
                lodsw

                ; If the cluster number was even, the cluster value is now in
                ; bits 0-11 of AX. If the cluster number was odd, the cluster
                ; value is in bits 4-15, and must be shifted right 4 bits. If
                ; the number was odd, CF was set in the last shift instruction.

; If CF is 0 which means the current cluster number is even, jump to
; `fat_even`.
                jnc     fat_even
; If CF is 1 which means the current cluster number is odd.
; Put 4 in CL, to be used as shift count below.
                mov     cl, 4
; Shift off the lower 4 bits.
                shr     ax, cl

; Mask off the higher 4 bits.
; Now AX stores the new current cluster number.
fat_even:       and     ah, 0x0f        ; mask off the highest 4 bits
; Test whether the new current cluster number is EOF.
                cmp     ax, 0x0ff8      ; check for EOF
; If the new current cluster number is not EOF, jump to `next_clust`.
                jb      next_clust      ; continue if not EOF

%endif
%ifdef ISFAT16
                ; This is a FAT-16 disk. The maximal size of a 16-bit FAT
                ; is 128 kb, so it may not fit within a single 64 kb segment.

; Put the user read buffer's segment to DX.
; DX = 0x0060.
fat_16:         mov     dx, [loadseg_60]
; Multiply the current cluster number by 2 to get the offset of the 2 bytes
; storing the next cluster number.
; If overflow, CF becomes 1.
                add     si, si          ; multiply cluster number by two
; If not overflow, jump to `first_half`.
                jnc     first_half      ; if overflow...
; If overflow, add 0x1000 to DX, which points DX to the next 0x10000 bytes
; segment. Notice SI overflows around and SI can address 0x10000 bytes (64KB).
                add     dh, 0x10        ; ...add 64 kb to segment value

; Put the user read buffer's segment to DS.
; Now DS:SI points to the next cluster number.
first_half:     mov     ds, dx          ; DS:SI = pointer to next cluster
; Put the next cluster number in [DS:SI] to AX.
; Now AX stores the new current cluster number.
                lodsw                   ; AX = next cluster

; Test whether the new current cluster number is EOF.
                cmp     ax, 0xfff8      ; >= FFF8 = 16-bit EOF
; If the new current cluster number is not EOF, jump to `next_clust`.
                jb      next_clust      ; continue if not EOF
%endif

finished:       ; Mark end of FAT chain with 0, so we have a single
                ; EOF marker for both FAT-12 and FAT-16 systems.

; Put 0 to AX.
                xor     ax, ax
; Put 0 in AX to [ES:DI] in the FAT buffer to mark the end.
                stosw

; Code below aims to load the kernel and jump to it.
;
; Put the FAT buffer's segment in CS to DS.
                push    cs
                pop     ds


;       loadFile: Loads the file into memory, one cluster at a time.

; Point ES:BX to the user read buffer.
                les     bx, [loadsegoff_60]   ; set ES:BX to load address 60:0

; Point DS:SI to the FAT buffer.
                mov     si, FATBUF      ; set DS:SI to the FAT chain

; Put the cluster number [DS:SI] in the FAT buffer to AX.
cluster_next:   lodsw                           ; AX = next cluster to read
; Test whether the cluster number is 0 which means EOF.
                or      ax, ax                  ; EOF?
; If the cluster number is not EOF, jump to `load_next`.
                jne     load_next               ; no, continue
; If the cluster number is EOF, it means the kernel has been fully loaded.
; Put the drive number to BL.
                mov     bl,dl ; drive (left from readDisk)
; Jump to run the kernel.
                jmp     far [loadsegoff_60]     ; yes, pass control to kernel

; Code below aims to load one cluster of the kernel file.
;
; Decrease the cluster number by 2 to get the 0-based sector number.
load_next:      dec     ax                      ; cluster numbers start with 2
                dec     ax

; Put the number of sectors per cluster to DI.
; The higher byte in DI is unused.
                mov     di, word [bsSecPerClust]
; Mask off the higher byte in DI.
; DI specifies the number of sectors to read for `readDisk` below.
                and     di, 0xff                ; DI = sectors per cluster
; Multiply the cluster number in AX by the number of sectors per cluster in DI
; to get the sector number, relative to the FAT data region's sector number.
; DX:AX = AX * DI.
; Now DX:AX stores the relative sector number.
                mul     di
; Add lower 2 bytes of the FAT data region's sector number to AX.
; If overflow, CF becomes 1.
                add     ax, [data_start]
; Add higher 2 bytes of the FAT data region's sector number and CF to AX.
; Now DX:AX stores the absolute sector number.
; DX:AX specifies the starting sector number for `readDisk` below.
                adc     dx, [data_start+2]      ; DX:AX = first sector to read
; Read one cluster of the kernel file to the user read buffer.
                call    readDisk
; Jump to `cluster_next`.
                jmp     short cluster_next

; shows text after the call to this function.

; Print the string following the caller's call instruction.
; The following string's offset is pushed by the caller's call instruction.
;
; Pop the offset of next character to SI.
show:           pop     si
; Put the character in [DS:SI] to AL.
; SI is incremented.
; Now SI points to one byte after the character.
; If the character is `.`, it will be the last character to print, then SI
; points to the next instruction to return to.
                lodsb                           ; get character
; Push SI as the potential return address.
                push    si                      ; stack up potential return address
; Put 0x0E to AH.
; 0x0E means TTY mode for interrupt 0x10 video service.
                mov     ah,0x0E                 ; show character
; Invoke interrupt 0x10 video service to print the character in AL.
                int     0x10                    ; via "TTY" mode
; Test whether the character is `.`.
                cmp     al,'.'                  ; end of string?
; If the character is not `.`, jump to print the next character.
                jne     show                    ; until done
; If the character is `.`, return.
                ret

; Print error message.
boot_error:     call    show
;                db      "Error! Hit a key to reboot."
; Error message.
                db      "Error!."

; Put 0 to AH.
                xor     ah,ah
; Invoke interrupt 0x13 AH=0 service to reset the disk.
                int     0x13                    ; reset floppy
; Invoke interrupt 0x16 AH=0 service to wait for a key press.
                int     0x16                    ; wait for a key
; Invoke interrupt 0x19 AH=0 service to reboot.
                int     0x19                    ; reboot the machine


;       readDisk:       Reads a number of sectors into memory.
;
;       Call with:      DX:AX = 32-bit DOS sector number
;                       DI = number of sectors to read
;                       ES:BX = destination buffer
;
;       Returns:        CF set on error
;                       ES:BX points one byte after the last byte read.

; Read disk sectors to the read buffer, then copy to the destination buffer.
;
; Push SI.
readDisk:       push    si

; Put the sector number to read to fields `LBA_SECTOR_0` and `LBA_SECTOR_16`.
                mov     LBA_SECTOR_0,ax
                mov     LBA_SECTOR_16,dx
; Put the destination buffer's segment to [READADDR_SEG].
                mov     word [READADDR_SEG], es
; Put the destination buffer's offset to [READADDR_OFF].
                mov     word [READADDR_OFF], bx

; Print the following message.
; (gdb) break *0x27B6C
                call    show
; Message.
; 0x1FE0:0x7D6F
                db      "."
read_next:

;******************** LBA_READ *******************************

                                                ; check for LBA support

; Specify to use interrupt 0x13 AH=0x41 service.
                mov     ah,041h                 ;
; Put 0x55AA to BX, as required by interrupt 0x13 AH=0x41 service.
                mov     bx,055aah               ;
; Put the drive number to DL, as required by interrupt 0x13 AH=0x41 service.
                mov     dl, [drive]

                ; NOTE: sys must be updated if location changes!!!
; Test whether the drive number is 0 which means the first floppy disk.
                test    dl,dl                   ; don't use LBA addressing on A:
; If the drive number is 0, jump to `read_normal_BIOS`.
                jz      read_normal_BIOS        ; might be a (buggy)
                                                ; CDROM-BOOT floppy emulation

; Invoke interrupt 0x13 AH=0x41 service to check extensions present.
; If extensions are not present, CF is 1. If present, CX stores the flags:
; 1 – Device access using the LBA packet.
; 2 – Drive locking and ejecting.
; 4 – Enhanced disk drive support.
                int     0x13
; If extensions are not present, jump to `read_normal_BIOS`.
                jc      read_normal_BIOS

; Right-shift CX by 1 bit.
; Now CF stores the lower 1 bit shifted out.
                shr     cx,1                    ; CX must have 1 bit set

; Test whether CF is 1.
; BX = 0xAA55 - 1 + CF - BX = 0xAA54 + CF - 0xAA55 = CF - 1.
                sbb     bx,0aa55h - 1           ; tests for carry (from shr) too!
; If CF is not 1 which means LBA addressing is not supported, jump to
; `read_normal_BIOS`.
                jne     read_normal_BIOS


                                                ; OK, drive seems to support LBA addressing

; Put the address of the LBA packet to SI, as required by interrupt 0x13
; AH=0x42 service.
                lea     si,[LBA_PACKET]

; Put 0 to field `LBA_SECTOR_32`.
                                                ; setup LBA disk block
                mov     LBA_SECTOR_32,bx        ; bx is 0 if extended 13h mode supported
; Put 0 to field `LBA_SECTOR_48`.
                mov     LBA_SECTOR_48,bx

; Specify to use interrupt 0x13 AH=0x42 service.
                mov     ah,042h

; Jump to `do_int13_read`.
                jmp short    do_int13_read



read_normal_BIOS:

;******************** END OF LBA_READ ************************
; Code block below aims to convert the sector number to read into CHS numbers
; to be used by interrupt 0x13 AH=0x02 service.
;
; Put the sector number to read to DX:CX.
                mov     cx,LBA_SECTOR_0
                mov     dx,LBA_SECTOR_16


                ;
                ; translate sector number to BIOS parameters
                ;

                ;
                ; abs = sector                          offset in track
                ;     + head * sectPerTrack             offset in cylinder
                ;     + track * sectPerTrack * nHeads   offset in platter
                ;

; Put the number of sectors per track to AL.
                mov     al, [sectPerTrack]
; Multiply the number of sectors per track by the number of heads to get the
; number of sectors per cylinder.
; AX = AL * [nHeads].
                mul     byte [nHeads]
; Exchange AX and CX.
; Now CX stores the number of sectors per cylinder.
; Now DX:AX stores the sector number to read.
                xchg    ax, cx
                ; cx = nHeads * sectPerTrack <= 255*63
                ; dx:ax = abs
; Divide the sector number to read by the number of sectors per cylinder.
; DX(remainder):AX(quotient) = DX:AX / CX.
; NOW AX stores the cylinder number.
; NOW DX stores the in-cylinder sector offset.
                div     cx
                ; ax = track, dx = sector + head * sectPertrack
; Exchange AX and DX.
; NOW AX stores the in-cylinder sector offset.
; NOW DX stores the cylinder number.
                xchg    ax, dx
                ; dx = track, ax = sector + head * sectPertrack
; Divide the in-cylinder sector offset by the number of sectors per track.
; AH(remainder):AL(quotient) = AX / [sectPerTrack].
; Now AL stores the head number, AH stores the in-track sector number.
                div     byte [sectPerTrack]
                ; dx =  track, al = head, ah = sector
; Put the cylinder number to CX.
                mov     cx, dx
                ; cx =  track, al = head, ah = sector

                ; the following manipulations are necessary in order to
                ; properly place parameters into registers.
                ; ch = cylinder number low 8 bits
                ; cl = 7-6: cylinder high two bits
                ;      5-0: sector
; Put the head number to DH.
                mov     dh, al                  ; save head into dh for bios
; CX stores both the cylinder number (10 bits, possible values are 0 to 1023)
; and the sector number (6 bits, possible values are 1 to 63).
; Layout:
; CX:        ---CH--- ---CL---
; Cylinder : 76543210 98
; Sector   :            543210
;
; Put the lower 8 bits of the cylinder number to CH.
; Put the higher 2 bits of the cylinder number to CL's lower 2 bits.
                xchg    ch, cl                  ; set cyl no low 8 bits
; Right-rotate CL's lower 2 bits to higher 2 bits.
                ror     cl, 1                   ; move track high bits into
                ror     cl, 1                   ; bits 7-6 (assumes top = 0)
; Put the in-track sector number to CL's lower 6 bits.
                or      cl, ah                  ; merge sector into cylinder
; Increment the in-track sector number to make it 1-based.
                inc     cx                      ; make sector 1-based (1-63)

; Point ES:BX to `readDisk`'s read buffer.
; ES:BX specifies interrupt 0x13 AH=0x02 service's read buffer.
                les     bx,[LBA_OFF]

; Specify to use interrupt 0x13 AH=0x02 service.
; AH=0x02 service means read sectors from drive using CHS addressing.
; AL=0x01 means read 1 sector.
                mov     ax, 0x0201
do_int13_read:
; Put the drive number to DL, as required by interrupt 0x13 AH=0x02 or
; interrupt 0x13 AH=0x42 service.
                mov     dl, [drive]
; Invoke interrupt 0x13 AH=0x02 service to read disk using CHS addressing, or
; invoke interrupt 0x13 AH=0x42 service to read disk using LBA addressing.
; If have error, CF becomes 1.
                int     0x13
; If have error, jump to `boot_error`.
                jc      boot_error              ; exit on error

; Code below aims to copy sectors from `readDisk`'s read buffer to the
; destination buffer.
;
; Put the number of bytes per sector to AX.
                mov     ax, word [bsBytesPerSec]

; Push the number of sectors to read in DI.
                push    di
; Put `readDisk`'s read buffer's offset to SI.
                mov     si,READBUF              ; copy read in sector data to
; Put the destination buffer's unfilled part's segment and offset to ES:DI.
                les     di,[READADDR_OFF]       ; user provided buffer
; Put the number of bytes per sector to CX.
                mov     cx, ax
;                shr     cx, 1                   ; convert bytes to word count
;                rep     movsw
; Copy one sector from `readDisk`'s read buffer to the destination buffer.
; Copy one byte from [DS:SI] to [ES:DI], repeat CX times.
; Each time SI and DI are incremented by 1, CX is decremented by 1.
                rep     movsb
; Pop the number of sectors to read to DI.
                pop     di

;               div     byte[LBA_PACKET]        ; luckily 16 !!
; Put 4 to CL, to be used as shift count below.
                mov     cl, 4
; Divide the number of bytes per sector by 16 to get the number of segments
; read.
                shr     ax, cl                  ; adjust segment pointer by increasing
; Increment the destination buffer's segment by the number of segments read.
                add     word [READADDR_SEG], ax ; by paragraphs read in (per sector)

; Increment the LBA packet's sector number's `LBA_SECTOR_0` field.
; If overflow, CF becomes 1.
                add     LBA_SECTOR_0,  byte 1
; Add CF to the LBA packet's sector number's `LBA_SECTOR_16` field.
                adc     LBA_SECTOR_16, byte 0   ; DX:AX = next sector to read
; Decrement the number of sectors to read in DI.
; If DI becomes 0, ZF becomes 1.
                dec     di                      ; if there is anything left to read,
; If the number of sectors to read is not 0, jump to `read_next`.
                jnz     read_next               ; continue

; Put the destination buffer's unfilled part's segment and offset to ES:BX.
                les     bx, [READADDR_OFF]
                ; clear carry: unnecessary since adc clears it
; Pop old SI, which was pushed by the first instruction of `readDisk`.
                pop     si
; Return from `readDisk`.
                ret

; Allocate zeros up to $$:0x01F1 exclusive.
; 0x01F1 + 15 = 512.
; The remaining 15 bytes below make the boot sector exactly 512 bytes.
       times   0x01f1-$+$$ db 0

; Kernel file name and two bytes of 0.
filename        db      "KERNEL  SYS",0,0

; Mark the boot sector as bootable.
sign            dw      0xAA55

%ifdef DBGPRNNUM
; DEBUG print hex digit routines
; Print lower 4 bits of AL as a hex digit.
PrintLowNibble:         ; Prints low nibble of AL, AX is destroyed
; Mask off higher 4 bits of AL.
        and  AL, 0Fh    ; ignore upper nibble
; Test whether AL is greater than 9.
        cmp  AL, 09h    ; if greater than 9, then don't base on '0', base on 'A'
; If AL is not greater than 9, jump to `.printme`.
        jbe .printme
; If AL is greater than 9, add 7 to AL to later convert AL to character A-F.
        add  AL, 7      ; convert to character A-F
        .printme:
; Convert AL to hex digit.
        add  AL, '0'    ; convert to character 0-9
; Put 0x0E to AH.
; 0x0E means TTY mode for interrupt 0x10 video service.
        mov  AH,0x0E    ; show character
; Invoke interrupt 0x10.
        int  0x10       ; via "TTY" mode
; Return.
        retn
; Print AL as two hex digits.
PrintAL:                ; Prints AL, AX is preserved
; Save AX.
        push AX         ; store value so we can process a nibble at a time
; Shift higher 4 bits of AL to lower 4 bits.
        shr  AL, 4              ; move upper nibble into lower nibble
; Print lower 4 bits of AL as a hex digit.
        call PrintLowNibble
; Restore AX.
        pop  AX         ; restore for other nibble
; Save AX.
        push AX         ; but save so we can restore original AX
; Print lower 4 bits of AL as a hex digit.
        call PrintLowNibble
; Restore AX.
        pop  AX         ; restore for other nibble
; Return.
        retn
; Print AX as hex digits.
PrintNumber:            ; Prints (in Hex) value in AX, AX is preserved
; Exchange AH and AL in order to print AH.
        xchg AH, AL     ; high byte 1st
; Print AL (the old AH value) as two hex digits.
        call PrintAL
; Exchange AH and AL in order to print AL.
        xchg AH, AL     ; now low byte
; Print AL as two hex digits.
        call PrintAL
; Return.
        retn
%endif
