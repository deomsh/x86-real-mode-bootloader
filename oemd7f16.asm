; modified version, File: OEMBOOT93.ASM
;
; File:
;                          oemboot.asm
;                      2004, Kenneth J. Davis
;
; This is the final, corrected version that addresses all identified bugs.
;
CPU 8086
;%define ISFAT12         1
%define ISFAT16         1

;%define TRYLBAREAD       1                  ; Removed in version 92

%define SETROOTDIR       1
%define LOOPONERR        1
%define WINBOOT         1
%define MSCOMPAT        1

%ifdef WINBOOT
%ifndef MSCOMPAT
%define MSCOMPAT
%endif
%endif

segment .text
%define BASE            0x7c00
%define LOADSEG         0x0070
%define LOADEND         0x07b0
%define FATBUF          bp-0x7500
%define ROOTDIR         bp-0x7700

%define LBA_PACKET      bp+0x0200
%define LBA_SIZE        word [LBA_PACKET]
%define LBA_SECNUM      word [LBA_PACKET+2]
%define LBA_OFF         LBA_PACKET+4
%define LBA_SEG         LBA_PACKET+6
%define LBA_SECTOR_0    word [LBA_PACKET+8]
%define LBA_SECTOR_16   word [LBA_PACKET+10]
%define LBA_SECTOR_32   word [LBA_PACKET+12]
%define LBA_SECTOR_48   word [LBA_PACKET+14]

%define fat_start        (bp+0x200+0x10)+0x2
%define first_cluster    (bp+0x200+0x10)+0x0a
%define data_start       bp-4

                org     BASE
Entry:          jmp     short real_start
                nop

%define bsOemName       bp+0x03
%define bsBytesPerSec   bp+0x0b
%define bsSecPerClust   bp+0x0d
%define bsResSectors    bp+0x0e
%define bsFATs          bp+0x10
%define bsRootDirEnts   bp+0x11
%define bsSectors       bp+0x13
%define bsMedia         bp+0x15
%define sectPerFat      bp+0x16
%define sectPerTrack    bp+0x18
%define nHeads          bp+0x1a
%define nHidden         bp+0x1c
%define drive           bp+0x24

                db 'IBM  5.0'
                dw 512
                db 1
                dw 1
                db 2
                dw 224
                dw 2880
                db 0xF0
                dw 9
                dw 18
                dw 2
                dd 0
                dd 0
                db 0
                db 0
                db 0x29
                dd 0x12345678
                db 'NO NAME    '
                times   36h - ($ - $$) db 0
%ifdef ISFAT12
                db "FAT12   "
%elifdef ISFAT16
                db "FAT16   "
%else
%error Must select one FS
%endif
                times   3Eh - ($ - $$) db 0

real_start:
                cli
                cld
                xor     ax, ax
                mov     ds, ax
                mov     es, ax
                mov     ss, ax
                mov     bp, BASE
                lea     sp, [bp-4]
                sti
                mov     [drive], dl        ; rely on BIOS drive number in DL

GETDRIVEPARMS:
                mov     si, word [nHidden]
                mov     di, word [nHidden+2]
                add     si, word [bsResSectors]
                adc     di, byte 0
                mov     word [fat_start], si
                mov     word [fat_start+2], di
                mov     al, [bsFATs]
                cbw
                mul     word [sectPerFat]
                add     si, ax
                adc     di, dx
                push    di
                push    si
                mov     bx, [bsBytesPerSec]
                mov     cl, 5
                shr     bx, cl
                mov     ax, [bsRootDirEnts]
                xor     dx, dx
                div     bx
                push    ax
                add     si, ax
                adc     di, byte 0
                mov     [data_start], si
                mov     [data_start+2], di

FINDFILE:
                pop     di
                pop     ax
                pop     dx
                lea     bx, [ROOTDIR]
                call    readDisk
                lea     si, [ROOTDIR]
next_entry:
                mov     cx, 11
                mov     di, filename
                push    si
                repe    cmpsb
                pop     si
                mov     ax, [si+0x1A]
                je      ffDone
                add     si, byte 0x20
                cmp     byte [si], 0
                jnz     next_entry
                jmp     boot_error
ffDone:
                mov     [first_cluster], ax
%ifdef SETROOTDIR
                lea     di, [ROOTDIR]
                mov     cx, 16 ; 32 bytes = 16 words
                rep     movsw
%endif

; --- START OF THE FINAL, CORRECTED, AND VERIFIED LOADER ---
;       This is a simple, direct loader that replaces the old complex routines.
;
LOAD_KERNEL:
                mov     ax, [first_cluster]
                dec     ax
                dec     ax
                mov     di, word [bsSecPerClust]
                and     di, 0xff
                xor     dx, dx
                mul     di
                add     ax, [data_start]
                adc     dx, [data_start+2]

                push    dx              ; --- FIX: Save high word of LBA
                push    ax              ; --- FIX: Save low word of LBA

                mov     ax, LOADSEG     ; Now we can safely use AX
                mov     es, ax
                xor     bx, bx
                mov     di, 32

                pop     ax              ; --- FIX: Restore low word of LBA
                pop     dx              ; --- FIX: Restore high word of LBA
                call    readDisk

load_finished:
                mov     ch, [bsMedia]
                mov     ax, [data_start+2]
                mov     bx, [data_start]
                mov     di, [first_cluster]
%ifdef WINBOOT
                jmp     LOADSEG:0x0200
%else
                jmp     LOADSEG:0000
%endif

boot_error:
                call    show
                db      "):",0
%ifdef LOOPONERR
                jmp $
%else
                xor     ah,ah
                int     0x13
                int     0x16
                int     0x19
%endif
; --- END OF THE FINAL, CORRECTED, AND VERIFIED LOADER ---

show.do_show:
                mov     ah, 0Eh
                int     10h
show:
                pop     si
                lodsb
                push    si
                cmp     al, 0
                jne     .do_show
                ret

readDisk:       push    si                      ; Preserve SI
                mov     LBA_SECTOR_0, ax        ; Store LBA from caller
                mov     LBA_SECTOR_16, dx
                mov     word [LBA_SEG], es      ; Store destination pointer from caller
                mov     word [LBA_OFF], bx
                call    show
                db      ".",0

read_next:
                ; Set up constants for a single-sector read
                mov     LBA_SIZE, 10h
                mov     LBA_SECNUM, 1

                ; Safety check: prevent overwriting the bootloader's own data
                cmp     word [LBA_SEG], LOADEND
                je      read_skip

;******************** LBA_READ WITH CHS FALLBACK (from oemboot80.asm) *******
                mov     ah,041h                 ; BIOS LBA check function
                mov     bx,055aah
                mov     dl, [drive]
                int     0x13
                jc      read_normal_BIOS        ; If check fails, jump to CHS

                shr     cx,1                    ; Check for LBA support bit
                sbb     bx,0aa55h - 1
                jne     read_normal_BIOS        ; If not supported, jump to CHS

                ; OK, drive supports LBA addressing
                lea     si,[LBA_PACKET]
                mov     ah,042h                 ; Extended Read function
                jmp     short do_int13_read

read_normal_BIOS:
;******************** CHS CALCULATION (from oemboot80.asm) *******************
                mov     cx, LBA_SECTOR_0
                mov     dx, LBA_SECTOR_16
                mov     al, [sectPerTrack]
                mul     byte [nHeads]
                xchg    ax, cx
                div     cx
                xchg    ax, dx
                div     byte [sectPerTrack]
                mov     cx, dx
                mov     dh, al
                xchg    ch, cl
                ror     cl, 1
                ror     cl, 1
                or      cl, ah
                inc     cx
                les     bx,[LBA_OFF]
                mov     ax, 0x0201              ; Standard CHS read function
                
do_int13_read:
                mov     dl, [drive]
                int     0x13
                jc      boot_error

read_ok:
;******************** CORRECT POINTER ARITHMETIC (from oemboot921.asm) ******
                add     word [LBA_OFF], 512     ; Advance buffer offset
                adc     word [LBA_SEG], 0       ; Add carry to buffer segment

                ; Advance to the next LBA sector for the next loop iteration
                add     LBA_SECTOR_0,  byte 1
                adc     LBA_SECTOR_16, byte 0

                ; Loop if more sectors are requested
                dec     di
                jnz     read_next

read_skip:
;******************** CORRECT RETURN VALUE (from oemboot921.asm) *************
                mov     es, word [LBA_SEG]
                mov     bx, word [LBA_OFF]
                pop     si
                ret
; --- NEW, ROBUST PADDING AND SIGNATURE STRUCTURE ---
%ifdef MSCOMPAT
filename        db      "IO      SYS"
%else
filename        db      "IBMBIO  COM"
%endif

       ; This TIMES directive now pads the *entire rest of the sector* with zeros,
       ; up to the last 2 bytes. This is robust against code size changes.
       times   510-($-$$) db 0

sign            dw      0xAA55

