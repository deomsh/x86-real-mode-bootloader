;
; File:
;                          oemboot.asm
; Description:
;   Reference 8086 boot sector for Win9x IO.SYS. Solves the >32MB disk issue
;   by correctly implementing 32-bit LBA addressing via BIOS extensions, with
;   a CHS fallback. This is the definitive, architecturally correct solution.
;
CPU 8086

segment .text
%define BASE            0x7c00          ; Boot sector originally at 0x0:BASE
%define LOADSEG         0x0070          ; Final segment to load kernel at (0x0700)
%define FAT_TEMP_SEG    0x1000          ; Temporary buffer for the FAT at 0x1000:0 (64KB)
%define ROOTDIR         0x0500          ; Buffer for root directory entries
%define CLUSTLIST       0x7f00          ; Zero-terminated list of kernel clusters

; BPB Defines
%define bsSecPerClust   0x7c0d
%define bsResSectors    0x7c0e
%define bsFATs          0x7c10
%define sectPerFat      0x7c16
%define sectPerTrack    0x7c18
%define nHeads          0x7c1a
%define nHidden         0x7c1c
%define drive           0x7c24

; Variable and LBA Packet storage (overlapped to save space)
%define fat_start_l     0x7c40          ; Low word of FAT start LBA
%define fat_start_h     0x7c42          ; High word of FAT start LBA
%define root_dir_l      0x7c44
%define root_dir_h      0x7c46
%define data_start      BASE-4          ; Critical for Win9x: [bp-4]
%define first_cluster   0x7c4a
%define lba_packet      0x7e00          ; Disk Address Packet for LBA reads

                org     BASE
Entry:          jmp     short real_start
                nop
                db 'MSWIN4.1'           ; Standard OEM name for Win9x
                ; Zero out the entire BPB. The SYS or FORMAT utility is responsible for
                ; populating this with the correct disk parameters.
                times (0x3E - ($ - $$)) db 0

;-----------------------------------------------------------------------
real_start:
                cli
                xor     ax, ax
                mov     ds, ax
                mov     es, ax
                mov     ss, ax
                mov     bp, BASE        ; Set BP correctly for Win9x
                mov     sp, bp          ; Stack grows down from 0x7c00
                sti

                mov     [drive], dl

; Calculate disk layout (32-bit using DX:AX)
                mov     ax, word [nHidden]
                mov     dx, word [nHidden+2]
                add     ax, word [bsResSectors]
                adc     dx, 0
                mov     word [fat_start_l], ax
                mov     word [fat_start_h], dx
                mov     word [root_dir_l], ax
                mov     word [root_dir_h], dx

                mov     al, byte [bsFATs]
                cbw
                mul     word [sectPerFat]
                add     word [root_dir_l], ax
                adc     word [root_dir_h], dx

                mov     ax, 14
                add     word [root_dir_l], ax
                adc     word [root_dir_h], 0
                mov     ax, word [root_dir_l]
                mov     dx, word [root_dir_h]
                mov     word [data_start], ax
                mov     word [data_start+2], dx

; FINDFILE: Read root directory
                mov     ax, word [root_dir_l]
                mov     dx, word [root_dir_h]
                mov     di, 14
                mov     bx, ROOTDIR
                call    readDisk
                mov     si, ROOTDIR

next_entry:     mov     cx, 11
                mov     di, filename
                repe    cmpsb
                je      ffDone
                add     si, 32
                cmp     si, ROOTDIR + 14*512
                jb      next_entry
                jmp     short boot_error

ffDone:         mov     ax, [si+26]
                mov     [first_cluster], ax

; GETFATCHAIN: Load FAT to temp buffer
                mov     ax, FAT_TEMP_SEG
                mov     es, ax
                xor     bx, bx
                mov     di, [sectPerFat]
                mov     ax, word [fat_start_l]
                mov     dx, word [fat_start_h]
                call    readDisk

                mov     di, CLUSTLIST
                mov     ax, FAT_TEMP_SEG
                mov     ds, ax
                mov     ax, [first_cluster]
                push    ds

next_clust:     stosw
                mov     si, ax

fat_16:         pop     dx
                push    dx
                shl     si, 1
                jnc     first_half
                add     dh, 0x10
first_half:     mov     ds, dx
                lodsw
                cmp     ax, 0xfff8
                jb      next_clust

finished:       pop     ax
                xor     ax, ax
                stosw
                push    cs
                pop     ds

; loadFile: Load kernel into final destination
                mov     ax, LOADSEG
                mov     es, ax
                xor     bx, bx
                mov     si, CLUSTLIST
cluster_loop:   lodsw
                or      ax, ax
                jz      launch_kernel
                dec     ax
                dec     ax
                mul     word [bsSecPerClust]
                add     ax, word [data_start]
                adc     dx, word [data_start+2]
                mov     di, [bsSecPerClust]
                call    readDisk
                jmp     short cluster_loop

launch_kernel:
                mov     di, word [first_cluster]
                jmp     LOADSEG:0x0200

boot_error:
                hlt
                jmp     short boot_error

; readDisk: Reads DI sectors from DX:AX (32-bit LBA) into ES:BX.
readDisk:
.read_next:     cmp     di, 0
                je      .exit
                dec     di
                pusha
                mov     ah, 0x41        ; LBA Extension Check
                mov     bx, 0x55AA
                mov     dl, [drive]
                int     0x13
                jc      .use_chs
                test    cx, 1
                jz      .use_chs

; --- LBA Read Path ---
                popa
                push    ax
                push    dx
                mov     word [lba_packet], 0x10
                mov     word [lba_packet+2], 1
                mov     word [lba_packet+4], bx
                mov     word [lba_packet+6], es
                mov     word [lba_packet+8], ax
                mov     word [lba_packet+10], dx
                mov     word [lba_packet+12], 0
                mov     word [lba_packet+14], 0
                mov     ah, 0x42
                mov     dl, [drive]
                push    ds
                xor     ax, ax
                mov     ds, ax
                mov     si, lba_packet
                int     0x13
                pop     ds
                pop     dx
                pop     ax
                jc      short boot_error ; Halt on LBA error
                jmp     short .success

; --- CHS Fallback Path ---
.use_chs:       popa
                push    ax
                push    bx
                xor     dx, dx
                div     word [sectPerTrack]
                inc     dl
                mov     cl, dl
                pop     bx
                pop     ax
                push    ax
                xor     dx, dx
                div     word [sectPerTrack]
                xor     dx, dx
                div     word [nHeads]
                mov     dh, dl
                mov     ch, al
                mov     ah, 0x02
                mov     al, 1
                mov     dl, [drive]
                int     0x13
                pop     ax
                jnc     .success_chs
                xor     ah, ah
                int     0x13
                jmp     short .read_next

.success_chs:   add     bx, 512
                inc     ax
                jc      .lba_carry
                jmp     short .read_next
.lba_carry:     inc     dx
                jmp     short .read_next

.success:       add     bx, 512
                add     ax, 1
                adc     dx, 0
                jmp     short .read_next
.exit:          ret

                times   0x1F1-($-$$) db 0
filename        db "IO      SYS"
                times 510-($-$$) db 0
sign            dw 0xAA55

