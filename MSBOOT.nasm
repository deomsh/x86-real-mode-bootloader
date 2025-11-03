;	Page 60,132 ;	    SCCSID = @(#)msboot.asm	    1.1 85/05/13
; TITLE BOOT	SECTOR 1 OF TRACK 0 - BOOT LOADER
;
;   Rev 1.0 ChrisP, AaronR and others.	2.0 format boot
;
;   Rev 3.0 MarkZ   PC/AT enhancements
;		    2.50 in label
;   Rev 3.1 MarkZ   3.1 in label due to vagaries of SYSing to IBM drive D's
;		    This resulted in the BPB being off by 1.  So we now trust
;		    2.0 and 3.1 boot sectors and disbelieve 3.0.
;
;   Rev 3.2 LeeAc   Modify layout of extended BPB for >32M support
;		    Move PHYDRV to 3rd byte from end of sector
;		    so that it won't have to be moved again
;		    FORMAT and SYS count on PHYDRV being in a known location
;
;   Rev. 3.3 D.C. L. Changed Sec 9 EOT field from 15 to 18. May 29, 1986.
;
;   Rev 3.31 MarkT  The COUNT value has a bogus check (JBE????) to determine
;		    if we've loaded in all the sectors of IBMBIO. This will
;		    cause too big of a load if the sectors per track is high
;		    enough, causing either a stack overflow or the boot code
;		    to be overwritten.
;
;   Rev 4.00 J. K.  For DOS 4.00 Modified to handle the extended BPB, and
;		    32 bit sector number calculation to enable the primary
;		    partition be started beyond 32 MB boundary.
;
;
; The ROM in the IBM PC starts the boot process by performing a hardware
; initialization and a verification of all external devices.  If all goes
; well, it will then load from the boot drive the sector from track 0, head 0,
; sector 1.  This sector is placed at physical address 07C00h.	The initial
; registers are set up as follows:  CS=DS=ES=SS=0.  IP=7C00h, SP=0400H.
;
; The code in this sector is responsible for locating the MSDOS device drivers
; (IBMBIO) and for placing the directory sector with this information at
; physical address 00500h.  After loading in this sector, it reads in the
; entirety of the BIOS at BIOSEG:0 and does a long jump to that point.
;
; If no BIOS/DOS pair is found an error message is displayed and the user is
; prompted to reinsert another disk.  If there is a disk error during the
; process, a message is displayed and things are halted.
;
; At the beginning of the boot sector, there is a table which describes the
; MSDOS structure of the media.  This is equivalent to the BPB with some
; additional information describing the physical layout of the driver (heads,
; tracks, sectors)
;
;==============================================================================
; REVISION HISTORY:
; AN000 - New for DOS Version 4.00 - J.K.
; AC000 - Changed for DOS Version 4.00 - J.K.
; AN00x - PTM number for DOS Version 4.00 - J.K.
;==============================================================================
; AN001; d52 Make the fixed positioned variable "CURHD" to be local.  7/6/87 J.K.
; AN002; d48 Change head settle at boot time.			     7/7/87 J.K.
; AN003; P1820 New message SKL file				   10/20/87 J.K.
; AN004; D304 New structrue of Boot record for OS2.		   11/09/87 J.K.
;==============================================================================
; The segment:offset notation is a way to specify a memory address in real mode (16-bit x86 architecture). It consists of two parts:
; Segment: A 16-bit value representing a memory segment; Offset: A 16-bit value representing the location within that segment.
; The actual physical address is calculated as: Physical Address = (Segment * 16) + Offset
; Example: Segment:Offset Notation: Segment: 0x70 : Offset: 0x1234
; Physical Address = (0x70 * 16) + 0x1234 = 0x700 + 0x1234 = 0x1934
; 4 segment registers in x86 (CS, DS, ES, SS): used to specify the segment part of a memory address in segment:offset notation.
; Segment Registers Overview: 
;	CS (Code Segment): Defines the segment for code execution; The instruction pointer (IP) works with CS to form the address of the next instruction to execute (CS:IP).
;   DS (Data Segment): Defines the segment for most data access operations (e.g., mov, add, etc.). Default segment for memory operands unless overridden.
;   ES (Extra Segment): Used as an additional data segment, often for string operations or BIOS interrupts. Commonly paired with DI (Destination Index) for destination memory access.
;	SS (Stack Segment): Defines the segment for the stack. The stack pointer (SP) works with SS to manage the stack (SS:SP).
;==============================================================================
;SECTION .text				; DeepSeek V3
;[BITS 16]					; DeepSeek V3
;
;SECTION .data       		; Define data section [DeepSeek V3]
;
; This is the corrected NASM conversion of the provided MSBOOT.ASM source code [1].
bits 16
org 0x7C00
; --- Configuration Constants ---
ORIGIN 		equ 	0x7C00	; ORIGIN	    EQU 7C00H			; Origin of bootstrap LOADER
BIOSEG 		equ		0x70 	; BIOSEG	    EQU 70H			; destingation segment of BIOS
BioOff 		equ		0x700 	; BioOff	    EQU 700H			; offset of bios
cbSec 		equ		512		; cbSec	    EQU 512
cbDirEnt 	equ		32 		; cbDirEnt    EQU 32
DirOff	    equ		0x500 	; DirOff	    EQU 500h
IBMLOADSIZE	equ		3		; IBMLOADSIZE equ 3			;J.K. Size of IBMLOAD module in sectors
ROM_DISKRD	equ		2		; ROM_DISKRD  equ 2
;
%include "version.inc"		; include version.inc
;
; Define the destination segment of the BIOS, including the initialization
; label
;
BIOS equ BIOSEG ; !for nasm
	;	Use equ if: You want BIOS to act as a label pointing to the address 0x70.
	;	You need to access memory at BIOS (e.g., mov al, [BIOS]).
; SEGBIOS SEGMENT AT BIOSEG
; BIOS	LABEL	BYTE
; SEGBIOS ENDS
;
; CODE	SEGMENT
;	ASSUME CS:CODE,DS:NOTHING,ES:NOTHING,SS:NOTHING
;
;;	 ORG	 DirOff + 1Ch
;;BiosFS  LABEL	 WORD
;
;org ORIGIN		;	ORG	ORIGIN
;
; !from msdos027.nasm: DSKADR      equ 0x0078 ; POINTER TO DRIVE PARAMETERS (INT 1Eh vector is at 0000:0078)
DSKADR      equ 0x1E * 4   ;DSKADR	=	1EH*4			;POINTER TO DRIVE PARAMETERS
;
;GLOBAL UDATA        		; Make UDATA visible to other modules - ALL next lines from:  [DeepSeek V3]
;UDATA:              		; Define UDATA as a label
;    resb 21         		; Reserve 21 bytes for the data structure
				; Define symbolic constants for offsets from UDATA
;Sec9 	equ		UDATA+0    	; 11 byte diskette parm. table
;BIOS$_L equ		UDATA+11
;BIOS$_H equ		UDATA+13	;AN000;
;CURTRK 	equ		UDATA+15
;CURSEC 	equ		UDATA+17
;DIR$_L 	equ		UDATA+18
;DIR$_H 	equ		UDATA+20		;AN000;
;
; Public $START
; $START:
GLOBAL EntryPoint:			; Declares EntryPoint as a global symbol, making it visible to the linker or other modules.  
							; In NASM, GLOBAL is equivalent to global (case-insensitive).
    jmp short START			; 
; A short jump (2-byte instruction) to the label START.  
; The short keyword ensures the jump is encoded as a relative 8-bit displacement (saving space).
;0x0000000000000000:  EB 3C             jmp        0x3e 							; jmp short START
	nop						; A no-operation instruction (1 byte). Often used for alignment or as a placeholder for patching.
;0x0000000000000002:  90                nop  		   		; NOP for alignment, common practice      
; Purpose: This pattern is typically used to separate the Entry Point from Code. The EntryPoint label marks where execution begins, but the actual code starts at START.  
; 	This allows for header data (e.g., BIOS Parameter Block in bootloaders) to be placed between EntryPoint and START.
; Compatibility with COM Files: In MS-DOS COM files, the first instruction is often a jmp to skip over data or headers.
; Bootloader Usage: In boot sectors, this pattern skips over the BIOS Parameter Block (BPB) or other metadata.
;
;J.K. Extened_BPB
;
%ifdef ibmcopyright          ; Check if ibmcopyright is defined
    db 'IBM  '               ; If true, define "IBM  "
%else
    db 'MSDOS'               ; If false, define "MSDOS"
%endif
    db '4.0'                 ; Always define "4.0"
; if ibmcopyright
; 	  DB	  "IBM  "
; else
;     DB	  "MSDOS"
; endif
;	  DB	  "4.0"        	;AN005;
;0x0000000000000003:  29 74 47          sub        word [si + 0x47], si
;0x0000000000000006:  32 2A             xor        ch, byte [bp + si]
;0x0000000000000008:  49                dec        cx
;0x0000000000000009:  48                dec        ax
;0x000000000000000a:  43                inc        bx
;
	ByteSec			dw	cbSec      		; Bytes per Sector ; ByteSec   DW	  cbSec 	; SIZE OF A PHYSICAL SECTOR
;0x000000000000000b:  00 02     	        add        byte [bp + si], al
					db	8							;	  DB	  8			; SECTORS PER ALLOCATION UNIT
;0x000000000000000d:  01             add        word [bx + di], ax
	cSecRes			dw	1				; cSecRes   DW	  1			; NUMBER OF RESERVED SECTORS
;0x000000000000000e:  01 00             add        word [bx + di], ax
;0x000000000000000d:  01 01             add        word [bx + di], ax
	cFat			db	2						; cFat	  DB	  2			; NUMBER OF FATS
;0x0000000000000010:  02             add        byte [bp + si], al
;0x000000000000000f:  00 02             add        byte [bp + si], al
	DirNum			dw 	512				; DirNum	  DW	  512			; NUMBER OF DIREC ENTRIES
;0x0000000000000011:  E0 00             loopne     0x13
	cTotSec			dw	4*17*305-1		; cTotSec   DW	  4*17*305-1		; NUMBER OF SECTORS - NUMBER OF HIDDEN SECTORS
										;  (0 when 32 bit sector number)
;0x0000000000000013:  40 0B                inc        ax
	MEDIA			db 	0xF8			; MEDIA	  DB	  0F8H			; MEDIA BYTE
;0x0000000000000015:  F0             or         si, ax
	cSecFat			dw	8				; cSecFat   DW	  8			; NUMBER OF FAT SECTORS
;0x0000000000000016:  09 00             or         word [bx + si], ax
	SECLIM			dw	17				; SECLIM	  DW	  17			; SECTORS PER TRACK
;0x0000000000000018:  12 00             adc        al, byte [bx + si]
	HDLIM			dw	4				; HDLIM	  DW	  4			; NUMBER OF SURFACES !HEADS
;0x000000000000001a:  02 00             add        al, byte [bx + si]
;
; Ext_cSecHid label dword
	cSecHid_L		dw	63			; cSecHid_L DW	  1			;AN000; NUMBER OF HIDDEN SECTORS
;0x000000000000001c:  00 00             add        byte [bx + si], al
	cSecHid_H		dw	0			; cSecHid_H dw	  0			;AN000; high order word of Hiden Sectors
;0x000000000000001e:  00 00             add        byte [bx + si], al
;
; Ext_cTotSec label dword
	cTotSec_L 		dw	0			; cTotSec_L dw	  0			;AN000; 32 bit version of NUMBER OF SECTORS
;0x0000000000000020:  00 00             add        byte [bx + si], al
	ctotsec_H 		dw	0			;AN000; (when 16 bit version is zero)
;0x0000000000000022:  00 00             add        byte [bx + si], al
;
	PhyDrv	  		db	0x80			; PhyDrv	  db	 80h			;AN004;
;0x0000000000000024:  00             add        byte [bx + si], al
	CURHD			db  0			; Current Head Number
;0x0000000000000025:  00
	Ext_Boot_Sig	db    41		; Ext_Boot_Sig	db    41		;AN000;
;0x0000000000000026:  29                sub        word [bp + si], cx
;0x0000000000000026:  29 0A             sub        word ptr [bp + si], cx
	Boot_Serial		dd    0			; Boot_Serial	dd    0 		;AN000;
;0x0000000000000027:  0A
;0x0000000000000028:  11 63 19          adc        word [bp + di + 0x19], sp
	Boot_Vol_Label	db    'NO NAME    ' ; Boot_Vol_Label	db    'NO NAME    '     ;AN000;
;0x000000000000002b:  4D                dec        bp
;0x000000000000002c:  53                push       bx
;0x000000000000002d:  44                inc        sp
;0x000000000000002e:  34 30             xor        al, 0x30
;0x0000000000000030:  31 20             xor        word [bx + si], sp
;0x0000000000000032:  20 20             and        byte [bx + si], ah
;0x0000000000000034:  20 20             and        byte [bx + si], ah
	Boot_System_id	db    'FAT12   '	; Boot_System_id	db    'FAT12   '        ;AN000;
;0x0000000000000036:  46                inc        si
;0x0000000000000037:  41                inc        cx
;0x0000000000000038:  54                push       sp
;0x0000000000000039:  31 32             xor        word [bp + si], si
;0x000000000000003b:  20 20             and        byte [bx + si], ah
;0x000000000000003d:  20 
;
; J.K. Danger!!! If not 32 bit sector number calculation, FORMAT should
; set the value of cSecHid_h and Ext_cTotSec to 0 !!!
;
; Public UDATA
; UDATA	LABEL	byte
; Sec9	  equ	byte ptr UDATA+0	;11 byte diskette parm. table
; BIOS$_L   EQU	WORD PTR UDATA+11
; BIOS$_H   equ	word ptr UDATA+13	;AN000;
; CURTRK	  EQU	WORD PTR UDATA+15
; CURSEC	  EQU	BYTE PTR UDATA+17
; DIR$_L	  EQU	WORD PTR UDATA+18
; Dir$_H	  equ	word ptr UDATA+20	;AN000;
;
; Start of Bootcode 0x3e
;----------------------------------------------------------
; Bootloader Code
;----------------------------------------------------------
UDATA:
; --- Local variable definitions ---
Sec9        equ UDATA+0       ; A temporary storage area for the disk parameter table.
BIOS$_L      equ UDATA+11      ; Stores the low word of the data area's starting sector LBA.
BIOS$_H      equ UDATA+13      ; Stores the high word of the data area's starting sector LBA.
CURTRK      equ UDATA+15      ; Stores the current track/cylinder for disk reads.
CURSEC      equ UDATA+17      ; Stores the current sector for disk reads.
DIR$_L       equ UDATA+18      ; Stores the low word of the root directory's starting sector LBA.
DIR$_H       equ UDATA+20      ; Stores the high word of the root directory's starting sector LBA.
;
START:
;
; First thing is to reset the stack to a better and more known place.  The ROM
; may change, but we'd like to get the stack in the correct place.
	cli								; (Clear Interrupts) instruction, which disables hardware interrupts.
; Prevent interrupts during critical sections (e.g., setting up the stack). Avoid race conditions during hardware initialization.
;0x000000000000003e:  FA            ;    CLI				;Stop interrupts till stack ok
;XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
; NEW code, safe according to DeepSeek
    mov 		ax, cs              ; Copy CS to AX (8C C8) instead of MASM:   ASSUME	SS:CODE
    mov 		ss, ax              ; Set SS = CS (8E D0)
; IF SS is not explicitly set to match CS, this can be risky because the BIOS might load the bootloader with CS = 0x07C0 instead of CS = 0x0000.
	; ASSUME	SS:CODE
	mov 		sp, ORIGIN 			; Sets the stack pointer (SP) to ORIGIN (i.e. 0x7C00). 
	xor     	ax, ax				; Clear AX. Prepares AX for use in setting up segment registers. Clears all arithmetic flags (ZF=1, CF=0, etc.). Smaller and faster than mov ax, 0 (2 bytes vs 3 bytes).
    mov 		ds, ax              ; Set DS = 0x0000
;    mov 		es, ax              ; Set ES = 0x0000
;    sti         		            ; Re-enable interrupts
; END of new code XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
;	xor        	ax, ax
;0x000000000000003f:  33 C0             xor        ax, ax
;	mov        	ss, ax				; Sets the stack segment (SS) to 0x0000 (since AX=0). Prepares the stack for use in real mode. SS defines the segment for stack operations (push, pop, etc.).
; On x86, mov ss, ax automatically disables interrupts for the next instruction to ensure atomic stack setup.
;0x0000000000000041:  8E D0             mov        ss, ax
	;   ASSUME	SS:CODE
;	mov 		sp, ORIGIN 			; Sets the stack pointer (SP) to ORIGIN (i.e. 0x7C00). 
; The stack grows downward from 0x7C00 (e.g., push decrements SP), ensuring it doesn’t overwrite the bootloader code.
;0x0000000000000043:  BC 00 7C          mov        sp, 0x7c00 					; mov sp, ORIGIN        ; Stack pointer starts at 0x7C00
	push       	ss					; Push SS onto the stack
;0x0000000000000046:  16                push       ss
	pop        	es					; Pop SS into ES	
;0x0000000000000047:  07                pop        es
										; ASSUME	ES:CODE
; We copy the disk parameter table into a local area.  We scan the table above
; for non-zero parameters.  Any we see get changed to their non-zero values.
; J.K. We copy the disk parameter table into a local area (overlayed into the
; code), and set the head settle time to 1, and End of Track to SECLIM given
; by FORMAT.
	mov        	bx, DSKADR			; Set BX = 0x78
;0x0000000000000048:  BB 78 00          mov        bx, 0x78						;	MOV	BX,DSKADR
	lds        	si, ss:[bx]			; Load DS:SI from SS:BX
;0x000000000000004b:  36 C5 37          lds        si, ss:[bx]
	push       	ds					; Push DS onto the stack
;0x000000000000004e:  1E                push       ds
	push       	si					; Push SI onto the stack
;0x000000000000004f:  56                push       si
	push       	ss					; Push SS onto the stack
;0x0000000000000050:  16                push       ss
	push       	bx					; Push BX onto the stack
;0x0000000000000051:  53                push       bx
; DeepSeek V3: In NASM 0.98, the offset keyword is not used. Instead, you directly reference the label (Sec9 or UDATA) to calculate offsets.
	mov        	di, Sec9			; DeepSeek: DI now points to Sec9 (UDATA+0) as destination	 
;0x0000000000000052:  BF 3E 7C          mov        di, 0x7c3e					; 	MOV	DI,offset Sec9
	mov        	cx, 0xB				; DeepSeek: Sets CX to the number of bytes to copy (11)
;0x0000000000000055:  B9 0B 00          mov        cx, 0xb						; 	MOV	CX,11
	cld								; DeepSeek: cld Ensures MOVSB processes data in the forward direction
; clears the Direction Flag (DF), ensuring string operations process data in the forward direction.
; It’s typically used before string operations like MOVSB, LODSB, or STOSB.
; In your example, CLD prepares the processor for a string operation involving DI and CX.
;0x0000000000000058:  FC                cld        
;
; if	$ le BIOS$_L
;	%OUT Don't destroy unexcuted code yet!!!
; endif
;
; DeepSeek: In NASM, the full syntax rep movsb byte es:[di], byte [si] is not needed and would actually result in an error.
; DeepSeek: NASM simplifies string instructions like MOVSB, assuming the source and destination implicitly.
	rep movsb				; NASM assumes DS for the source
	; MOVSB: Moves a byte from DS:[SI] (source) to ES:[DI] (destination). Automatically increments SI and DI (or decrements if DF = 1).
	; REP: Repeats MOVSB CX times.
;0x0000000000000059:  F3 A4             rep movsb  byte es:[di], byte [si]		; 	repz	movsb		;AN000;
; Following two lines: copies ES into DS (DS = ES)
	push       	es					; Push ES onto the stack
;0x000000000000005b:  06                push       es
	pop        	ds					; Pop SS into DS	
;0x000000000000005c:  1F                pop        ds
									 ; assume	ds:code 		;AN000;
; mov	 byte ptr [di-2], 1	 ;AN000; Head settle time
; J.K. Change the head settle to 15 ms will slow the boot time quite a bit!!!
	mov         byte [di - 2], 0xF	; Updates the segment part of the disk parameter table vector at SS:BX+2
;0x000000000000005d:  C6 45 FE 0F       mov        byte [di - 2], 0xf
	mov    	    cx, word [SECLIM]	; Set CX = SECLIM (SECTORS PER TRACK). Loads the sectors per track value into CX
;0x0000000000000061:  8B 0E 18 7C       mov        cx, word [0x7c18] 			; mov	cx, SECLIM		;AN004;
	mov        	byte [di - 7], cl	; Update disk parameter table with SECLIM
;0x0000000000000065:  88 4D F9          mov        byte [di - 7], cl
; Place in new disk parameter table vector.
	mov	        word [bx + 2], ax	; Updates the segment part of the disk parameter table vector at SS:BX+2
;0x0000000000000068:  89 47 02          mov        word [bx + 2], ax
	mov         word [bx], Sec9		; Updates the offset part of the disk parameter table vector at SS:BX.
; DeepSeek: writes a 16-bit value (either the offset or value of Sec9) to the memory location pointed to by BX.
;0x000000000000006b:  C7 07 3E 7C       mov        word [bx], 0x7c3e				; MOV	[BX],offset SEC9
; We may now turn interrupts back on.  Before this, there is a small window
; when a reboot command may come in when the disk parameter table is garbage
	sti								; Re-enable interrupts
;0x000000000000006f:  FB                sti        
; Reset the disk system just in case any thing funny has happened.
	int        	0x13				; Reset the system using BIOS INT 0x13. Jumps to CKErr on failure.
;0x0000000000000070:  CD 13             int        0x13			;Reset the system
	jb         	CKErr				; Points to Non-System Message
;0x0000000000000072:  72 7C             jb         0xf0							; jc	CKErr			;AN000;
; The system is now prepared for us to begin reading.  First, determine
; logical sector numbers of the start of the directory and the start of the
; data area.
	xor     	ax, ax				; Clear AX. 
;0x0000000000000074:  33 C0             xor        ax, ax
	cmp        	word [cTotSec], ax	; Compare cTotSec with 0. 
;0x0000000000000076:  39 06 13 7C       cmp        word [0x7c13], ax				; cmp	cTotSec,ax		;AN000; 32 bit calculation?
	je         	Dir_Cont			; Jump to Dir_Cont if cTotSec = 0.
;0x000000000000007a:  74 08             je         0x84								; je	Dir_Cont		;AN000;
	mov        	cx, word [cTotSec]	; Load CX with cTotSec. 
;0x000000000000007c:  8B 0E 13 7C       mov        cx, word [0x7c13]				; mov	cx,cTotSec		;AN000;
	mov        	word [cTotSec_L], cx ; Save CX in cTotSec_L. 
;0x0000000000000080:  89 0E 20 7C       mov        word [0x7c20], cx				; mov	cTotSec_L,cx	;AN000; cTotSec_L,cTotSec_H will be used for calculation
Dir_Cont:
	mov        	al, byte [cFat]		; Load AL with the number of FAT copies. 
;0x0000000000000084:  A0 10 7C          mov        al, byte [0x7c10]				; MOV	AL,cFat 		;Determine sector dir starts on
	mul        	word [cSecFat]		; Multiply AL by the number of sectors per FAT (DX:AX = AL * cSecFat). 
;0x0000000000000087:  F7 26 16 7C       mul        word [0x7c16]					; MUL	cSecFat 		;DX;AX
	add        	ax, word [cSecHid_L] ; Add the lower word of hidden sectors to AX. 
;0x000000000000008b:  03 06 1C 7C       add        ax, word [0x7c1c]				; ADD	AX,cSecHid_L
	adc        	dx, word [cSecHid_H] ; Add the higher word of hidden sectors to DX with carry. 
;0x000000000000008f:  13 16 1E 7C       adc        dx, word [0x7c1e]				; adc	DX,cSecHid_H
	add        	ax, word [cSecRes]	; Add the reserved sectors to AX. 
;0x0000000000000093:  03 06 0E 7C       add        ax, word [0x7c0e]				; ADD	AX,cSecRes
	adc        	dx, 0				; Add carry to DX (if AX overflowed). 
;0x0000000000000097:  83 D2 00          adc        dx, 0
	mov        	word [DIR$_L], ax	; Save AX (lower word) in DIR$_L. 
;0x000000000000009a:  A3 50 7C          mov        word [0x7c50], ax				; MOV	[DIR$_L],AX		; DX;AX = cFat*cSecFat + cSecRes + cSecHid
	mov        	word [DIR$_H], dx	; Save DX (higher word) in DIR$_H. 
;0x000000000000009d:  89 16 52 7C       mov        word [0x7c52], dx				; mov	[DIR$_H],DX		;AN000;
	mov        	word [BIOS$_L], ax	; DeepSeek: writes the (!lower) 16-bit value in AX to the memory location specified by BIOS$_L
; mov [BIOS$_L], ax       ; DeepSeek Implicit word size - in nasm 'word' is only needed if not both are 16 bits, c.q. one is 'byte' for example
;0x00000000000000a1:  A3 49 7C          mov        word [0x7c49], ax				; MOV	[BIOS$_L],AX
; A 32-bit value is typically stored in a pair of registers (e.g., DX:AX in 16-bit mode, where DX holds the upper 16 bits and AX holds the lower 16 bits)
	mov        	word [BIOS$_H], dx	; DeepSeek: Upper 16 bits stored in BIOS$_H
;0x00000000000000a4:  89 16 4B 7C       mov        word [0x7c4b], dx				; mov	[BIOS$_H],DX		;AN000;
; Take into account size of directory (only know number of directory entries)
	mov			ax, cbDirEnt		; Load AX with the size of a directory entry (32 bytes). 
;0x00000000000000a8:  B8 20 00          mov        ax, 0x20						; MOV	AX,cbDirEnt		; bytes per directory entry
	mul        	word [DirNum]		; Multiply AX by the number of directory entries (DX:AX = AX * DirNum). 
;0x00000000000000ab:  F7 26 11 7C       mul        word [0x7c11]					; MUL	DirNum			; convert to bytes in directory
	mov        	bx, word [ByteSec]	; Load BX with the number of bytes per sector. 
;0x00000000000000af:  8B 1E 0B 7C       mov        bx, word [0x7c0b]				; MOV	BX,ByteSec		; add in sector size
	add        	ax, bx				; Add BX to AX (round up to the nearest sector). 
;0x00000000000000b3:  03 C3             add        ax, bx
	dec        	ax					; Decrement AX to ensure correct rounding up. 
;0x00000000000000b5:  48                dec        ax								; DEC	AX			; decrement so that we round up
	div        	bx					; Divide AX by BX (AX = sectors in directory).
;0x00000000000000b6:  F7 F3             div        bx								; DIV	BX			; convert to sector number
	add        	word [BIOS$_L], ax	; DeepSeek: Adds the value in AX to the 16-bit value stored at the memory location [BIOS$_L]
;0x00000000000000b8:  01 06 49 7C       add        word [0x7c49], ax				; ADD	[BIOS$_L],AX		; Start sector # of Data area
; The instruction adc word [BIOS$_H], 0 performs an add with carry operation. Here’s a detailed breakdown of its meaning and purpose:
; adc (Add with Carry): Adds the source operand (0 in this case) and the Carry Flag (CF) to the destination operand ([BIOS$_H]).
; word [BIOS$_H]: 		Specifies that the destination is a 16-bit memory location at the address given by BIOS$_H.
; 0:					The source operand is 0, so this instruction essentially adds the Carry Flag (CF) to [BIOS$_H].
; 	If CF = 1, this increments the value at [BIOS$_H]. If CF = 1, the destination is incremented by 1.
;	If CF = 0, the value at [BIOS$_H] remains unchanged.
;	The result is stored in the memory location [BIOS$_H]
; 
	adc        	word [BIOS$_H], 0	; adds the Carry Flag (CF) (!from previous calculation) to [BIOS$_H].
; adc word [BIOS$_H], 1: Adds 1 + CF to [BIOS$_H]; can be used but is uncommon because:
;	It combines a constant (1) with the carry (CF), which is rarely needed.
;	It’s less readable than separate add and adc instructions.
;	Multi-Precision Arithmetic with a Constant: 
;	If you’re performing a multi-word addition and need to add a constant (1) while also incorporating a carry from a lower-precision operation.
;0x00000000000000bc:  83 16 4B 7C 00    adc        word [0x7c4b], 0				; adc	[BIOS$_H],0		;AN000;
; We load in the first directory sector and examine it to make sure the the
; BIOS and DOS are the first two directory entries.  If they are not found,
; the user is prompted to insert a new disk.  The directory sector is loaded
; into 00500h
	mov        	bx, DirOff 
;0x00000000000000c1:  BB 00 05          mov        bx, 0x500					; MOV	BX,DirOff		; sector to go in at 00500h
	mov        	dx, word [DIR$_H]	; 
;0x00000000000000c4:  8B 16 52 7C       mov        dx, word [0x7c52]				; mov	dx,[DIR$_H]		;AN000;
	mov        	ax, word [DIR$_L]
;0x00000000000000c8:  A1 50 7C          mov        ax, word [0x7c50]				; MOV	AX,[DIR$_L]		; logical sector of directory
	call       	DODIV				; 
;0x00000000000000cb:  E8 87 00          call       0x155							; CALL	DODIV			; convert to sector, track, head
	jb         	CKErr				; Points to Non-System Message
;0x00000000000000ce:  72 20             jb         0xf0							; jc	CKErr			;AN000; Overflow? BPB must be wrong!!
	mov        	al, 1				; 
;0x00000000000000d0:  B0 01             mov        al, 1							; mov	al, 1			;AN000; disk read 1 sector
	call       DOCALL
;0x00000000000000d2:  E8 A1 00          call       0x176							; CALL	DOCALL			; do the disk read
	jb		   	CKErr				; Points to Non-System Message
;0x00000000000000d5:  72 19             jb         0xf0							; 
; Now we scan for the presence of IBMBIO  COM and IBMDOS  COM.	Check the
; first directory entry.
	mov        	di, bx				; 
;0x00000000000000d7:  8B FB             mov        di, bx
	mov        	cx, 0xB				; 
;0x00000000000000d9:  B9 0B 00          mov        cx, 0xb						; MOV	CX,11
	mov        	si, BIO
;0x00000000000000dc:  BE DB 7D          mov        si, 0x7ddb					; MOV	SI,OFFSET BIO		; point to "ibmbio  com"
	repe cmpsb ; Compare CX bytes from DS:SI with ES:DI
;	BAD: repe cmpsb 	byte [si], byte es:[di]	;
;0x00000000000000df:  F3 A6             repe cmpsb byte [si], byte es:[di]		; REPZ	CMPSB			; see if the same
	jb	       	CKErr				; Points to Non-System Message
;0x00000000000000e1:  75 0D             jne        0xf0								; JNZ	CKERR			; if not there advise the user
; Found the BIOS.  Check the second directory entry.
	lea        	di, [bx + 0x20]
;0x00000000000000e3:  8D 7F 20          lea        di, [bx + 0x20]
	mov        	si, DOS
;0x00000000000000e6:  BE E6 7D          mov        si, 0x7de6					; MOV	SI,OFFSET DOS		; point to "ibmdos  com"
	mov        	cx, 0xB				; 
;0x00000000000000e9:  B9 0B 00          mov        cx, 0xb						; MOV	CX,11
	repe cmpsb ; Compare CX bytes from DS:SI with ES:DI
;	BAD: repe cmpsb 	byte [si], byte es:[di]	;
;0x00000000000000ec:  F3 A6             repe cmpsb byte [si], byte es:[di]		; REPZ	CMPSB
	je         	DoLoad
;0x00000000000000ee:  74 18             je         0x108							; JZ	DoLoad
; There has been some recoverable error.  Display a message and wait for a
; keystroke.
	jb         	CKErr				; Points to Non-System Message
CKErr:
	MOV			si, SYSMSG	; point to no system message ; now at 0xf0
;0x00000000000000f0:  BE 93 7D          mov        si, 0x7d93						; same as 1 line before
ErrOut:
	CALL		WRITE			; and write on the screen ; WRITE is called at 0x147
;0x00000000000000f3:  E8 51 00          call       0x147							; CALL	WRITE			; and write on the screen
; The next code up to 'jb CKerr' clears AH, waits for keyboard input, restores the disk parameter table, reboots the system, and handles errors. 
	xor     	ah, ah				; Clear AH (high byte of AX). Clears all arithmetic flags (ZF=1, CF=0, etc.). Any value XORed with itself yields 0. Thus, AH is set to 0x00. 
;0x00000000000000f6:  32 E4             xor        ah, ah						; wait for response
	int        	0x16				; BIOS interrupt 0x16: Keyboard input. Waits for a keypress. 
;0x00000000000000f8:  CD 16             int        0x16							; INT	16H			; get character from keyboard
	pop 		si					; Pop the saved SI value from the stack. SI points to the disk parameter table. 
;0x00000000000000fa:  5E                pop        si							; POP	SI			; reset disk parameter table back to
	pop 		ds					; Pop the saved DS value from the stack. DS is the segment for the disk parameter table. 
;0x00000000000000fb:  1F                pop        ds							; POP	DS			; rom
	pop        	word [si]			; Pop the saved offset of the disk parameter table into [SI]. 
;0x00000000000000fc:  8F 04             pop        word [si]
	pop        	word [si + 2]		; Pop the saved segment of the disk parameter table into [SI + 2]. 
;0x00000000000000fe:  8F 44 02          pop        word [si + 2]
	int        	0x19				; BIOS interrupt 0x19: Reboot the system. Reloads the bootloader. 
; BIOS-interrupts like int 0x13 use CF for errors: 
;    CF = 1: Operatie failed (forinstance read/write error on disk). 
;    CF = 0: Operation succeeded
;0x0000000000000101:  CD 19             int        0x19							; INT	19h			; Continue in loop till good disk
Load_Failure:
	pop        	ax					; Pop a value into AX (adjusts the stack).
;0x0000000000000103:  58                pop        ax							; pop	ax			;adjust the stack
	pop        	ax					; Pop a value into AX (adjusts the stack).
;0x0000000000000103:  58                pop        ax							; pop	ax			;adjust the stack
	pop        	ax					; Pop a value into AX (adjusts the stack).
;0x0000000000000103:  58                pop        ax							; pop	ax			;adjust the stack
	pop        	ax					; Pop a value into AX (adjusts the stack).
;0x0000000000000104:  58                pop        ax
	pop        	ax					; Pop a value into AX (adjusts the stack).
;0x0000000000000103:  58                pop        ax							; pop	ax			;adjust the stack
	pop        	ax					; Pop a value into AX (adjusts the stack).
;0x0000000000000105:  58                pop        ax
	jb         	CKErr				; Jump to CKErr if the carry flag (CF) is set (conditional jump). Points to Non-System Message
;0x0000000000000106:  EB E8             jmp        0xf0							; jmp	short Ckerr		;display message and reboot.
;J.K. We don't have the following error message any more!!!
;J.K. Sysmsg is fine.  This will save space by eliminating DMSSG message.
;;RERROR: MOV	 SI,OFFSET DMSSG	 ; DISK ERROR MESSAGE
;;JMP	 ErrOut
;
; We now begin to load the BIOS in.  Compute the number of sectors needed.
; J.K. All we have to do is just read in sectors contiguously IBMLOADSIZE
; J.K. times.  We here assume that IBMLOAD module is contiguous.  Currently
; J.K. we estimate that IBMLOAD module will not be more than 3 sectors.
;
DoLoad:
	mov 		bx, BioOff			; Set BX = Offset of IBMBIO (IBMLOAD) to be loaded.
;0x0000000000000108:  BB 00 07          mov        bx, 0x700					; mov	BX,BioOff		;offset of ibmbio(IBMLOAD) to be loaded.
	mov        	cx, IBMLOADSIZE 	; offset of ibmbio(IBMLOAD) to be loaded.
;0x000000000000010b:  B9 03 00          mov        cx, 3								; mov	CX,IBMLOADSIZE		;# of sectors to read.
	mov        	ax, word [BIOS$_L]	; DeepSeek: Read from memory, the reverse operation of: mov word [BIOS$_L], ax
;0x000000000000010e:  A1 49 7C          mov        ax, word [0x7c49]				; mov	AX, [BIOS$_L]		;Sector number to read.
	mov        	dx, word [BIOS$_H]	; DeepSeek: reads a 16-bit value from [BIOS$_H] and stores it in DX (!Here the high bytes).
;  Segment Assumption: NASM assumes DS as the segment register for [BIOS$_H] unless overridden.
;0x0000000000000111:  8B 16 4B 7C       mov        dx, word [0x7c4b]				; mov	DX, [BIOS$_H]		;AN000;
Do_While:				;AN000;
	push       	ax					; Push AX (sector number, lower word) onto the stack.
;0x0000000000000115:  50                push       ax							; push	AX			;AN000;
	push       	dx					; Push DX (sector number, higher word) onto the stack.
;0x0000000000000116:  52                push       dx							; push	DX			;AN000;
	push       	cx					; Push CX (number of sectors) onto the stack.
;0x0000000000000117:  51                push       cx							; push	CX			;AN000;
	call		DODIV				; Call subroutine to calculate cylinder, head, and sector.
;0x0000000000000118:  E8 3A 00          call       0x155							; call	DODIV			;AN000; DX;AX = sector number.
	jb         	Load_Failure		; Jump to Load_Failure if carry flag (CF) is set (error).
;0x000000000000011b:  72 E6             jb         0x103							; jc	Load_Failure		;AN000; Adjust stack. Show error message
	mov        	al, 1				; Set AL = 1 (read 1 sector).
;0x000000000000011d:  B0 01             mov        al, 1							; mov	al, 1			;AN000; Read 1 sector at a time.
					;This is to handle a case of media
					;when the first sector of IBMLOAD is the
					;the last sector in a track.
	call       	DOCALL				; Call subroutine to read the sector from disk.
;0x000000000000011f:  E8 54 00          call       0x176							; call	DOCALL			;AN000; Read the sector.
	pop        	cx					; Restore CX (number of sectors) from the stack.
;0x0000000000000122:  59                pop        cx							; AN000;
	pop        	dx					; Restore DX (sector number, higher word) from the stack.
;0x0000000000000123:  5A                pop        dx							; AN000;
	pop        	ax					; Restore AX (sector number, lower word) from the stack.
;0x0000000000000124:  58                pop        ax							; AN000;
	jb         	CKErr				; Jump to CKErr if carry flag (CF) is set (read error). Points to Non-System Message
;0x0000000000000125:  72 C9             jb         0xf0							; jc	CkErr			;AN000; Read error?
	add        	ax, 1				; Increment AX (sector number, lower word) by 1.
;0x0000000000000127:  05 01 00          add        ax, 1							; add	AX,1			;AN000; Next sector number.
	adc        	dx, 0				; Add carry to DX (sector number, higher word) if AX overflowed.
;0x000000000000012a:  83 D2 00          adc        dx, 0							; adc	DX,0			;AN000;
	add        	bx, word [ByteSec]	; Add ByteSec (bytes per sector) to BX (buffer address).
;0x000000000000012d:  03 1E 0B 7C       add        bx, word [0x7c0b]				; add	BX,ByteSec		;AN000; adjust buffer address.
	loop       	Do_While			; Decrement CX and loop if CX ≠ 0 (read next sector).
;0x0000000000000131:  E2 E2             loop       0x115							; loop	Do_While		;AN000;
;
; IBMINIT requires the following input conditions:
;   DL = INT 13 drive number we booted from
;   CH = media byte
; J.K.I1. BX was the First data sector on disk (0-based)
; J.K.I1. IBMBIO init routine should check if the boot record is the
; J.K.I1. extended one by looking at the extended_boot_signature.
; J.K.I1. If it is, then should us AX;BX for the starting data sector number.
;
DISKOK:
	mov        	ch, byte [MEDIA]	; Load CH with the media descriptor byte from memory.
;0x0000000000000133:  8A 2E 15 7C       mov        ch, byte [0x7c15]				; MOV	CH,Media
	mov        	dl, byte [PhyDrv]	; Load DL with the physical drive number from memory.
;0x0000000000000137:  8A 16 24 7C       mov        dl, byte [0x7c24]				; MOV	DL,PhyDrv
	mov        	bx, word [BIOS$_L]	; Load lower 16 bits into BX
;0x000000000000013b:  8B 1E 49 7C       mov        bx, word [0x7c49]				; MOV	bx,[BIOS$_L]		;AN000; J.K.I1.Get bios sector in bx
	mov        	ax, word [BIOS$_H]	; Overwrite AX with higher 16 bits (AX now contains only BIOS$_R). 
; Result: Now AX = high word, BX = low word - Now AX:BX = 32-bit value (non-standard pairing): Call BIOS disk service (AX/BX used for parameters).
; 	AX is often used for arithmetic operations or system calls (e.g., BIOS interrupts).
; 	Why Start with BX? (Possible Reasons): 1. Preserving AX for a Specific Purpose; 2. Preparing for a 32-bit Operation; 3. Avoiding Register Clobbering; 4. Data Structure Alignment.
;0x000000000000013f:  A1 4B 7C          mov        ax, word [0x7c4b]				; mov	ax,[BIOS$_H]		;AN000; J.K.I1.
	jmp 		BIOSEG:0x0000 		; Far jump to BIOS entry point (BIOSEG = 0x70). !BioOff is 0x700 - can not be used here ;0x0000000000000142:  EA 00 00 70 00    ljmp       0x70:0							; JMP	FAR PTR BIOS		;CRANK UP THE DOS
WRITE:
; The code is a loop that prints characters from memory (DS:SI) using BIOS INT 0x10 teletype function. 
; It stops when a null terminator (\0) is encountered. 
	lodsb							; Load next character from DS:SI into AL. Increment SI. GET NEXT CHARACTER ; called now at 0x147
;0x0000000000000147:  AC                lodsb      al, byte [si]					; WRITE:	LODSB			;GET NEXT CHARACTER
	or         	al, al				; Check if AL (character) is zero (end of string).
;0x0000000000000148:  0A C0             or         al, al						; OR	AL,AL			;clear the high bit
	je         	ENDWR				; Jump to ENDWR if AL = 0 (end of string).
;0x000000000000014a:  74 29             je         0x175							; JZ	ENDWR			;ERROR MESSAGE UP, JUMP TO BASIC
	mov        	ah, 0xE				; Set AH = 0x0E (BIOS teletype function).
;0x000000000000014c:  B4 0E             mov        ah, 0xe						; MOV	AH,14			;WILL WRITE CHARACTER & ATTRIBUTE
	mov        	bx, 7				; Set BX = 7 (attribute: white on black). Sets the video attribute byte for BIOS INT 0x10 teletype output.
;0x000000000000014e:  BB 07 00          mov        bx, 7							; MOV	BX,7			;ATTRIBUTE
	int        	0x10				; Call BIOS teletype function to print the character in AL.
;0x0000000000000151:  CD 10             int        0x10							; INT	10H			;PRINT THE CHARACTER
	jmp        	WRITE				; Jump back to WRITE to process the next character.
;0x0000000000000153:  EB F2             jmp        0x147							; JMP	WRITE
;
; convert a logical sector into Track/sector/head.  AX has the logical
; sector number
; J.K. DX;AX has the sector number. Because of not enough space, we are
; going to use Simple 32 bit division here.
; Carry set if DX;AX is too big to handle.
;
DODIV:
	cmp        	dx, word [SECLIM]	; Compare DX (high word of sector number) with SECLIM (sectors per track). 
;0x0000000000000155:  3B 16 18 7C       cmp        dx, word [0x7c18]				; cmp	dx,SECLIM		;AN000; To prevent overflow!!!
	jae        	DivOverFlow			; Jump to DivOverFlow if DX ≥ SECLIM (overflow prevention). 
;0x0000000000000159:  73 19             jae        0x174							; jae	DivOverFlow		;AN000; Compare high word with the divisor.
	div        	word [SECLIM]		; Divide DX:AX by SECLIM (sectors per track). 
;0x000000000000015b:  F7 36 18 7C       div        word [0x7c18]					; DIV	SECLIM			;AX = Total tracks, DX = sector number
	inc        	dl					; Increment DL (sector number). 
;0x000000000000015f:  FE C2             inc        dl							; INC	DL			;Since we assume SecLim < 255 (a byte), DH =0.
					; Cursec is 1-based. DeepSeek: Many BIOS routines and disk formats (e.g., floppy disks) use 1-based sector numbering (!instead starting with 0).
	mov        	byte [CURSEC], dl	; Save DL (sector number) in CURSEC. 
;0x0000000000000161:  88 16 4F 7C       mov        byte [0x7c4f], dl				; MOV	CURSEC, DL		;save it
	xor     	dx, dx				; Clear DX. Clears all arithmetic flags (ZF=1, CF=0, etc.).
;0x0000000000000165:  33 D2             xor        dx, dx						; 
	div        	word [HDLIM]		; Divide AX (total tracks) by HDLIM (heads per cylinder). 
;0x0000000000000167:  F7 36 1A 7C       div        word [0x7c1a]					; DIV	HDLIM
	mov        	byte [CURHD], dl	; Save DL (head number) in CURHD. 
;0x000000000000016b:  88 16 25 7C       mov        byte [0x7c25], dl				; MOV	CURHD,DL		;Also, Hdlim < 255.
	mov        	word [CURTRK], ax	; Save AX (track number) in CURTRK. 
;0x000000000000016f:  A3 4D 7C          mov        word [0x7c4d], ax				; MOV	CURTRK,AX
	clc								; Clear carry flag (CF = 0). 
;0x0000000000000172:  F8                clc        								; clc				;AN000;
	ret								; Return from subroutine. 
;0x0000000000000173:  C3                ret        								; ret				;AN000;
DivOverFlow:						;AN000;
	stc								; Set carry flag (CF = 1). 
;0x0000000000000174:  F9                stc        								; stc				;AN000;
ENDWR:
	ret								; Return from subroutine. 
;0x0000000000000175:  C3                ret        								; 
; Issue one read request.  ES:BX have the transfer address, AL is the number
; of sectors.
;
DOCALL:	
; The DOCALL subroutine prepares and executes a BIOS disk read operation.  
; It combines track, sector, head, and drive information for the BIOS call.  
	mov			ah, ROM_DISKRD		; Set AH = 0x02 (BIOS disk read function). 
									; DOCALL: MOV	AH,ROM_DISKRD		;AC000;=2
;0x0000000000000176:  B4 02             mov        ah, 2						; MOV	AH,ROM_DISKRD		;AC000;=2 !SAME!
	mov        	dx, word [CURTRK]	; Load DX with the current track number. 
;0x0000000000000178:  8B 16 4D 7C       mov        dx, word [0x7c4d]				; MOV	DX,CURTRK
	mov        	cl, 6				; Set CL = 6 (shift count). 
;0x000000000000017c:  B1 06             mov        cl, 6							; MOV	CL,6
	shl        	dh, cl				; Shift DH (high byte of DX) left by 6 bits. 
;0x000000000000017e:  D2 E6             shl        dh, cl						; SHL	DH,CL
; or: Bitwise OR operation (sets bits to 1 if either operand has a 1 in that position); destination operand (8-bit high half of the DX register); The source operand, an 8-bit value read from memory at the address CURSEC.
; The source operand, an 8-bit value read from memory at the address CURSEC; byte specifies an 8-bit operation (required because [CURSEC] is a memory operand); Without byte, NASM would throw an error due to ambiguity.
; SF (Sign Flag): Set if the result’s MSB is 1; ZF (Zero Flag): Set if the result is 0; PF (Parity Flag): Set if the result has an even number of 1 bits; OF/CF (Overflow/Carry Flags): Cleared (always for or).
; Common Use Cases: Setting Specific Bits; Merging Data; Fast Zero Check.
	or         	dh, byte [CURSEC]	; Combine DH (track) with CURSEC (sector number). 
; DeepSeek: bitwise OR operation between the 8-bit value in DH (!high bytes of dx) and the 8-bit value stored at the memory location [CURSEC], storing the result back in DH.
; 	or dh, [CURSEC]: Invalid because DH alone doesn’t imply the size of the memory operand.
; The 8-bit registers (AH, AL, BH, BL, CH, CL, DH, DL) are part of the general-purpose registers (AX, BX, CX, DX).
;0x0000000000000180:  0A 36 4F 7C       or         dh, byte [0x7c4f]				; OR	DH,CURSEC
	mov        	cx, dx				; Move DX (cylinder/sector) into CX. 
;0x0000000000000184:  8B CA             mov        cx, dx						; MOV	CX,DX
	xchg       	cl, ch				; Swap CH (cylinder) and CL (sector). 
;0x0000000000000186:  86 E9             xchg       cl, ch						; XCHG	CH,CL
	mov        	dl, byte [PhyDrv]	; Load DL with the physical drive number. 
;0x0000000000000188:  8A 16 24 7C       mov        dl, byte [0x7c24]				; MOV	DL, PhyDrv
	mov        	dh, byte [CURHD]	; Load DH with the current head number. 
;0x000000000000018c:  8A 36 25 7C       mov        dh, byte [0x7c25]				; mov	dh, CURHD
	int        	0x13				; Call BIOS interrupt 0x13 (disk read).
;0x0000000000000190:  CD 13             int        0x13							; INT	13H
	ret								; Return from subroutine. 
;0x0000000000000192:  C3                ret        								; RET
;
; Data area for messages and filenames
%include "boot.cl1" 	;	include boot.cl1			;AN003;
;
%if IBMCOPYRIGHT 		;	IF IBMCOPYRIGHT
BIO db "IBMBIO  COM" 	; BIO	DB	"IBMBIO  COM"
DOS db "IBMDOS  COM" 	; DOS	DB	"IBMDOS  COM"
%else 					; 	ELSE
BIO db "IO      SYS" 	; BIO	DB	"IO      SYS"
DOS db "MSDOS   SYS" 	; DOS	DB	"MSDOS   SYS"
%endif 					;	ENDIF
;
; !Unused? ; Free	EQU (cbSec - 4) - ($-$start)		;AC000;
;;Free	 EQU (cbSec - 5) - ($-$start)	; !Old code, unused!
; !Unused? ; if Free LT 0
; !Unused? ;    %out FATAL PROBLEM:boot sector is too large
; !Unused? ; endif
;
; !Unused? ; org	ORIGIN + (cbSec - 2) ;	org	origin + (cbSec - 2)		;AN004; !defined: ORIGIN => Variable in NASM is case sensitive, by default NOT in MASM
;
    times 510 - ($ - $$) db 0   ; Pad remainder of boot sector with 0 ; From v027
;
;Warning!! Do not change the position of following unless
;Warning!! you change BOOTFORM.INC (in COMMON subdirectory) file.
;Format should set this EOT value for IBMBOOT.
;FEOT	 db	 12h			 ;AN000; set by FORMAT. AN004;Use SecLim in BPB instead.
; FORMAT and SYS count on CURHD,PHYDRV being right here
;J.K. CURHD has been deleted since it is not being used by anybody.
;CURHD	 DB	 ?			 ;AN001;Unitialized (J.K. Maybe don't need this).
;PHYDRV  db	 0			 ;AN000;moved into the header part.
; Boot sector signature
    db 0x55, 0xAA	; 	db	55h,0aah
;
; !Unused? ; CODE	ENDS	; !NONEED?
; !Unused? ; END			; !NONEED?
;
; !FOUND in Disassembly: WRITTEN Data area for messages and filenames
;0x0000000000000193:  0D 0A 4E          or         ax, 0x4e0a
;0x0000000000000196:  6F                outsw      dx, word ptr [si]
;0x0000000000000197:  6E                outsb      dx, byte ptr [si]
;0x0000000000000198:  2D 53 79          sub        ax, 0x7953
;0x000000000000019b:  73 74             jae        0x211
;0x000000000000019d:  65 6D             insw       word ptr es:[di], dx
;0x000000000000019f:  20 64 69          and        byte ptr [si + 0x69], ah
;0x00000000000001a2:  73 6B             jae        0x20f
;0x00000000000001a4:  20 6F 72          and        byte ptr [bx + 0x72], ch
;0x00000000000001a7:  20 64 69          and        byte ptr [si + 0x69], ah
;0x00000000000001aa:  73 6B             jae        0x217
;0x00000000000001ac:  20 65 72          and        byte ptr [di + 0x72], ah
;0x00000000000001af:  72 6F             jb         0x220
;0x00000000000001b1:  72 0D             jb         0x1c0
;0x00000000000001b3:  0A 52 65          or         dl, byte ptr [bp + si + 0x65]
;0x00000000000001b6:  70 6C             jo         0x224
;0x00000000000001b8:  61                popaw      
;0x00000000000001b9:  63 65 20          arpl       word ptr [di + 0x20], sp
;0x00000000000001bc:  61                popaw      
;0x00000000000001bd:  6E                outsb      dx, byte ptr [si]
;0x00000000000001be:  64 20 70 72       and        byte ptr fs:[bx + si + 0x72], dh
;0x00000000000001c2:  65 73 73          jae        0x238
;0x00000000000001c5:  20 61 6E          and        byte ptr [bx + di + 0x6e], ah
;0x00000000000001c8:  79 20             jns        0x1ea
;0x00000000000001ca:  6B 65 79 20       imul       sp, word ptr [di + 0x79], 0x20
;0x00000000000001ce:  77 68             ja         0x238
;0x00000000000001d0:  65 6E             outsb      dx, byte ptr gs:[si]
;0x00000000000001d2:  20 72 65          and        byte ptr [bp + si + 0x65], dh
;0x00000000000001d5:  61                popaw      
;0x00000000000001d6:  64 79 0D          jns        0x1e6							; MSDOS   SYS ?? seems shifted up
;0x00000000000001d9:  0A 00             or         al, byte ptr [bx + si]
;0x00000000000001db:  49                dec        cx
;0x00000000000001dc:  4F                dec        di
;0x00000000000001dd:  20 20             and        byte ptr [bx + si], ah
;0x00000000000001df:  20 20             and        byte ptr [bx + si], ah
;0x00000000000001e1:  20 20             and        byte ptr [bx + si], ah
;0x00000000000001e3:  53                push       bx
;0x00000000000001e4:  59                pop        cx
;0x00000000000001e5:  53                push       bx
;0x00000000000001e6:  4D                dec        bp
;0x00000000000001e7:  53                push       bx
;0x00000000000001e8:  44                inc        sp
;0x00000000000001e9:  4F                dec        di
;0x00000000000001ea:  53                push       bx
;0x00000000000001eb:  20 20             and        byte ptr [bx + si], ah
;0x00000000000001ed:  20 53 59          and        byte ptr [bp + di + 0x59], dl
;0x00000000000001f0:  53                push       bx
;0x00000000000001f1:  00 00             add        byte ptr [bx + si], al
;0x00000000000001f3:  00 00             add        byte ptr [bx + si], al
;0x00000000000001f5:  00 00             add        byte ptr [bx + si], al
;0x00000000000001f7:  00 00             add        byte ptr [bx + si], al
;0x00000000000001f9:  00 00             add        byte ptr [bx + si], al
;0x00000000000001fb:  00 00             add        byte ptr [bx + si], al
;0x00000000000001fd:  00 55 AA          add        byte ptr [di - 0x56], dl
