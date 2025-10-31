; This is the NASM conversion of the provided MSBOOT.ASM source code [1].

bits 16

;	Page 60,132 ;	    SCCSID = @(#)msboot.asm	    1.1 85/05/13
; TITLE BOOT	SECTOR 1 OF TRACK 0 - BOOT LOADER

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
;REVISION HISTORY:
;AN000 - New for DOS Version 4.00 - J.K.
;AC000 - Changed for DOS Version 4.00 - J.K.
;AN00x - PTM number for DOS Version 4.00 - J.K.
;==============================================================================
;AN001; d52 Make the fixed positioned variable "CURHD" to be local.  7/6/87 J.K.
;AN002; d48 Change head settle at boot time.			     7/7/87 J.K.
;AN003; P1820 New message SKL file				   10/20/87 J.K.
;AN004; D304 New structrue of Boot record for OS2.		   11/09/87 J.K.
;==============================================================================

ORIGIN	    equ 7C00H			; Origin of bootstrap LOADER
BIOSEG	    equ 70H			; destingation segment of BIOS
BioOff	    equ 700H			; offset of bios
cbSec	    equ 512
cbDirEnt    equ 32
DirOff	    equ 500h
IBMLOADSIZE equ 3			;J.K. Size of IBMLOAD module in sectors
ROM_DISKRD  equ 2
%include "version.inc"

;
; Define the destination segment of the BIOS, including the initialization
; label
;

;	 ORG	 DirOff + 1Ch
;BiosFS  LABEL	 WORD

	org	ORIGIN

DSKADR	=	1EH*4			;POINTER TO DRIVE PARAMETERS

$START:
	jmp	short START
;----------------------------------------------------------
;
;	THE FOLLOWING DATA CONFIGURES THE BOOT PROGRAM
;	FOR ANY TYPE OF DRIVE OR HARDFILE
;
;J.K. Extened_BPB

; Define 'ibmcopyright' to choose the "IBM" string, otherwise it defaults to "MSDOS"
%define ibmcopyright 1

%ifdef ibmcopyright
	  db	  "IBM  "
%else
	  db	  "MSDOS"
%endif
	  db	  "4.0"                 ;AN005;
ByteSec   dw	  cbSec 		; SIZE OF A PHYSICAL SECTOR
	  db	  8			; SECTORS PER ALLOCATION UNIT
cSecRes   dw	  1			; NUMBER OF RESERVED SECTORS
cFat	  db	  2			; NUMBER OF FATS
DirNum	  dw	  512			; NUMBER OF DIREC ENTRIES
cTotSec   dw	  4*17*305-1		; NUMBER OF SECTORS - NUMBER OF HIDDEN SECTORS
					;  (0 when 32 bit sector number)
MEDIA	  db	  0F8H			; MEDIA BYTE
cSecFat   dw	  8			; NUMBER OF FAT SECTORS
SECLIM	  dw	  17			; SECTORS PER TRACK
HDLIM	  dw	  4			; NUMBER OF SURFACES
Ext_cSecHid:
cSecHid_L dw	  1			;AN000; NUMBER OF HIDDEN SECTORS
cSecHid_H dw	  0			;AN000; high order word of Hiden Sectors
Ext_cTotSec:
ctotsec_L dw	  0			;AN000; 32 bit version of NUMBER OF SECTORS
ctotsec_H dw	  0			;AN000; (when 16 bit version is zero)
;
Phydrv	  db	 80h			;AN004;
Curhd	  db	  0h			;AN004; Current Head
Ext_Boot_Sig	db    41		;AN000;
Boot_Serial	dd    0 		;AN000;
Boot_Vol_Label	db    'NO NAME    '     ;AN000;
Boot_System_id	db    'FAT12   '        ;AN000;

;J.K. Danger!!! If not 32 bit sector number calculation, FORMAT should
;set the value of cSecHid_h and Ext_cTotSec to 0 !!!
;

UDATA:
Sec9	  equ	UDATA+0 	    ;11 byte diskette parm. table
BIOS$_L   equ	word ptr UDATA+11
BIOS$_H   equ	word ptr UDATA+13	;AN000;
CURTRK	  equ	word ptr UDATA+15
CURSEC	  equ	byte ptr UDATA+17
DIR$_L	  equ	word ptr UDATA+18
Dir$_H	  equ	word ptr UDATA+20	;AN000;
START:

;
; First thing is to reset the stack to a better and more known place.  The ROM
; may change, but we'd like to get the stack in the correct place.
;
	cli				;Stop interrupts till stack ok
	xor	ax,ax
	mov	ss,ax			;Work in stack just below this routine
	mov	sp,ORIGIN
	push	ss
	pop	es
;
; We copy the disk parameter table into a local area.  We scan the table above
; for non-zero parameters.  Any we see get changed to their non-zero values.
;
;J.K. We copy the disk parameter table into a local area (overlayed into the
;code), and set the head settle time to 1, and End of Track to SECLIM given
;by FORMAT.

	mov	bx,DSKADR
	lds	si,dword [ss:bx]	; get address of disk table
	push	ds			; save original vector for possible
	push	si			; restore
	push	ss
	push	bx
	mov	di, Sec9
	mov	cx,11
	cld
%if	$ <= BIOS$_L
	%error "Don't destroy unexcuted code yet!!!"
%endif
	rep	movsb			;AN000;
	push	es			;AN000;
	pop	ds			;AN000; DS = ES = code = 0.
;	 mov	 byte [di-2], 1	 ;AN000; Head settle time
;J.K. Change the head settle to 15 ms will slow the boot time quite a bit!!!
	mov	byte [di-2], 0fh	;AN002; Head settle time
	mov	cx, [SECLIM]		;AN004;
	mov	byte [di-7], cl	;AN000; End of Track
;
; Place in new disk parameter table vector.
;
	mov	[ss:bx+2],ax
	mov	[ss:bx],Sec9
;
; We may now turn interrupts back on.  Before this, there is a small window
; when a reboot command may come in when the disk parameter table is garbage
;
	sti				;Interrupts OK now
;
; Reset the disk system just in case any thing funny has happened.
;
	int	13H			;Reset the system
;	 JC	 RERROR
	jc	CKErr			;AN000;
;
; The system is now prepared for us to begin reading.  First, determine
; logical sector numbers of the start of the directory and the start of the
; data area.

	xor	ax,ax			;AN000;
	cmp	word [cTotSec],ax		;AN000; 32 bit calculation?
	je	Dir_Cont		;AN000;
	mov	cx,[cTotSec]		;AN000;
	mov	[ctotsec_L],cx		;AN000; cTotSec_L,cTotSec_H will be used for calculation
Dir_Cont:				;AN000;
	mov	al,[cFat] 		;Determine sector dir starts on
	mul	word [cSecFat] 		;DX;AX
	add	ax,[cSecHid_L]
	adc	dx,[cSecHid_H]		;AN000;
	add	ax,[cSecRes]
	adc	dx,0
	mov	[DIR$_L],ax		; DX;AX = cFat*cSecFat + cSecRes + cSecHid
	mov	[DIR$_H],dx		;AN000;
	mov	[BIOS$_L],ax
	mov	[BIOS$_H],dx		;AN000;
;
; Take into account size of directory (only know number of directory entries)
;
	mov	ax,[cbDirEnt]		; bytes per directory entry
	mul	word [DirNum]			; convert to bytes in directory
	mov	bx,[ByteSec]		; add in sector size
	add	ax,bx
	dec	ax			; decrement so that we round up
	div	bx			; convert to sector number
	add	[BIOS$_L],ax		; Start sector # of Data area
	adc	word [BIOS$_H],0		;AN000;

;
; We load in the first directory sector and examine it to make sure the the
; BIOS and DOS are the first two directory entries.  If they are not found,
; the user is prompted to insert a new disk.  The directory sector is loaded
; into 00500h
;
	mov	bx,DirOff		; sector to go in at 00500h
	mov	dx,[DIR$_H]		;AN000;
	mov	ax,[DIR$_L]		; logical sector of directory
	call	DODIV			; convert to sector, track, head
	jc	CKErr			;AN000; Overflow? BPB must be wrong!!
;	 MOV	 AX,0201H		 ; disk read 1 sector
	mov	al, 1			;AN000; disk read 1 sector
	call	DOCALL			; do the disk read
	jb	CKERR			; if errors try to recover
;
; Now we scan for the presence of IBMBIO  COM and IBMDOS  COM.	Check the
; first directory entry.
;
	mov	di,bx
	mov	cx,11
	mov	si,BIO		; point to "ibmbio  com"
	repe	cmpsb			; see if the same
	jnz	CKERR			; if not there advise the user
;
; Found the BIOS.  Check the second directory entry.
;
	lea	di,[bx+20h]
	mov	si,DOS		; point to "ibmdos  com"
	mov	cx,11
	repe	cmpsb
	jz	DoLoad

;
; There has been some recoverable error.  Display a message and wait for a
; keystroke.
;
CKERR:	mov	si,SYSMSG	; point to no system message
ErrOut: call	WRITE			; and write on the screen
	xor	ah,ah			; wait for response
	int	16H			; get character from keyboard
	pop	si			; reset disk parameter table back to
	pop	ds			; rom
	pop	word [ss:si]
	pop	word [ss:si+2]
	int	19h			; Continue in loop till good disk

Load_Failure:
	pop	ax			;adjust the stack
	pop	ax
	pop	ax
	jmp	short Ckerr		;display message and reboot.

;J.K. We don't have the following error message any more!!!
;J.K. Sysmsg is fine.  This will save space by eliminating DMSSG message.
;RERROR: MOV	 SI,OFFSET DMSSG	 ; DISK ERROR MESSAGE
;	 JMP	 ErrOut

;
; We now begin to load the BIOS in.  Compute the number of sectors needed.
; J.K. All we have to do is just read in sectors contiguously IBMLOADSIZE
; J.K. times.  We here assume that IBMLOAD module is contiguous.  Currently
; J.K. we estimate that IBMLOAD module will not be more than 3 sectors.

DoLoad:
	mov	bx,BioOff		;offset of ibmbio(IBMLOAD) to be loaded.
	mov	cx,IBMLOADSIZE		;# of sectors to read.
	mov	ax, [BIOS$_L]		;Sector number to read.
	mov	dx, [BIOS$_H]		;AN000;
Do_While:				;AN000;
	push	ax			;AN000;
	push	dx			;AN000;
	push	cx			;AN000;
	call	DODIV			;AN000; DX;AX = sector number.
	jc	Load_Failure		;AN000; Adjust stack. Show error message
	mov	al, 1			;AN000; Read 1 sector at a time.
					;This is to handle a case of media
					;when the first sector of IBMLOAD is the
					;the last sector in a track.
	call	DOCALL			;AN000; Read the sector.
	pop	cx			;AN000;
	pop	dx			;AN000;
	pop	ax			;AN000;
	jc	CkErr			;AN000; Read error?
	add	ax,1			;AN000; Next sector number.
	adc	dx,0			;AN000;
	add	bx,[ByteSec]		;AN000; adjust buffer address.
	loop	Do_While		;AN000;

; (Code from older revisions, now replaced by the DoLoad loop above)
;	 MOV	 AX,BiosFS		 ; get file size
;	 XOR	 DX,DX			 ; presume < 64K
;	 DIV	 ByteSec		 ; convert to sectors
;	 INC	 AL			 ; reading in one more can't hurt
;	 MOV	 COUNT,AL		 ; Store running count
;	 MOV	 AX,BIOS$		 ; get logical sector of beginning of BIOS
;	 MOV	 BIOSAV,AX		 ; store away for real bios later
;	 MOV	 BX,BioOff		 ; Load address from BIOSSEG
; ...

; IBMINIT requires the following input conditions:
;
;   DL = INT 13 drive number we booted from
;   CH = media byte
;J.K.I1. BX was the First data sector on disk (0-based)
;J.K.I1. IBMBIO init routine should check if the boot record is the
;J.K.I1. extended one by looking at the extended_boot_signature.
;J.K.I1. If it is, then should us AX;BX for the starting data sector number.

DISKOK:
	mov	ch,[Media]
	mov	dl,[PhyDrv]
	mov	bx,[BIOS$_L]		;AN000; J.K.I1.Get bios sector in bx
	mov	ax,[BIOS$_H]		;AN000; J.K.I1.
	jmp	BIOSEG:0		;CRANK UP THE DOS

WRITE:	lodsb				;GET NEXT CHARACTER
	or	al,al			;clear the high bit
	jz	ENDWR			;ERROR MESSAGE UP, JUMP TO BASIC
	mov	ah,14			;WILL WRITE CHARACTER & ATTRIBUTE
	mov	bx,7			;ATTRIBUTE
	int	10H			;PRINT THE CHARACTER
	jmp	WRITE

; convert a logical sector into Track/sector/head.  AX has the logical
; sector number
; J.K. DX;AX has the sector number. Because of not enough space, we are
; going to use Simple 32 bit division here.
; Carry set if DX;AX is too big to handle.
;

DODIV:
	cmp	dx,[Seclim]		;AN000; To prevent overflow!!!
	jae	DivOverFlow		;AN000; Compare high word with the divisor.
	div	word [SECLIM]			;AX = Total tracks, DX = sector number
	inc	dl			;Since we assume SecLim < 255 (a byte), DH =0.
					;Cursec is 1-based.
	mov	[CURSEC], dl		;save it
	xor	dx,dx
	div	word [HDLIM]
	mov	[CURHD],dl		;Also, Hdlim < 255.
	mov	[CURTRK],ax
	clc				;AN000;
	ret				;AN000;
DivOverFlow:				;AN000;
	stc				;AN000;
ENDWR:
	ret

;
;J.K.We don't have space for the following full 32 bit division.
; convert a logical sector into Track/sector/head.  AX has the logical
; sector number
; J.K. DX;AX has the sector number.
;DODIV:
;	push	ax
;	mov	ax,dx
;	 xor	 dx,dx
;	 div	 SecLim
;	 mov	 Temp_H,ax
;	 pop	 ax
;	 div	 SecLim 		 ;J.K.Temp_H;AX = total tracks, DX=sector
;	 INC	 DL			 ;Since we assume SecLim < 255 (a byte), DH =0.
;					 ;Cursec is 1-based.
;	 MOV	 CURSEC, DL		 ;save it
;	 push	 ax
;	 mov	 ax,Temp_H
;	 XOR	 DX,DX
;	 DIV	 HDLIM
;	 mov	 Temp_H,ax
;	 pop	 ax
;	 div	 HdLim			 ;J.K.Temp_H;AX=total cyliners,DX=head
;	 MOV	 CURHD,DL		 ;Also, Hdlim < 255.
;	 cmp	 Temp_H,0
;	 ja	 TooBigToHandle
;	 cmp	 ax, 1024
;	 ja	 TooBigToHandle
;	 MOV	 CURTRK,AX
;ENDWR:  RET
;TooBigToHandle:
;	 stc
;	 ret

;
; Issue one read request.  ES:BX have the transfer address, AL is the number
; of sectors.
;
DOCALL: mov	ah,ROM_DISKRD		;AC000;=2
	mov	dx,[CURTRK]
	mov	cl,6
	shl	dh,cl
	or	dh,[CURSEC]
	mov	cx,dx
	xchg	ch,cl
	mov	dl, [PHYDRV]
	mov	dh, [curhd]
	int	13H
	ret

;	 include ibmbtmes.inc
	%include "boot.cl1"			;AN003;


%ifdef IBMCOPYRIGHT
BIO	db	"IBMBIO  COM"
DOS	db	"IBMDOS  COM"
%else
BIO	db	"IO      SYS"
DOS	db	"MSDOS   SYS"
%endif

Free	equ (cbSec - 4) - ($ - $START)		;AC000;
;Free	 equ (cbSec - 5) - ($ - $START)
%if Free < 0
    %error "FATAL PROBLEM:boot sector is too large"
%endif

	org	ORIGIN + (cbSec - 2)		;AN004;
;	 org	 origin + (cbSec - 5)

;Warning!! Do not change the position of following unless
;Warning!! you change BOOTFORM.INC (in COMMON subdirectory) file.
;Format should set this EOT value for IBMBOOT.
;FEOT	 db	 12h			 ;AN000; set by FORMAT. AN004;Use SecLim in BPB instead.
; FORMAT and SYS count on CURHD,PHYDRV being right here
;J.K. CURHD has been deleted since it is not being used by anybody.
;CURHD	 DB	 ?			 ;AN001;Unitialized (J.K. Maybe don't need this).
;PHYDRV  db	 0			 ;AN000;moved into the header part.
; Boot sector signature
	db	55h,0aah
