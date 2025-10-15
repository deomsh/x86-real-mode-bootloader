org 0x0700 ; IO.SYS example

SECTION .text
  bits 16      ; Specify 16-bit mode

start:
  ; Set AH to 0x0E (teletype output function)
  mov ah, 0x0E

  ; Set AL to the character to print ('@')
  mov al, '@'

  ; Set BL to the color attribute (optional, default is usually 0x07 - light gray on black)
  mov bl, 0x07

  ; Call the BIOS interrupt 0x10
  int 0x10

  ; Halt the program (infinite loop to prevent it from running off into memory)
halt:
  jmp halt


; No data section is needed for this simple example

;  SECTION .data  ; Not needed
;  SECTION .bss   ; Not needed
