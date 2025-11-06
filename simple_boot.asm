; Simple x86 real mode bootloader for testing the emulator
; This boots at 0x7C00 and performs basic operations

BITS 16
ORG 0x7C00

start:
    ; Disable interrupts
    cli

    ; Set up segments
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, 0x7C00

    ; Enable interrupts
    sti

    ; Set direction flag
    cld

    ; Write a test value to memory
    mov ax, 0x1234
    mov [0x0500], ax

    ; Read it back
    mov bx, [0x0500]

    ; Do some arithmetic
    add ax, bx
    mov cx, ax

    ; Test loop
    mov cx, 5
loop_start:
    dec cx
    jnz loop_start

    ; Print 'H' using BIOS interrupt
    mov ah, 0x0E
    mov al, 'H'
    mov bh, 0
    int 0x10

    ; Halt
    hlt
    jmp halt_loop

halt_loop:
    hlt
    jmp halt_loop

; Fill remaining space and add boot signature
times 510-($-$$) db 0
dw 0xAA55
