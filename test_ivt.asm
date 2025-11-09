; Simple test bootloader to exercise IVT access
[ORG 0x7C00]

start:
    ; Read from IVT (vector 0x08 - clock interrupt, at address 0x0020)
    mov ax, word [0x0020]
    
    ; Read segment part (at 0x0022)
    mov bx, word [0x0022]
    
    ; Write to IVT (vector 0x20, at address 0x0080)
    mov word [0x0080], ax
    mov word [0x0082], bx
    
    ; Read it back
    mov cx, word [0x0080]
    
    ; Halt
    hlt
    jmp start

; Pad to 512 bytes with zeros
TIMES 512 - ($ - $$) db 0

; Add boot signature
DW 0xAA55
