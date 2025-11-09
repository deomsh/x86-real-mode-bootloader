; Test bootloader to exercise stub-based interrupt handling with IVT chaining
[ORG 0x7C00]
[BITS 16]

start:
    ; Initialize
    xor ax, ax
    mov ds, ax
    mov es, ax

    ; === TEST 1: Direct BIOS call ===
    ; Call INT 10h directly (should hit BIOS stub at F000:0040)
    mov ah, 0x0E        ; Teletype output
    mov al, '1'         ; Character '1'
    mov bh, 0           ; Page 0
    int 0x10            ; This should go: bootloader -> IVT -> F000:0040 stub -> Python handler

    ; Print newline
    mov al, 13
    int 0x10
    mov al, 10
    int 0x10

    ; === TEST 2: Hook INT 10h and chain to original ===
    ; Save original INT 10h vector as far pointer
    mov ax, word [0x0040]    ; Read offset of INT 10h
    mov word [old_int10_vector], ax
    mov ax, word [0x0042]    ; Read segment of INT 10h
    mov word [old_int10_vector+2], ax

    ; Install our custom handler
    mov word [0x0040], custom_int10  ; New offset
    mov word [0x0042], 0x0000        ; New segment (CS=0)

    ; Now call INT 10h - should go to our handler first
    ; '2' -> level 1 changes to '1' -> prints '1'
    mov ah, 0x0E
    mov al, '2'
    int 0x10            ; This should go: bootloader -> IVT -> our handler -> tail jump -> stub -> Python

    ; Print newline
    mov al, 13
    int 0x10
    mov al, 10
    int 0x10

    ; === TEST 3: Multiple chaining levels ===
    ; Save current INT 10h vector (which is our custom handler)
    mov ax, word [0x0040]
    mov word [old_int10_vector_2], ax
    mov ax, word [0x0042]
    mov word [old_int10_vector_2+2], ax

    ; Install second-level handler
    mov word [0x0040], custom_int10_level2
    mov word [0x0042], 0x0000

    ; Call INT 10h - should go through both handlers
    ; '3' -> level 2 changes to '2' -> level 1 changes to '1' -> prints '1'
    mov ah, 0x0E
    mov al, '3'
    int 0x10

    ; Print success message
    mov al, 13
    int 0x10
    mov al, 10
    int 0x10
    mov al, 'O'
    int 0x10
    mov al, 'K'
    int 0x10
    mov al, '!'
    int 0x10

    ; Halt
    hlt
    jmp $

; === Custom INT 10h handler (level 1) ===
custom_int10:
    ; This handler modifies AL before chaining
    cmp ah, 0x0E        ; Only for teletype output
    jne .chain

    ; Change '2' to '1', pass everything else through
    cmp al, '2'
    jne .chain
    mov al, '1'

.chain:
    ; Tail call to original BIOS handler
    ; Interrupt frame is already on stack (pushed by emulator hook)
    ; BIOS will IRET directly back to original caller
    jmp far [old_int10_vector]

; === Custom INT 10h handler (level 2) ===
custom_int10_level2:
    ; This handler changes '3' to '2'
    cmp ah, 0x0E
    jne .chain

    cmp al, '3'
    jne .chain
    mov al, '2'

.chain:
    ; Tail call to level 1 handler
    jmp far [old_int10_vector_2]

; === Data section ===
old_int10_vector:    dd 0  ; offset:segment (4 bytes)
old_int10_vector_2:  dd 0  ; offset:segment (4 bytes)

; Pad to 512 bytes with zeros
TIMES 510 - ($ - $$) db 0

; Add boot signature
DW 0xAA55
