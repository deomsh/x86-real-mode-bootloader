SECTIONS {
    . = 0x7c00;

    .text : {
        *(.text*);
    }
    .data : {
        *(.rodata*);
        *(.data*);
    }
    .bss ALIGN(4) (NOLOAD): {
        _bss_start = .;
        *(.bss*);
        *(COMMON);
    }
    _bss_size = SIZEOF(.bss);

    . = ASSERT(. <= 0x7dfe, "Boot sector code+data exceeds 510 bytes!");
    .bootsig 0x7dfe : { SHORT(0xaa55); }
};
