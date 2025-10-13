SECTIONS {
    . = 0x0700;
    
    .text : {
        *(.text.start);
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

    . = ASSERT(. <= 0x0d00, "Dummy io.sys cannot exceed 3 sectors");
};
