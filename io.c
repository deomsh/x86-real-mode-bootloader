#include <stdint.h>

static void putchar(char x)
{
    __asm__ volatile("int $0x0010"
                     :
                     : "a"(0x0e00 | x), "b"(0x0000)
                     : "cc");
}

static void puts(char *s)
{
    for (; *s; ++s)
        putchar(*s);
}

static char hexch(uint8_t l)
{
    return l + (l < 10 ? 48 : 55);
}

static void printhex(uint8_t x)
{
    putchar(hexch(x >> 4));
    putchar(hexch(x & 0xF));
}

__attribute__ ((noinline))
static void dump(uint8_t *buf, uint16_t size)
{
    for (uint16_t i = 0; i < size; i++)
    {
        printhex(buf[i]);
    }
    puts("\r\n");
}

__attribute__((noreturn, section(".text.start"))) void _start()
{
    puts("Hello from IO.SYS!\r\n");
    dump((uint8_t*)0x0700, 512);
    while(1);
}
