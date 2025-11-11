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

static void print_u32(uint32_t x)
{
    printhex(x >> 24);
    printhex(x >> 16);
    printhex(x >> 8);
    printhex(x);
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

__attribute__ ((noinline))
static void dump_far(uint8_t __far* buf, uint16_t size)
{
    for (uint16_t i = 0; i < size; i++)
    {
        printhex(buf[i]);
    }
    puts("\r\n");
}

typedef uint8_t __far* farptr_t;

__attribute__((noreturn, section(".text.start"))) void _start()
{
    puts("IVT:\r\n");
    dump((uint8_t*)0x0000, 0x400);
    puts("BDA:\r\n");
    dump((uint8_t*)0x400, 0x100);
    farptr_t* ivt = (farptr_t*)0x0000;
    puts("EGA characters:\r\n");
    dump_far(ivt[0x1F], 0x16); // dump INT 0x1E vector table
    while(1);
}
