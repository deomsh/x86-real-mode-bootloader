#include <stdint.h>
#include <stdbool.h>

__asm__(R"(
// Jump to start
.byte 0xE9
.word (_start - . - 2)
// Space for the FAT header
.space 59
)");

uint8_t drive; // Drive number from DL on boot

// References:
// - https://stackoverflow.com/a/33975465/1806760
// - https://stackoverflow.com/a/32705076/1806760
__attribute__((noreturn)) void _start()
{
    __asm__ volatile(R"(
.intel_syntax noprefix
// Set up segments with interrupts disabled
cli
xor ax, ax
mov ds, ax
mov es, ax
mov ss, ax
mov sp, 0x7c00
sti

// Set direction flag to be in positive direction
cld

// Copy the drive number in the global variable
mov byte ptr [drive], dl

// Jump to boot function
jmp boot

.att_syntax
    )" ::: "memory");
    __builtin_unreachable();
}

static void putchar(uint8_t x)
{
    __asm__ volatile("int $0x0010"
                     :
                     : "a"(0x0e00 | x), "b"(0x0000)
                     : "cc");
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

static uint8_t read_disk_information()
{
    // INT 0x13 AH 0x08 read disk information
    // TODO: update documentation
    register uint8_t sectors;
    __asm__ volatile(
        "int $0x13\n"
        : "=c"(sectors)
        : "a"(0x0800),
          "d"(drive)
        : "bx");
    return sectors;
}

static void puts(char *s)
{
    for (; *s; ++s)
        putchar(*s);
    putchar('\r');
    putchar('\n');
}

typedef struct
{
    uint8_t jmp_boot[3];         // 0x00: jmp boot
    char oem_name[8];            // 0x03: OEM name
    uint16_t bytes_per_sector;   // 0x0B: Bytes per sector
    uint8_t sectors_per_cluster; // 0x0D: Sectors per cluster
    uint16_t reserved_sectors;   // 0x0E: Reserved sectors
    uint8_t num_fats;            // 0x10: Number of FATs
    uint16_t root_entries;       // 0x11: Root directory entries
    uint16_t total_sectors_16;   // 0x13: Total sectors (small)
    uint8_t media_descriptor;    // 0x15: Media descriptor
    uint16_t sectors_per_fat;    // 0x16: Sectors per FAT
    uint16_t sectors_per_track;  // 0x18: Sectors per track
    uint16_t num_heads;          // 0x1A: Number of heads
    uint32_t hidden_sectors;     // 0x1C: Hidden sectors
    uint32_t total_sectors_32;   // 0x20: Total sectors (large)
    uint8_t drive_number;        // 0x24: Drive number
    uint8_t reserved;            // 0x25: Reserved
    uint8_t boot_signature;      // 0x26: Extended boot signature (0x29)
    uint32_t volume_serial;      // 0x27: Volume serial number
    char volume_label[11];       // 0x2B: Volume label
    char filesystem_type[8];     // 0x36: Filesystem type
} __attribute__((packed)) fat_boot_sector_t;

static void print_u32(uint32_t x)
{
    printhex(x >> 24);
    printhex(x >> 16);
    printhex(x >> 8);
    printhex(x);
}

typedef struct
{
    uint8_t size;     // Size of packet (16 bytes)
    uint8_t reserved; // Always 0
    uint16_t sectors; // Number of sectors to read
    uint16_t offset;  // Buffer offset
    uint16_t segment; // Buffer segment
    uint64_t lba;     // Starting LBA
} __attribute__((packed)) disk_address_packet_t;

// NOTE: we are assuming 512-byte sector sizes here (TODO: perform CHS conversion instead)
static void read_sectors_lba(uint32_t lba, uint16_t sectors, void *buffer)
{
    disk_address_packet_t packet = {
        .size = 16,
        .reserved = 0,
        .sectors = sectors,
        .offset = (uint16_t)((uint32_t)buffer & 0xF),
        .segment = (uint16_t)((uint32_t)buffer >> 4),
        .lba = lba,
    };

    __asm__ volatile(
        "mov $0x42, %%ah\n" // Function: Extended Read
        "mov %0, %%dl\n"    // Drive number
        "mov %1, %%si\n"    // DS:SI = address packet
        "int $0x13\n"
        :
        : "r"(drive), "r"(&packet)
        : "ax", "dx", "si", "cc", "memory");
}

typedef struct
{
  char     filename[8];              // 0x00: Filename (space-padded)
  char     extension[3];             // 0x08: Extension (space-padded)
  uint8_t  attributes;               // 0x0B: File attributes
  uint8_t  reserved;                 // 0x0C: Reserved for Windows NT (lowercase flags)
  uint8_t  creation_time_tenths;     // 0x0D: Creation time in tenths of a second (0-199)
  uint16_t creation_time;            // 0x0E: Creation time (encoded)
  uint16_t creation_date;            // 0x10: Creation date (encoded)
  uint16_t last_access_date;         // 0x12: Last access date (encoded)
  uint16_t first_cluster_high;       // 0x14: High 16 bits of first cluster (FAT32 only, 0 for FAT12/16)
  uint16_t last_modification_time;   // 0x16: Last modification time (encoded)
  uint16_t last_modification_date;   // 0x18: Last modification date (encoded)
  uint16_t first_cluster_low;        // 0x1A: Low 16 bits of first cluster
  uint32_t file_size;                // 0x1C: File size in bytes
} __attribute__((packed)) fat_dir_entry_t;

__attribute__ ((noinline))
static void dump()
{
    for (uint16_t i = 0; i < 512; i++)
    {
        printhex(((uint8_t*)0x0700)[i]);
    }
    putchar('\r');
    putchar('\n');
    //puts("\r\n");
}

__attribute__ ((noinline))
static int memcmp(const void *s1, const void *s2, uint16_t n)
{
    int result;
    
    __asm__ volatile (
        "cld\n"
        "repe cmpsb\n"            // Compare while equal
        "mov $0, %%ax\n"          // Assume equal
        "je .Ldone%=\n"           // If ZF=1, we're done
        "inc %%ax\n"              // Not equal, AX = 1
        ".Ldone%=:\n"
        : "=a"(result), "+S"(s1), "+D"(s2), "+c"(n)
        :
        : "cc", "memory"
    );
    
    return result;  // 0 = equal, 1 = not equal
}

__attribute__((noreturn)) void boot()
{
#if 0
    uint8_t sectors = read_disk_information();
    puts("sectors:");
    printhex(sectors);
    puts("\r\n");
#endif

    volatile fat_boot_sector_t *boot_sector = (volatile fat_boot_sector_t *)0x7C00;

    // Root directory starts at:
    uint32_t root_dir_sector = boot_sector->reserved_sectors + (boot_sector->num_fats * boot_sector->sectors_per_fat);
    // puts("root_dir_sector:");
    // print_u32(root_dir_sector);
    // puts("\r\n");

    // NOTE: We are kind of assuming that the sector size is 512
    // Root directory size in sectors:
    uint32_t root_dir_size = ((boot_sector->root_entries * 32) +
                              (boot_sector->bytes_per_sector - 1)) /
                             boot_sector->bytes_per_sector;
     //puts("bytes_per_sector:");
     //print_u32(boot_sector->bytes_per_sector);
     //puts("\r\n");
    volatile uint8_t *buf = (volatile uint8_t *)0x0700;

    for(uint32_t i = 0; i < root_dir_size; i++) {
        read_sectors_lba(root_dir_sector + i, 1, buf);
        //dump(buf, 512);
        for(uint8_t j = 0; j < 512 / sizeof(fat_dir_entry_t); j++) {
            fat_dir_entry_t* entry = (fat_dir_entry_t*)(buf + j * sizeof(fat_dir_entry_t));
            //puts(entry->filename);
            if(memcmp(entry->filename, "IO      SYS", 8 + 3) == 0) {
                //puts("YES!");
                //putchar('Y');
                root_dir_sector += root_dir_size;
                root_dir_sector += (entry->first_cluster_low - 2) * boot_sector->sectors_per_cluster;
                read_sectors_lba(root_dir_sector, 3, buf);
                dump(buf);
                //printhex(buf[0]);
                //printhex(buf[1]);
                asm ("jmpw %0, %1" : : "g"(0x0000), "g"(0x0700));
                //printhex(buf[2]);
                //printhex(buf[3]);
                while(true);
            }
        }
        //dump(buf, boot_sector->bytes_per_sector);
    }

    //puts("IO.SYS NOT FOUND");
    putchar('N');

    while (true)
        ;

    __builtin_unreachable();
}
