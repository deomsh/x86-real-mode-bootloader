;
; fat16m.nasm: empty FAT16 filesystem with MBR and partition table
; by pts@fazekas.hu at Thu Dec 26 01:51:51 CET 2024
;
; Compile with: nasm -O0 -w+orphan-labels -f bin -o fat16m.bin fat16m.nasm
; Minimum NASM version required to compile: 0.98.39
;
; This is a legacy file only retained for its comments only and for its use
; in mkfs.sh.
;
; See boot_process.md for a general description of the BIOS (legacy, MBR)
; boot process.
;

bits 16
cpu 8086
;org 0x7c00  ; Independent.

%macro assert_fofs 1
  times +(%1)-($-$$) times 0 nop
  times -(%1)+($-$$) times 0 nop
%endm
%macro assert_at 1
  times +(%1)-$ times 0 nop
  times -(%1)+$ times 0 nop
%endm

PTYPE:  ; Partition type.
.EMPTY equ 0
.FAT12 equ 1
.FAT16_LESS_THAN_32MIB equ 4  ; Works on DOS <=3.30.
.EXTENDED equ 5
.FAT16 equ 6  ; Needs DOS >=4.00.
.HPFS_NTFS_EXFAT equ 7
.FAT32 equ 0xb
.FAT32_LBA equ 0xc
.FAT16_LBA equ 0xe
.EXTENDED_LBA equ 0xf
.MINIX_OLD equ 0x80
.MINIX equ 0x81
.LINUX_SWAP equ 0x82
.LINUX equ 0x83
.LINUX_EXTENDED equ 0x85
.LINUX_LVM equ 0x8e
.LINUX_RAID_AUTO equ 0xfd

PSTATUS:  ; Partition status.
.INACTIVE equ 0
.ACTIVE equ 0x80

BOOT_SIGNATURE equ 0xaa55  ; dw.

; !! For partition_entry_lba to fill the CHS values properly, values from qemu-system-i386.
pe_heads equ 16
pe_secs equ 63

; %1: status (PSTATUS.*: 0: inactive, 0x80: active (bootable))
; %2: CHS head of first sector; %3: CHS cylinder and sector of first sector
; %4: partition type (PTYPE.*)
; %5: CHS head of last sector; %6: CHS cylinder and sector of last sector
; %7: sector offset (LBA) of the first sector
; %8: number of sectors
%macro partition_entry 8
  db (%1), (%2)
  dw (%3)
  db (%4), (%5)
  dw (%6)
  dd (%7), (%8)
%endm
; Like partition_entry, but sets all CHS values to 0.
;
; (The following is verified only if DOS is not booted from this drive.)
; FreeDOS 1.0..1.3 displays a warning at boot time about a bad CHS value,
; but it works. MS-DOS 6.22 doesn't care about CHS values here.
;
; !! Check and add compatibility with MS-DOS 5.00, 6.00 and 6.20. Works: 4.01, 5.00, 6.22, 7.x, 8.0.
;
; %1: status (PSTATUS.*: 0: inactive, 0x80: active (bootable))
; %2: partition type (PTYPE.*)
; %3: sector offset (LBA) of the first sector
; %4: number of sectors
%macro partition_entry_lba 4
  partition_entry (%1), 0, 0, (%2), 0, 0, (%3), (%4)
%endm
%macro partition_entry_empty 0
  partition_entry PSTATUS.INACTIVE, 0, 0, PTYPE.EMPTY, 0, 0, 0, 0  ; All NULs.
%endm

%macro fat_header 8  ; %1: .reserved_sector_count value; %2: .sector_count value; %3: .fat_count, %4: .sectors_per_cluster, %5: fat_sectors_per_fat, %6: fat_rootdir_sector_count, %7: fat_32 (0 for FAT16, 1 for FAT32), %8: partition_gap_sector_count.
; More info about FAT12, FAT16 and FAT32: https://en.wikipedia.org/wiki/Design_of_the_FAT_file_system
;
.header:	jmp strict short .boot_code
		nop  ; 0x90 for CHS. Another possible value is 0x0e for LBA. Who uses it? It is ignored by .boot_code.
assert_at .header+3
.oem_name:	db 'MSDOS5.0'
assert_at .header+0xb
.bytes_per_sector: dw 0x200  ; The value 0x200 is hardcoded in boot_sector.boot_code, both explicitly and implicitly.
assert_at .header+0xd
.sectors_per_cluster: db (%4)
assert_at .header+0xe
.reserved_sector_count: dw (%1)+(%8)
assert_at .header+0x10
.fat_count:	db (%3)  ; Must be 1 or 2. MS-DOS 6.22 supports only 2. Windows 95 DOS mode supports 1 or 2.
assert_at .header+0x11
%if (%7)  ; FAT32.
.rootdir_entry_count: dw 0
%else
.rootdir_entry_count: dw (%6)<<4  ; Each FAT directory entry is 0x20 bytes. Each sector is 0x200 bytes.
%endif
assert_at .header+0x13
%if (%7) || (((%2)+(%8))&~0xffff)
.sector_count_zero: dw 0  ; See true value in .sector_count.
%else
.sector_count_zero: dw (%2)+(%8)
%endif
assert_at .header+0x15
.media_descriptor: db 0xf8  ; 0xf8 for HDD.
assert_at .header+0x16
%if (%7)  ; FAT32.
.sectors_per_fat: dw 0  ; IBM PC DOS 7.1 msload detects FAT32 by comparing this to 0.
%else
.sectors_per_fat: dw (%5)
%endif
assert_at .header+0x18
; FreeDOS 1.2 `dir c:' needs a correct value for .sectors_per_track and
; .head_count. MS-DOS 6.22 and FreeDOS 1.3 ignore these values (after boot).
.sectors_per_track: dw 1  ; Track == cylinder. Dummy nonzero value to pacify mtools(1). Will be overwritten with value from BIOS int 13h AH == 8.
assert_at .header+0x1a
.head_count: dw 1  ; Dummy nonzero value to pacify mtools(1). Will be overwritten with value from BIOS int 13h AH == 8.
assert_at .header+0x1c
.hidden_sector_count: dd 0  ; Occupied by MBR and previous partitions. Will be overwritten with value from the partition entry: partition start sector offset. !! Does MS-DOS 6.22 use it outside boot (probably no)? Does FreeDOS use it (probably no).
assert_at .header+0x20
.sector_count: dd (%2)+(%8)
assert_at .header+0x24
%if (%7)  ; FAT32.
; B1G-4K based on: rm -f fat32.img && mkfs.vfat -a -C -D 0 -f 1 -F 32 -i abcd1234 -r 128 -R 17 -s 8 -S 512 -h 63 --invariant fat32.img 1049604
; -R >=16 for Windows XP installation, it modifies sector 8 when making the partition bootable.
.sectors_per_fat_fat32: dd (%5)
assert_at .header+0x28
.mirroring_flags: dw 0  ; As created by mkfs.vfat.
assert_at .header+0x2a
.version: dw 0
assert_at .header+0x2c
.rootdir_start_cluster: dd 2
assert_at .header+0x30
.fsinfo_sec_ofs: dw 1+(%8)
assert_at .header+0x32
.first_boot_sector_copy_sec_ofs: dw 6+(%8)  ; 6 was created by mkfs.vfat, also for Windows XP. 4 would also work. There are up to 3 sectors here. Windows XP puts some extra boot code to sector 8 (of 16).
assert_at .header+0x34
.reserved:	dd 0, 0, 0
assert_at .header+0x40
.drive_number: db 0x80
assert_at .header+0x41
.reserved2:	db 0
assert_at .header+0x42
.extended_boot_signature: db 0x29
assert_at .header+0x43
.volume_id: dd 0x1234abcd  ; 1234-ABCD.
assert_at .header+0x47
.volume_label:	db 'NO NAME    '
assert_at .header+0x52
.fstype:	db 'FAT32   '
assert_at .header+0x5a
%else  ; Non-FAT32.
; Based on: truncate -s 2155216896 hda.img  # !! Magic size value for QEMU, see notes.txt.
; Based on: rm -f fat16.img && mkfs.vfat -a -C -D 0 -f 1 -F 16 -i abcd1234 -r 128 -R 57 -s 64 -S 512 -h 63 --invariant fat16.img 2096766
assert_at .header+0x24
.drive_number: db 0x80
assert_at .header+0x25
.var_unused: db 0  ;.var_read_head: db 0  ; Can be used as a temporary variable in .boot_code.
assert_at .header+0x26
.extended_boot_signature: db 0x29
assert_at .header+0x27
.volume_id: dd 0x1234abcd  ; 1234-ABCD.
assert_at .header+0x2b
.volume_label:	db 'NO NAME    '
assert_at .header+0x36
.fstype:	db 'FAT16   '
assert_at .header+0x3e
%endif
%endm

; ---

%ifndef FAT_32
  %define FAT_32 0  ; 0 or 1.
%endif
fat_32 equ FAT_32

partition_1_sec_ofs equ 0x3f  ; 63. For MS-DOS, this must be a multiple of the CHS secs (sectors per track).
%ifndef FAT_CLUSTER_COUNT
  %define FAT_CLUSTER_COUNT 0xffee
%endif
fat_cluster_count equ FAT_CLUSTER_COUNT  ; This is physical (stored on disk) cluster count. Valid values for FAT16 are: 0xffe..0xffee. Valid values for FAT32 are: 0xfffe..0xfffffee.
%ifndef FAT_COUNT  ; Must be 1 or 2 if defined.
  %define FAT_COUNT 2  ; For MS-DOS 6.22 compatibility. !! Make the filesystem image 128 KiB larger than.
%endif
fat_fat_count equ FAT_COUNT
%ifndef FAT_SECTORS_PER_CLUSTER
  %define FAT_SECTORS_PER_CLUSTER 0x40
%endif
fat_sectors_per_cluster equ FAT_SECTORS_PER_CLUSTER  ; Valid values: 1, 2, 4, 8, 0x10, 0x20, 0x40.

%if fat_32
  fat_reserved_sector_count equ 0x11
  fat_rootdir_sector_count equ 0
%else
  %if fat_sectors_per_cluster<0x10
    fat_reserved_sector_count equ 1 ; Only the boot sector.
  %else
    fat_reserved_sector_count equ 1+(fat_sectors_per_cluster-8)  ; !! Explain this because of alignment, after first FAT and second FAT. !! Also the -8 is related to the .rootdir_sector_count.
  %endif
  fat_rootdir_sector_count equ 8  ; 128 entries.
%endif
fat_sectors_per_fat equ (fat_cluster_count+2+(1<<(8-fat_32))-1)>>(8-fat_32)  ; Good formula for FAT16. We have the +2 here because clusters 0 and 1 have a next-pointer in the FATs, but they are not stored on disk.
fat_sector_count equ fat_reserved_sector_count+fat_fat_count*fat_sectors_per_fat+fat_rootdir_sector_count+fat_cluster_count*fat_sectors_per_cluster  ; Largest FAT16, close to 2 GiB.

assert_fofs 0
mbr:  ; Master Boot record, sector 0 (LBA) of the drive.
; More info about the MBR: https://wiki.osdev.org/MBR_(x86)
; More info about the MBR: https://en.wikipedia.org/wiki/Master_boot_record
; More info about the MBR: https://pushbx.org/ecm/doc/ldosboot.htm#protocol-rombios-sector
fat_header fat_reserved_sector_count, fat_sector_count, fat_fat_count, fat_sectors_per_cluster, fat_sectors_per_fat, fat_rootdir_sector_count, fat_32, partition_1_sec_ofs
.org: equ -0x7e00+.header
		times 0x5a-($-.header) db '+'  ; Pad FAT16 headers to the size of FAT32, for uniformity.
.boot_code:
		incbin 'boot.bin', 0x5a, 0x1b8-0x5a
assert_at .header+0x1b8
.disk_id_signature: dd 0x9876edcb
assert_at .header+0x1bc
.reserved_word_0: dw 0
.partition_1:
assert_at .header+0x1be  ; Partition 1.
%if fat_32
  .ptype equ PTYPE.FAT32_LBA  ; Windows 95 OSR2 cannot read the filesystem if PTYPE.FAT16 is (incorrectly) specified here.
%else
  %if fat_sector_count<=65535
    .ptype equ PTYPE.FAT16_LESS_THAN_32MIB  ; For DOS 3.30.
  %else
    .ptype equ PTYPE.FAT16  ; Needs DOS >=4.00.
  %endif
%endif
		partition_entry_lba PSTATUS.ACTIVE, .ptype, partition_1_sec_ofs, fat_sector_count
assert_at .header+0x1ce  ; Partition 2.
		partition_entry_empty
assert_at .header+0x1de  ; Partition 3.
		partition_entry_empty
assert_at .header+0x1ee  ; Partition 4.
		partition_entry_empty
assert_at .header+0x1fe
.boot_signature: dw BOOT_SIGNATURE
assert_at .header+0x200

; ---

assert_fofs 0x200
		times (partition_1_sec_ofs-1)<<9 db 0
assert_fofs partition_1_sec_ofs<<9

; ---

%macro fat_boot_sector 0
		fat_header fat_reserved_sector_count, fat_sector_count, fat_fat_count, fat_sectors_per_cluster, fat_sectors_per_fat, fat_rootdir_sector_count, fat_32, 0
.org: equ -0x7c00+.header
.boot_code:
%if fat_32
assert_at .header+0x5a
		incbin 'boot.bin', 0x25a, 0x1fe-0x5a
%else
assert_at .header+0x3e
		incbin 'boot.bin', 0x43e, 0x1fe-0x3e
%endif
.boot_signature: dw BOOT_SIGNATURE
assert_at .header+0x200
%endm
boot_sector:
		fat_boot_sector

; ---

assert_fofs (partition_1_sec_ofs+1)<<9
%if fat_32
fsinfo:  ; https://en.wikipedia.org/wiki/Design_of_the_FAT_file_system#FS_Information_Sector
.header:	db 'RRaA'
.reserved:	times 0x1e0 db 0
assert_at .header+0x1e4
.signature2:	db 'rrAa'
assert_at .header+0x1e8
.free_cluster_count: dd fat_cluster_count-1  ; -1 because the root directory occupies 1 cluster.
assert_at .header+0x1ec
.most_recently_allocated_cluster_ofs: dd 2  ; The root directory cluster.
assert_at .header+0x1f0
.reserved2:	times 0xc db 0
.signature3:	dw 0, BOOT_SIGNATURE
assert_at .header+0x200
assert_fofs (partition_1_sec_ofs+2)<<9

		times 4*0x200 db 0
backup_boot_sector:
		fat_boot_sector
%endif
		times (fat_reserved_sector_count-1-6*fat_32)<<9 db 0  ; Reserved sectors before FAT.
assert_fofs (partition_1_sec_ofs+fat_reserved_sector_count)<<9

assert_fofs (partition_1_sec_ofs+fat_reserved_sector_count)<<9
first_fat:
%if fat_32
		; !! Use fat_media_descriptor instead of 0xf8.
		dd 0xffffff8, 0xfffffff  ; 2 special cluster pointers, no used clusters in FAT16.
		dd 0xffffff8  ; Indicates empty root directory.
%else
		; !! Use fat_media_descriptor instead of 0xf8 of -8.
		dw -8, -1  ; 2 special cluster pointers, no used clusters in FAT16.
%endif
		times (first_fat-$)&0x1ff db 0  ; Align to multiple of sector size (0x200).

%if fat_fat_count>1
		times first_fat+(fat_sectors_per_fat<<9)-$ db 0
second_fat:
%if fat_32
		; !! Use fat_media_descriptor instead of 0xf8.
		dd 0xffffff8, 0xfffffff  ; 2 special cluster pointers, no used clusters in FAT16.
		dd 0xffffff8  ; Indicates empty root directory.
%else
		; !! Use fat_media_descriptor instead of 0xf8 of -8.
		dw -8, -1  ; 2 special cluster pointers, no used clusters in FAT16.
%endif
		times (second_fat-$)&0x1ff db 0  ; Align to multiple of sector size (0x200).
%endif

; __END__
