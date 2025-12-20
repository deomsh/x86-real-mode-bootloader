Here’s what jumps out to me in your INT 13h handler. I’ll group them by “definitely wrong / can cause incorrect behaviour” vs “spec mismatches / nits”.

---

## 1. Real bugs that can bite you

### 1.1 Sector 0 → negative LBA → read/write from *end* of disk

In both AH=0x02 (read CHS) and AH=0x03 (write CHS):

```python
sector = cl & 0x3F  # 1-based, per spec, but never validated
...
lba = (cylinder * self.heads + head) * self.sectors_per_track + (sector - 1)
```

If CL has sector 0 (caller bug / fuzzed input), `sector` becomes 0 and:

```python
lba = ... + (0 - 1) = ... - 1
disk_offset = lba * 512
```

In Python, negative indices on a `bytearray` / `bytes` slice are legal and index from the end, so you’ll read/write the last sector of the image instead of raising an error.

You should explicitly reject sector 0:

```python
if sector == 0 or sector > self.sectors_per_track:
    set_error(AH=0x01 / 0x04, CF=1, AL=0)
    return
```

Same logic applies to writes.

---

### 1.2 Missing drive checks in some extended functions

You consistently validate `dl` for most CHS-based functions, but not for some extended ones:

* **AH=0x42 (Extended read)**
* **AH=0x48 (Get extended drive parameters)**
* **AH=0x41 (Check extensions)**

In all three cases you ignore `dl` and happily operate on `self.disk_image` for whatever drive number is passed. For consistency with your other paths (AH=0x01, 0x02, 0x03, 0x08, 0x15) you probably want:

```python
if dl != self.drive_number:
    set CF, set AX to 0x0100 (or another error), return
```

Right now:

* `AH=0x41` will claim extensions present for any `dl`.
* `AH=0x42` will read from your one image even if the caller thinks it’s drive 0x81, etc.
* `AH=0x48` will report parameters even for nonexistent drives.

---

### 1.3 AH=0x02 / 0x03: AH not cleared on success

On success, you do:

```python
flags = uc.reg_read(UC_X86_REG_EFLAGS)
uc.reg_write(UC_X86_REG_EFLAGS, flags & ~0x0001)  # CF=0
uc.reg_write(UC_X86_REG_AX, (uc.reg_read(UC_X86_REG_AX) & 0xFF00) | al)
```

This only updates **AL**, keeping **AH** whatever it previously was (possibly an old error code). BIOS convention:

* On success: **CF=0, AH=0, AL = sectors actually transferred**.

If a caller looks at AH after a “successful” read, they might see an old error and misinterpret the result. Same problem exists in the write handler.

You probably want:

```python
uc.reg_write(UC_X86_REG_AX, (0x00 << 8) | al)
```

(or at least clear AH before OR-ing).

---

### 1.4 CHS range validation is incomplete

You never validate `cylinder`, `head`, or `sector` against your geometry before converting to LBA. You only check that:

```python
disk_offset + bytes_to_read <= len(self.disk_image)
```

This means:

* If your `self.cylinders`, `self.heads`, `self.sectors_per_track` don’t exactly match how the image is laid out, out-of-range CHS combinations may still produce an in-range LBA and silently “succeed” instead of returning an error (e.g., weird geometries or caller mistakes).
* You also never enforce BIOS-style “DMA boundary” constraints (buffer crossing 64K), but that’s more of a fidelity/nit than a bug.

At minimum, it’s worth doing:

```python
if (cylinder >= self.cylinders or
    head >= self.heads or
    sector == 0 or
    sector > self.sectors_per_track):
    # error: AH=0x01 or 0x04, CF=1, AL=0
```

---

## 2. Behaviour vs BIOS spec

These aren’t necessarily fatal, but they diverge from the spec you pasted.

### 2.1 AH=0x01 “Get disk status” register usage

In your code:

```python
uc.reg_write(UC_X86_REG_AX, 0x0100)  # AH=0x01 (invalid parameter)
...
uc.reg_write(UC_X86_REG_AX, 0)       # on success
```

But in the doc you included, AH=1 behaves as:

> AH = 0
> AL = status of previous disk operation

You’re instead encoding the error code in **AH**, not **AL**. That’s backwards relative to that table.

If you care about matching that spec:

* On success: CF=0, AH=0, AL=0
* On error: CF=1, AH=0, AL = status

Right now you also treat AH=1 as “get status for this DL, with a special case for nonexistent drive”, not “status of previous operation”. That’s a behavioural simplification, but worth being aware of.

---

### 2.2 AH=0x41 “Check extensions present”

Your implementation:

```python
if bx == 0x55AA:
    # Extensions present
    uc.reg_write(UC_X86_REG_AX, (uc.reg_read(UC_X86_REG_AX) & 0x00FF) | 0x3000)
    uc.reg_write(UC_X86_REG_BX, 0xAA55)
    uc.reg_write(UC_X86_REG_CX, 0x0003)
    clear CF
else:
    set CF
```

Issues:

1. **Version encoding**
   Spec (for Int 13h extensions) is typically:

   * On success: `BX = AA55h`
   * `AH = major version`, `AL = minor version`
     You’re setting **AH to 0x30** (because of `0x3000`), which is a weird “version 48.x”. Most callers ignore version and just check `CF` and `BX`, but it’s technically wrong.

2. **Not checking DL / drive existence**
   Mentioned earlier: you claim extensions present even for missing drives.

3. **Capabilities (CX) simplification**
   `CX = 0x0003` (“bits 0 and 1 set”) is a reasonable stub (“fixed disk + enhanced disk drive services”), but if you want more fidelity you might want to control this per-drive / per-image.

---

### 2.3 AH=0x48 EDD “flags” and drive checks

You do:

```python
struct.pack_into('<H', params, 2, 0x0002)  # Information flags (bit 1: removable)
```

But you also advertise the drive as a *fixed* disk in AH=0x15:

```python
uc.reg_write(UC_X86_REG_AX, (uc.reg_read(UC_X86_REG_AX) & 0x00FF) | 0x0300)
```

That’s inconsistent: flags say removable, AH=03 says “fixed disk installed”. For a typical HDD emulation, flags 0 is more accurate.

Also, as noted, 0x48 should probably validate `dl == self.drive_number` and return an error if not.

---

### 2.4 Extended read (AH=0x42) return values

Right now on success you:

* Clear CF
* Don’t touch AX at all
* Don’t update the Disk Address Packet

Typical BIOS behaviour:

* CF=0
* AH=0
* AL = number of sectors transferred (sometimes)
* For some BIOSes, word at DAP+2 updated to sectors transferred

Your minimalist behaviour will work for most code that only checks CF, but if you want closer emulation you’d at least clear AH and possibly write back the sector count.

On error you:

```python
flags = uc.reg_read(UC_X86_REG_EFLAGS)
uc.reg_write(UC_X86_REG_EFLAGS, flags | 0x0001)
# AX left whatever it was
```

You don’t set an error code in AH at all, which diverges from the normal int 13h pattern.

---

## 3. Minor / stylistic / robustness things

These aren’t “bugs” so much as rough edges.

### 3.1 AH=0x00 “Reset disk system” doesn’t touch status

You just clear CF:

```python
flags = uc.reg_read(UC_X86_REG_EFLAGS)
uc.reg_write(UC_X86_REG_EFLAGS, flags & ~0x0001)
```

Many BIOSes also clear AH (and sometimes AL) so that a following “get status” call returns “no error”. Right now AH could contain stale garbage.

### 3.2 No partial-transfer reporting

For reads/writes you always:

* Transfer **all** requested sectors or **none**.
* On error you don’t set AL to “number of sectors actually transferred” (which should usually be 0, but spec allows partials).

Totally fine for a simple emulator, just worth knowing you’re not modelling that behaviour.

### 3.3 DMA 64K boundary & segment wrap

Real BIOS rejects buffers where `ES:BX` + length crosses a 64K boundary with error 0x09 (“DMA overrun”). You don’t check that; you just happily `mem_write`. For most real-mode OS/bootloader code you’ll be fine; it’s a fidelity thing.

---

## 4. TL;DR checklist

If you want to tighten this up without going full pedant:

1. **Fix the sector-0 bug** in AH=0x02/0x03 (check `sector == 0` before computing LBA).
2. **Clear AH on success** (reads/writes, 0x42, 0x08, etc.).
3. **Validate `dl` consistently** in 0x41/0x42/0x48, like you already do in 0x01/0x02/0x03/0x08/0x15.
4. **Make AH=0x01 match the spec** if you care (status in AL, AH=0).
5. **Adjust 0x41 / 0x48 details**:

   * 0x41: set a sane version (e.g. AH=0x01, AL=0x00 or similar).
   * 0x48: info flags 0x0000 for a fixed disk, and set an error code in AH on failure.

If you want, next step I can sketch a small test harness (CHS & extended) you can run in Unicorn to sanity-check all the edge cases (sector 0, bad head, beyond geometry, bad DAP size, invalid drive, etc.).
