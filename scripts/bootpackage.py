#!/usr/bin/env python3
"""
SPDX-License-Identifier: MIT
Copyright (C) 2019-2026 Allwinner Technology., Ltd.

bootpackage.py - Python implementation of `dragonsecboot -pack <cfg_file>`

Usage:
    python3 bootpackage.py <cfg_file>

Parses the [package] section from cfg_file, reads the listed binary files,
and packs them into a <cfg_basename>.fex file.

Examples:
    # basic usage
    python3 bootpackage.py boot_package.cfg
    # output: boot_package.fex

    # cfg file with different name
    python3 bootpackage.py boot_package_nor.cfg
    # output: boot_package_nor.fex

    # cfg file in another directory
    python3 bootpackage.py /path/to/config/my_pack.cfg
    # output: /path/to/config/my_pack.fex

boot_package.cfg example:
    [package]
    ;item=Item_TOC_name,         Item_filename,
    item=u-boot,                 u-boot.fex
    ;item=monitor,               monitor.fex
    item=optee,                  optee.fex
"""

import struct
import os
import sys

# ── Constants ──────────────────────────────────────────────────────────────

TOC_MAIN_INFO_MAGIC = 0x89119800
TOC_MAIN_INFO_END   = 0x3b45494d
TOC_ITEM_INFO_END   = 0x3b454949

STAMP_VALUE     = 0x5F0A6C39
ITEM_TYPE_BINFILE = 3

PACKAGE_CONFIG_MAX = 16

# ── Structure sizes (packed, no padding) ───────────────────────────────────
#
# sbrom_toc1_head_info_t  (64 bytes)
#   char name[16]           16
#   u32  magic               4
#   u32  add_sum             4
#   u32  serial_num          4
#   u32  status              4
#   u32  items_nr            4
#   u32  valid_len           4
#   u32  main_version        4
#   u32  sub_version         4
#   u32  reserved[3]        12
#   u32  end                 4
HEAD_SIZE = 64

# sbrom_toc1_item_info_t (368 bytes)
#   char name[64]           64
#   u32  data_offset         4
#   u32  data_len            4
#   u32  encrypt             4
#   u32  type                4
#   u32  run_addr            4
#   u32  index               4
#   u32  reserved[69]      276
#   u32  end                 4
ITEM_SIZE = 368

# ── Struct format strings (little-endian) ──────────────────────────────────

# sbrom_toc1_head_info_t
HEAD_FMT = '<16s 8I'  # name(16s) + magic,add_sum,serial_num,status,items_nr,valid_len,mv,sv + end is part of reserved[3]+end
# Actually let's be precise:
# name[16], magic, add_sum, serial_num, status, items_nr, valid_len, main_version, sub_version, reserved[3], end
HEAD_FMT = '<16s I I I I I I I I 3I I'

# sbrom_toc1_item_info_t
# name[64], data_offset, data_len, encrypt, type, run_addr, index, reserved[69], end
ITEM_FMT = '<64s 6I 69I I'


# ── Config parser ──────────────────────────────────────────────────────────

def parse_cfg_section(cfg_path, section):
    """
    Parse a section from a .cfg file (INI-like format).
    Returns a list of (key, value) tuples.
    Lines starting with ';' or '#' are treated as comments.
    """
    items = []
    in_section = False
    with open(cfg_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            # Skip empty lines and comments
            if not line or line.startswith(';') or line.startswith('#'):
                continue
            # Section header
            if line.startswith('[') and line.endswith(']'):
                sec_name = line[1:-1].strip()
                in_section = (sec_name == section)
                continue
            if not in_section:
                continue
            # key=value  (allow = with spaces around)
            if '=' in line:
                key, _, val = line.partition('=')
                key = key.strip()
                val = val.strip()
                # Strip trailing comment (; or #)
                for sep in (';', '#'):
                    idx = val.find(sep)
                    if idx != -1:
                        val = val[:idx].strip()
                items.append((key, val))
    return items


def parse_item_value(value):
    """
    Parse a comma-separated value like "u-boot, u-boot.fex"
    Returns (item_name, file_name).
    """
    parts = [p.strip() for p in value.split(',')]
    item_name = parts[0] if len(parts) > 0 else ""
    file_name = parts[1] if len(parts) > 1 else ""
    return item_name, file_name


# ── Checksum ───────────────────────────────────────────────────────────────

def gen_general_checksum(data):
    """
    32-bit arithmetic sum (little-endian 32-bit words).
    Same as gen_general_checksum() in check.c
    """
    length = len(data)
    # Pad with zeros to 4-byte boundary if needed
    if length % 4 != 0:
        data = data + b'\x00' * (4 - length % 4)
        length = len(data)

    total = 0
    for i in range(0, length, 4):
        word = struct.unpack_from('<I', data, i)[0]
        total = (total + word) & 0xFFFFFFFF
    return total


# ── Align helpers ──────────────────────────────────────────────────────────

def align_up(value, alignment):
    """Align value up to the given alignment boundary."""
    return (value + alignment - 1) & ~(alignment - 1)


# ── Main pack logic ────────────────────────────────────────────────────────

def do_pack(cfg_path):
    """
    Equivalent to dragonsecboot -pack <cfg_path>
    """

    # 1. Parse [package] section from cfg file
    cfg_items = parse_cfg_section(cfg_path, "package")
    if not cfg_items:
        print(f"Error: no [package] section found in {cfg_path}")
        sys.exit(1)

    # 2. Build package descriptor list (like createcnf_for_package)
    entries = []  # list of (item_name, bin_path)
    for key, val in cfg_items:
        if key != "item":
            continue
        item_name, file_name = parse_item_value(val)
        if not item_name or not file_name:
            continue
        # Resolve relative to cfg file's directory
        cfg_dir = os.path.dirname(os.path.abspath(cfg_path))
        bin_path = os.path.join(cfg_dir, file_name)
        bin_path = os.path.abspath(bin_path)
        entries.append((item_name, bin_path))

    if len(entries) > PACKAGE_CONFIG_MAX:
        print(f"Error: too many items ({len(entries)}), max {PACKAGE_CONFIG_MAX}")
        sys.exit(1)

    content_count = len(entries)
    print(f"content_count={content_count}")

    # 3. Allocate buffer (512 MB like the C code)
    #    We'll use a simpler approach: build in-memory with bytearray
    buffer = bytearray(512 * 1024 * 1024)

    # 4. Build header
    head_bytes = struct.pack(HEAD_FMT,
        b'sunxi-package',          # name[16]
        TOC_MAIN_INFO_MAGIC,       # magic
        0,                         # add_sum (placeholder)
        0,                         # serial_num
        0,                         # status
        content_count,             # items_nr
        0,                         # valid_len (placeholder)
        0,                         # main_version
        0,                         # sub_version
        0, 0, 0,                   # reserved[3]
        TOC_MAIN_INFO_END          # end
    )
    buffer[0:HEAD_SIZE] = head_bytes

    # 5. Build item headers
    items_start = HEAD_SIZE
    for i in range(content_count):
        item_name, bin_path = entries[i]

        item_bytes = struct.pack(ITEM_FMT,
            item_name.encode('ascii').ljust(64, b'\x00'),  # name[64]
            0,          # data_offset (placeholder)
            0,          # data_len (placeholder)
            0,          # encrypt (0 = no aes)
            ITEM_TYPE_BINFILE,  # type (3 = bin file)
            0,          # run_addr
            0,          # index
            *([0] * 69),  # reserved[69]
            TOC_ITEM_INFO_END  # end
        )
        buf_offset = items_start + i * ITEM_SIZE
        buffer[buf_offset:buf_offset + ITEM_SIZE] = item_bytes

    # 6. Calculate total headers size, align to 1024
    headers_size = HEAD_SIZE + content_count * ITEM_SIZE
    data_start = align_up(headers_size, 1024)

    # 7. Write each binary file and update item headers
    offset = data_start
    for i in range(content_count):
        item_name, bin_path = entries[i]

        # Read binary file
        try:
            with open(bin_path, 'rb') as f:
                file_data = f.read()
        except FileNotFoundError:
            print(f"Error: file not found: {bin_path}")
            sys.exit(1)

        file_len = len(file_data)
        print(f"  [{i}] {item_name} -> {bin_path}  (offset={offset}, size={file_len})")

        # Write data into buffer
        buffer[offset:offset + file_len] = file_data

        # Update item header
        item_offset = items_start + i * ITEM_SIZE
        item_bytes = struct.pack(ITEM_FMT,
            item_name.encode('ascii').ljust(64, b'\x00'),
            offset,           # data_offset
            file_len,         # data_len
            0,                # encrypt
            ITEM_TYPE_BINFILE,
            0,                # run_addr
            0,                # index
            *([0] * 69),      # reserved[69]
            TOC_ITEM_INFO_END
        )
        buffer[item_offset:item_offset + ITEM_SIZE] = item_bytes

        # Next offset, align to 1024
        offset = align_up(offset + file_len, 1024)

    # 8. Align total length to 16KB
    valid_len = align_up(offset, 16 * 1024)

    # 9. Write header with STAMP_VALUE in add_sum, then compute checksum
    #    (same logic as C code: package_head->add_sum = STAMP_VALUE first,
    #     then gen_general_checksum overwrites it)
    head_bytes = struct.pack(HEAD_FMT,
        b'sunxi-package',
        TOC_MAIN_INFO_MAGIC,
        STAMP_VALUE,             # add_sum = STAMP_VALUE before checksum
        0,                       # serial_num
        0,                       # status
        content_count,
        valid_len,               # valid_len
        0, 0,
        0, 0, 0,
        TOC_MAIN_INFO_END
    )
    buffer[0:HEAD_SIZE] = head_bytes

    # Compute checksum (with STAMP_VALUE in header, matching C behavior)
    add_sum = gen_general_checksum(bytes(buffer[:valid_len]))

    # 10. Update header with the actual checksum
    head_bytes = struct.pack(HEAD_FMT,
        b'sunxi-package',
        TOC_MAIN_INFO_MAGIC,
        add_sum,                 # actual checksum
        0,                       # serial_num
        0,                       # status
        content_count,
        valid_len,               # valid_len
        0, 0,
        0, 0, 0,
        TOC_MAIN_INFO_END
    )
    buffer[0:HEAD_SIZE] = head_bytes

    # 11. Write output file (same basename as cfg, .fex extension)
    base = os.path.splitext(os.path.basename(cfg_path))[0]
    output_name = os.path.join(os.environ.get('PAK'), base + ".fex")
    with open(output_name, 'wb') as f:
        f.write(buffer[:valid_len])

    print(f"\nCreated: {output_name} ({valid_len} bytes, checksum=0x{add_sum:08x})")


# ── Entry point ────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 bootpackage.py <cfg_file>")
        sys.exit(1)

    cfg_path = os.path.abspath(sys.argv[1])
    if not os.path.isfile(cfg_path):
        print(f"Error: cfg file not found: {cfg_path}")
        sys.exit(1)

    do_pack(cfg_path)


if __name__ == "__main__":
    main()
