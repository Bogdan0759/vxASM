
SIGNATURES = {
    "crc32_table_data": {
        "pattern": b"00000000 77073096 EE0E612C 990951BA 076DC419 706AF48F E963A535 9E6495A3",
        "name": "CRC32 Table (Ethernet)",
        "type": "data"
    },
    "zlib_adler32_func": {
        "pattern": b"55 8B EC 8B 45 0C 8B 4D 08 8B 55 10 2B C1 8B F0 8D 49 00 C1 E8 04 33 C1",
        "name": "zlib: adler32",
        "type": "code"
    },
    "base64_chars": {
        "pattern": b"41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F 50 51 52 53 54 55 56 57 58 59 5A 61 62 63 64 65 66 67 68 69 6A 6B 6C 6D 6E 6F 70 71 72 73 74 75 76 77 78 79 7A 30 31 32 33 34 35 36 37 38 39 2B 2F",
        "name": "Base64 Character Table",
        "type": "data"
    },
    "md5_init_values": {
        "pattern": b"01 23 45 67 89 AB CD EF FE DC BA 98 76 54 32 10",
        "name": "MD5 Initial Values (A,B,C,D)",
        "type": "data"
    },
    "sha1_init_values": {
        "pattern": b"01 23 45 67 89 AB CD EF FE DC BA 98 76 54 32 10 F0 E1 D2 C3",
        "name": "SHA-1 Initial Values (H0-H4)",
        "type": "data"
    },
    "aes_sbox": {
        "pattern": b"63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76",
        "name": "AES S-Box (start)",
        "type": "data"
    },
    "msvc_strcpy": {
        "pattern": b"55 8B EC 8B 45 0C 8B 4D 08 8A 01 88 02 41 84 C0 75 F8",
        "name": "MSVC strcpy function",
        "type": "code"
    },
    "win_registry_currentversion": {
        "pattern": b"53 00 6F 00 66 00 74 00 77 00 61 00 72 00 65 00 5C 00 4D 00 69 00 63 00 72 00 6F 00 73 00 6F 00 66 00 74 00 5C 00 57 00 69 00 6E 00 64 00 6F 00 77 00 73 00 20 00 4E 00 54 00 5C 00 43 00 75 00 72 00 72 00 65 00 6E 00 74 00 56 00 65 00 72 00 73 00 69 00 6F 00 6E",
        "name": "Registry Key: ...\\CurrentVersion (UTF-16)",
        "type": "data"
    }
}