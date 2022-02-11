# Purpose

This directory hosts various IDA scripts that might be useful when performing malware analysis.

# Scripts
## restore_apis/ida_api_checksums_to_enum_names_bruteforce.py
This script aims to create enum values for checksums of API functions and DLL names commonly used in shellcodes instead of actual names and then search for them throughout the disassembled code.

**NB:** checksum algorithms are prone to collisions!

### Options
To begin with, place all required DLLs to the directory specified by PATH_TO_DLLS variable.

**MSFvenom shellcodes**
* API_FORMAT = WITH_NULL
* DLL_FORMAT = WITH_NULL | IS_WIDE | IS_UPPER
* DLL_WITH_FILE_EXTENSION = True
* ADD_DLL_CHECKSUM = True
* IS_ROR = True
* SHIFT_VALUE = 0x0D

**Cobalt Strike-related shellcodes**
* API_FORMAT = 0
* DLL_FORMAT = IS_WIDE | IS_UPPER
* DLL_WITH_FILE_EXTENSION = True
* ADD_DLL_CHECKSUM = False
* IS_CRC32 = True

## restore_apis/apis_by_hashes.idc
This script expects the user to place a cursor to the start of the function resolving API names by their hashes. As IDC capabilities are limited, the mappings are pre-built and stored in a separate file `matches.txt`. Adjust the metadata of the instruction mentioning the API hash according to your malware sample.

Tested on IDA Freeware 7.0

## decrypt_strings/find_and_decrypt_strings.idc
This script searches for all instances of encrypted strings and decrypts them using the key stored in a separate file key.bin

Tested on IDA Freeware 7.0

## name_to_ptr.idc
This script propagates addresses' names to their pointers within the selected area, useful when dealing with dynamically resolved import tables and decrypted strings

Tested on IDA Freeware 7.0
