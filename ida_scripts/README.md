# Purpose

This directory hosts various IDA scripts that might be useful when performing malware analysis.

# Scripts
## ida_api_checksums_to_enum_names_bruteforce.py
This script aims to create enum values for checksums of API functions and DLL names commonly used in shellcodes instead of actual names and then search for them througout the disassemled code.
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

## name_to_ptr.idc
This script propagates names to their pointers within the selected area, useful when dealing with dynamically resolved import tables and decrypted strings

Tested on IDA Freeware 7.0
