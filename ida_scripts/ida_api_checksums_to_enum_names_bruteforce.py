# Author: Alexey Kleymenov
# Original idea: Piotr Krysiuk <piotr_krysiuk@symantec.com>

import os
import pefile
import zlib

IS_WIDE = 0x1
IS_UPPER = 0x2
IS_LOWER = 0x4
WITH_NULL = 0x8

# ################# OPTIONS ###################
PATH_TO_DLLS = 'c:\\dlls'

DLL_ENUM_NAME = 'dll_hashes'
ENUM_VALUE_SUFFIX = '_checksum'

API_FORMAT = WITH_NULL
DLL_FORMAT = WITH_NULL | IS_WIDE | IS_UPPER
DLL_WITH_FILE_EXTENSION = True
ADD_DLL_CHECKSUM = True

IS_CRC32 = False
IS_ROR = True
IS_ROL = False
SHIFT_VALUE = 0x0D
# #############################################


def format_value(name, format):
	if format & WITH_NULL:
		name += '\x00'
	if format & IS_UPPER:
		name = name.upper()
	elif format & IS_LOWER:
		name = name.lower()
	if format & IS_WIDE:
		try:
			name = name.encode('utf-16le').decode('latin-1')
		except Exception as e:
			Message('%s - %s\n' % (name, str(e)))
	return name


def calculate_checksum(name):
	value = 0
	if IS_CRC32:
		value = zlib.crc32(name) & 0xFFFFFFFF
	else:
		for symbol in name:
			if IS_ROR:
				value = ((value >> SHIFT_VALUE) | (value << (0x20 - SHIFT_VALUE))) & 0xFFFFFFFF
			elif IS_ROL:
				value = ((value << SHIFT_VALUE) | (value >> (0x20 - SHIFT_VALUE))) & 0xFFFFFFFF
			else:
				raise Exception('Unsupported checksum algorithm')
			value += ord(symbol) & 0xFFFFFFFF
	return value


def build_mappings(dll_filepath):
	dll = pefile.PE(dll_filepath, fast_load=True)
	dll.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']])
	result = {}
	if hasattr(dll, 'DIRECTORY_ENTRY_EXPORT'):
		dll_name = os.path.basename(dll_filepath)
		if DLL_WITH_FILE_EXTENSION is False:
			dll_name = ".".join(dll_name.split(".")[:-1])
		dll_checksum = calculate_checksum(format_value(dll_name, DLL_FORMAT))
		Message('%s - %x\n' % (dll_name, dll_checksum))
		dll_name = dll_name.replace('.', '_')
		result[dll_checksum] = {'dll_name': dll_name}

		export_directory = dll.DIRECTORY_ENTRY_EXPORT
		for symbol in export_directory.symbols:
			if symbol.name is not None:
				api_name = symbol.name.decode('latin-1')
				api_checksum = calculate_checksum(format_value(api_name, API_FORMAT))
				if ADD_DLL_CHECKSUM:
					api_checksum = (api_checksum + dll_checksum) & 0xFFFFFFFF
				result[api_checksum] = {'dll_name': dll_name, 'api_name': api_name}
# 				Message('%s - %x\n' % (api_name, api_checksum))
	return result


def parse_dlls(path_to_dlls):
	list_dlls = os.listdir(path_to_dlls)
	mappings = {}
	for dll_filename in list_dlls:
		Message('Processing %s\n' % dll_filename)
		mappings.update(build_mappings(os.path.join(path_to_dlls, dll_filename)))
	return mappings


def create_enums(mappings):
	# allows digesting mappings from json
	if type(next(iter(mappings))) != int:
		mappings = {int(key): value for key, value in mappings.iteritems()}
	created_enums = set()
	dll_enum = GetEnum(DLL_ENUM_NAME)
	if dll_enum == 0xFFFFFFFF:
		dll_enum = AddEnum(GetEnumQty(), DLL_ENUM_NAME, FF_DWRD | FF_0NUMH)
	for checksum, metadata in mappings.iteritems():
		if 'api_name' in metadata:
			if metadata['dll_name'] in created_enums:
				enum = GetEnum(metadata['dll_name'].encode('latin-1'))
			else:
				enum = AddEnum(GetEnumQty(), metadata['dll_name'].encode('latin-1'), FF_DWRD | FF_0NUMH)
				created_enums.add(metadata['dll_name'])
			ret_code = AddConst(enum, (metadata['api_name'] + ENUM_VALUE_SUFFIX).encode('latin-1'), checksum)
			if ret_code:
				Message('Warning: %s - %x\n' % (metadata['api_name'], ret_code))
		else:
			ret_code = AddConst(dll_enum, (metadata['dll_name'] + ENUM_VALUE_SUFFIX).encode('latin-1'), checksum)
			if ret_code:
				Message('Warning: %s - %x\n' % (metadata['dll_name'], ret_code))
	return mappings


def bruteforce_enum_values(enums):
	for head in Heads():
		flags = GetFlags(head)
		if isCode(flags):
			if GetOpType(head, 0) == 5:
				operand_num = 0
			elif GetOpType(head, 1) == 5:
				operand_num = 1
			else:
				continue
			value = GetOperandValue(head, operand_num)
			if value in enums:
				if 'api_name' in enums[value]:
					Message('%x - found match: %s\n' % (head, enums[value]['api_name']))
					OpEnumEx(head, operand_num, GetEnum(enums[value]['dll_name'].encode('latin-1')), 0)
				else:
					Message('%x - found match: %s\n' % (head, enums[value]['dll_name']))
					OpEnumEx(head, operand_num, GetEnum(DLL_ENUM_NAME), 0)


bruteforce_enum_values(create_enums(parse_dlls(PATH_TO_DLLS)))
