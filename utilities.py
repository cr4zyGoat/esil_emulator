import re

PE_FORMATS = {'acm', 'ax', 'cpl', 'dll', 'drv', 'efi', 'exe', 'mui', 'ocx', 'scr', 'sys', 'tsp'}
CMP_OPERATIONS = {'cmp', 'test'}

def is_register(value):
	return type(value) == str and not value.isnumeric() and len(value) <= 3

def is_address(value):
	return type(value) == int or value.isnumeric() or value[:2] == '0x'

def is_pe_file(file):
	return file.split('.')[-1].lower() in PE_FORMATS

def is_zero(value):
	if type(value) == str:
		if value.isnumeric() and int(value) == 0: return True
		if value[:2] == '0x' and int(value, 16) == 0: return True
	return value == 0

def is_comparison(operation):
	return operation in CMP_OPERATIONS

def clean_argument(argument):
	match = re.search('\\[(.*)\\]', argument)
	return match.group(1) if match else argument
