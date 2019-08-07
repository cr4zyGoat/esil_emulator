PE_FORMATS = ['acm', 'ax', 'cpl', 'dll', 'drv', 'efi', 'exe', 'mui', 'ocx', 'scr', 'sys', 'tsp']

def is_address(value):
	return type(value) == int or value.isnumeric() or value[:2] == '0x'

def is_pe_file(file):
	return file.split('.')[-1].lower() in PE_FORMATS
