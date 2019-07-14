def is_address (value):
	return type(value) == int or value.isnumeric() or value[:2] == '0x'
