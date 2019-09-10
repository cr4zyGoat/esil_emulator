from functools import reduce

class Output:
	def __init__(self):
		self.__indentation = 0

	def write_title(self, message):
		print(f'\n=========== {message.upper()} ===========\n')

	def write_code(self, message):
		print('\t'*self.__indentation + message)
	
	def write_call(self, function_name, arguments=None):
		arg_str = reduce(lambda r, i: f'{r}, {i}', arguments) if arguments else ''
		message = f'call {function_name} ({arg_str})'
		self.write_code(message)
		self.__indentation += 1

	def write_reallocated_call(self, function_name, arguments=None):
		arg_str = reduce(lambda r, i: f'{r}, {i}', arguments) if arguments else ''
		message = f'jmp {function_name} ({arg_str})'
		self.write_code(message)
	
	def write_return(self, results=None):
		res_str = reduce(lambda r, i: f'{r}, {i}', results) if results else ''
		message = f'return {res_str}'
		self.write_code(message)
		self.__indentation -= 1

	def write_comparison(self, operation, params, zf):
		message = f'{operation} {params}\t# zf={zf}'
		self.write_code(message)
