class FunctionArgument:
	STRING = 'string'
	NUMBER = 'number'
	ADDRESS = 'address'
	POINTED_VALUE = 'pointed_value'

	def __init__(self, name, typed, value=None):
		self.name = name
		self.typed = typed
		self.value = value

	def __str__(self):
		return f'{self.name}={self.value} [{self.typed}]'

class FunctionResult:
	BYTES = 'bytes'
	NUMBER = 'number'

	def __init__(self, value, typed, target='eax', to_reference=False):
		self.target = target
		self.typed = typed
		self.value = value
		self.to_reference = to_reference

	def __str__(self):
		return f'{self.target}={self.value} [{self.typed}]'
