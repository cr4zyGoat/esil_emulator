class FunctionArgument:
	STRING = 'string'
	NUMBER = 'number'
	ADDRESS = 'address'

	def __init__(self, name, typed, value=None):
		self.name = name
		self.typed = typed
		self.value = value

class FunctionResult:
	BYTES = 'bytes'
	NUMBER = 'number'

	def __init__(self, value, typed, target='eax', to_reference=False):
		self.target = target
		self.typed = typed
		self.value = value
		self.to_reference = to_reference
