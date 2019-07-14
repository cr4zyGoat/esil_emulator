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

class AtomsTable:
	def __init__(self):
		self.__count = 0
		self.__table = {}

	def find_atom(self, string):
		for atom in self.__table:
			if self.__table[atom]['value'].lower() == string.lower():
				return self.__table[atom]['key']
		return 0

	def find_string(self, atom):
		return self.__table[atom]['value'] if atom in self.__table else 0

	def add_atom(self, string):
		atom = self.find_atom(string)
		if atom == 0:
			self.__count += 1
			atom = self.__count
			self.__table[atom] = {
				'key': atom,
				'value': string,
				'count': 1
			}
		else:
			self.__table[atom]['count'] += 1
		return atom
