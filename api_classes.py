class FunctionParam:
	BYTES = 'BYTES'
	STRING = 'STRING'
	NUMBER = 'NUMBER'

	def __init__(self, name, typed, value=None):
		self.name = name
		self.typed = typed
		self.value = value

class AtomsTable:
	def __init__(self):
		self.__count = 0
		self.__table = {}

	def find_atom(self, string):
		for atom in self.__table:
			if self.__table[atom]['value'].lower() == string.lower():
				return self.__table[atom]['key']
		return 0

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
