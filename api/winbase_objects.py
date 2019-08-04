class Atom:
	def __init__(self, key, value):
		self.key = key
		self.value = value
		self.count = 1

class AtomsTable:
	def __init__(self):
		self.__count = 0
		self.__table = {}

	def find_atom(self, string):
		for atom in self.__table:
			if self.__table[atom].value.lower() == string.lower():
				return self.__table[atom].key
		return 0

	def find_string(self, atom):
		return self.__table[atom].value if atom in self.__table else 0

	def add_atom(self, string):
		atom = self.find_atom(string)
		if atom == 0:
			self.__count += 1
			atom = self.__count
			self.__table[atom] = Atom(atom, string)
		else:
			self.__table[atom].count += 1
		return atom
