from abc import ABC, abstractmethod

class ApiInterface(ABC):
	@abstractmethod
	def contains_function(self, function_name):
		pass

	@abstractmethod
	def get_function_arguments(self, function_name):
		pass

	@abstractmethod
	def emulate_function(self, function_name, arguments):
		pass
