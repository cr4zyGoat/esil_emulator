from api.interface import ApiInterface

class ApiContainer(ApiInterface):
	def __init__(self):
		self.__apis = []

	def load_api(self, api):
		self.__apis.append(api)

	def contains_function(self, function_name):
		for api in self.__apis:
			if api.contains_function(function_name):
				return True
		return False

	def get_function_arguments(self, function_name):
		for api in self.__apis:
			if api.contains_function(function_name):
				return api.get_function_arguments(function_name)

	def emulate_function(self, function_name, arguments):
		for api in self.__apis:
			if api.contains_function(function_name):
				return api.emulate_function(function_name, arguments)
