from api.interface import ApiInterface

class ApiBase(ApiInterface):
    def __init__(self):
        self.__functions = {}

    def _add_functions(self, functions):
        self.__functions = {**self.__functions, **functions}

    def _wrap_results(self, results):
        return results if type(results) == list else [results]

    def contains_function(self, function_name):
        return function_name in self.__functions

    def get_function_arguments(self, function_name):
        return self.__functions[function_name][1]

    def emulate_function(self, function_name, arguments):
        args = map(lambda p: p.value, arguments)
        return self.__functions[function_name][0](*args)
