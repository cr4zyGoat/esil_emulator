from api.interface import ApiInterface
from api.parameters import FunctionResult

class ApiBase(ApiInterface):
    def __init__(self):
        self.__functions = {}

    def _add_functions(self, functions):
        self.__functions = {**self.__functions, **functions}

    def _wrap_results(self, results):
        if type(results) == FunctionResult: return [results]
        if not results: return list()
        return results

    def _true_result(self, target=None, to_reference=None):
        kwargs = {}
        if target: kwargs['target'] = target
        if to_reference: kwargs['to_reference'] = to_reference
        return FunctionResult(1, FunctionResult.NUMBER, **kwargs)

    def _null_result(self, target=None, to_reference=None):
        kwargs = {}
        if target: kwargs['target'] = target
        if to_reference: kwargs['to_reference'] = to_reference
        return FunctionResult(0, FunctionResult.NUMBER, **kwargs)
    
    def _new_address_result(self, target=None):
        kwargs = {'target': target} if target else {}
        return FunctionResult(1, FunctionResult.NUMBER, to_reference=True, **kwargs)

    def contains_function(self, function_name):
        return function_name in self.__functions

    def get_function_arguments(self, function_name):
        return self.__functions[function_name][1]

    def emulate_function(self, function_name, arguments):
        args = map(lambda p: p.value, arguments)
        return self.__functions[function_name][0](*args)
