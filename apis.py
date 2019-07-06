import inspect

class FunctionParam:
    STRING = 'STRING'
    NUMBER = 'NUMBER'

    def __init__(self, name, typed):
        self.name = name
        self.typed = typed
        self.value = None

class Api:
    def __init__(self):
        self.__functions = {
            'AddAtomA': [self.__add_atom_A, self.__add_atom_A_arguments],
            'FindAtomA': [self.__find_atom_A, self.__find_atom_A_arguments],
            'malloc': [self.__malloc, self.__malloc_arguments]
        }

    def contains_function(self, function_name):
        return function_name in self.__functions

    def get_function_arguments(self, function_name):
        return self.__functions[function_name][1]

    def emulate_function(self, function_name, arguments):
        args = map(lambda p: p.value, arguments)
        return self.__functions[function_name][0](*args)

    __add_atom_A_arguments = [
        FunctionParam('lpString', FunctionParam.STRING)
    ]

    def __add_atom_A(self, lpString):
        pass

    __find_atom_A_arguments = [
        FunctionParam('lpString', FunctionParam.STRING)
    ]

    def __find_atom_A(self, lpString):
        pass
        
    __malloc_arguments = [
        FunctionParam('size_t', FunctionParam.NUMBER)
    ]

    def __malloc(self, size_t):
        pass