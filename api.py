from api_classes import FunctionParam
from api_classes import AtomsTable

class Api:
    def __init__(self):
        self.__atoms_table = AtomsTable()
        self.__functions = {
            'AddAtomA': [self.__add_atom_A, self.__add_atom_A_arguments],
            'FindAtomA': [self.__find_atom_A, self.__find_atom_A_arguments],
            'GetAtomNameA': [self.__get_atom_name_A, self.__get_atom_name_A_arguments],
            'malloc': [self.__malloc, self.__malloc_arguments]
        }


    def contains_function(self, function_name):
        return function_name in self.__functions

    def get_function_arguments(self, function_name):
        return self.__functions[function_name][1]

    def emulate_function(self, function_name, arguments):
        args = map(lambda p: p.value, arguments)
        return self.__functions[function_name][0](*args)

    def __wrap_results(self, value, typed):
        return FunctionParam('eax', typed, value)

    __add_atom_A_arguments = [
        FunctionParam('lpString', FunctionParam.STRING)
    ]

    def __add_atom_A(self, lpString):
        atom = self.__atoms_table.add_atom(lpString)
        return self.__wrap_results(atom, FunctionParam.NUMBER)

    __find_atom_A_arguments = [
        FunctionParam('lpString', FunctionParam.STRING)
    ]

    def __find_atom_A(self, lpString):
        atom = self.__atoms_table.find_atom(lpString)
        return self.__wrap_results(atom, FunctionParam.NUMBER)

    __get_atom_name_A_arguments = [
        FunctionParam('nAtom', FunctionParam.NUMBER),
        FunctionParam('lpBuffer', FunctionParam.STRING),
        FunctionParam('nSize', FunctionParam.NUMBER)
    ]

    def __get_atom_name_A(self, nAtom, lpBuffer, nSize):
        #TODO
        return self.__wrap_results(0, FunctionParam.NUMBER)
        
    __malloc_arguments = [
        FunctionParam('size_t', FunctionParam.NUMBER)
    ]

    def __malloc(self, size_t):
        return self.__wrap_results('00'*size_t, FunctionParam.BYTES)
