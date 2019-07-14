from api_classes import FunctionArgument, FunctionResult
from api_classes import AtomsTable

class Api:
    def __init__(self):
        self.__atoms_table = AtomsTable()
        self.__functions = {
            'AddAtomA': [self.__add_atom_A, self.__add_atom_A_arguments],
            'FindAtomA': [self.__find_atom_A, self.__find_atom_A_arguments],
            'GetAtomNameA': [self.__get_atom_name_A, self.__get_atom_name_A_arguments],
            'malloc': [self.__malloc, self.__malloc_arguments],
            'printf': [self.__printf, self.__printf_arguments],
            'strlen': [self.__strlen, self.__strlen_arguments],
            'strncmp': [self.__strncmp, self.__strncmp_arguments]
        }

    def contains_function(self, function_name):
        return function_name in self.__functions

    def get_function_arguments(self, function_name):
        return self.__functions[function_name][1]

    def emulate_function(self, function_name, arguments):
        args = map(lambda p: p.value, arguments)
        return self.__functions[function_name][0](*args)

    def __wrap_results(self, results):
        return results if type(results) == list else [results]

    __add_atom_A_arguments = [
        FunctionArgument('lpString', FunctionArgument.STRING)
    ]

    def __add_atom_A(self, lpString):
        atom = self.__atoms_table.add_atom(lpString)
        result = FunctionResult(atom, FunctionResult.NUMBER)
        return self.__wrap_results(result)

    __find_atom_A_arguments = [
        FunctionArgument('lpString', FunctionArgument.STRING)
    ]

    def __find_atom_A(self, lpString):
        atom = self.__atoms_table.find_atom(lpString)
        result = FunctionResult(atom, FunctionResult.NUMBER)
        return self.__wrap_results(result)

    __get_atom_name_A_arguments = [
        FunctionArgument('nAtom', FunctionArgument.NUMBER),
        FunctionArgument('lpBuffer', FunctionArgument.ADDRESS),
        FunctionArgument('nSize', FunctionArgument.NUMBER)
    ]

    def __get_atom_name_A(self, nAtom, lpBuffer, nSize):
        string = self.__atoms_table.find_string(nAtom)
        string = string.encode()[:nSize].strip(b'\x00')
        return self.__wrap_results([
            FunctionResult(len(string), FunctionResult.NUMBER),
            FunctionResult(string, FunctionResult.BYTES, target=lpBuffer)
        ])
        
    __malloc_arguments = [
        FunctionArgument('size_t', FunctionArgument.NUMBER)
    ]

    def __malloc(self, size_t):
        result = FunctionResult(size_t, FunctionResult.NUMBER, to_reference=True)
        return self.__wrap_results(result)

    __printf_arguments = [
        FunctionArgument('format', FunctionArgument.STRING)
    ]

    def __printf(self, format):
        result = FunctionResult(len(format), FunctionArgument.NUMBER)
        return self.__wrap_results(result)

    __strlen_arguments = [
        FunctionArgument('string', FunctionArgument.STRING)
    ]

    def __strlen(self, string):
        result = FunctionResult(len(string), FunctionArgument.NUMBER)
        return self.__wrap_results(result)

    __strncmp_arguments = [
        FunctionArgument('str1', FunctionArgument.STRING),
        FunctionArgument('str2', FunctionArgument.STRING),
        FunctionArgument('num', FunctionArgument.NUMBER)
    ]

    def __strncmp(self, str1, str2, num):
        str1 = str1[:num]
        str2 = str2[:num]
        if str1 < str2: result = FunctionResult(-1, FunctionResult.NUMBER)
        elif str1 > str2: result = FunctionResult(1, FunctionResult.NUMBER)
        else: result = FunctionResult(0, FunctionResult.NUMBER)
        return self.__wrap_results(result)
