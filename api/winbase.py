from api.base import ApiBase
from api.parameters import *
from api import winbase_objects as wbo

class WinBase(ApiBase):
    def __init__(self):
        super().__init__()
        self.__atoms_table = wbo.AtomsTable()
        self._add_functions({
            'AddAtomA': [self.__add_atom_A, self.__add_atom_A_arguments],
            'FindAtomA': [self.__find_atom_A, self.__find_atom_A_arguments],
            'GetAtomNameA': [self.__get_atom_name_A, self.__get_atom_name_A_arguments]
        })

    __add_atom_A_arguments = [
        FunctionArgument('lpString', FunctionArgument.STRING)
    ]

    def __add_atom_A(self, lpString):
        atom = self.__atoms_table.add_atom(lpString)
        result = FunctionResult(atom, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __find_atom_A_arguments = [
        FunctionArgument('lpString', FunctionArgument.STRING)
    ]

    def __find_atom_A(self, lpString):
        atom = self.__atoms_table.find_atom(lpString)
        result = FunctionResult(atom, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __get_atom_name_A_arguments = [
        FunctionArgument('nAtom', FunctionArgument.NUMBER),
        FunctionArgument('lpBuffer', FunctionArgument.ADDRESS),
        FunctionArgument('nSize', FunctionArgument.NUMBER)
    ]

    def __get_atom_name_A(self, nAtom, lpBuffer, nSize):
        string = self.__atoms_table.find_string(nAtom)
        string = string.encode()[:nSize].strip(b'\x00')
        return self._wrap_results([
            FunctionResult(len(string), FunctionResult.NUMBER),
            FunctionResult(string, FunctionResult.BYTES, target=lpBuffer)
        ])
