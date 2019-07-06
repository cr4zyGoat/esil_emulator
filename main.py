#!/usr/bin/python3

import sys, r2pipe

from apis import Api, FunctionParam
from classes import Instruction, RelocationTable

class Emulator:
    def __init__(self, file, api):
        self.__rel_table = None
        self.__instruction = None
        self.__r2 = r2pipe.open(file)
        self.__api = api

        self.__set_environment()
        self.__set_relocations_table()
        self.__get_instruction()

    def __set_environment(self):
        self.__r2.cmd('aaa')
        self.__r2.cmd('e asm.emu=true')
        self.__r2.cmd('e asm.esil=true')
        self.__r2.cmd('e io.cache=true')
        self.__r2.cmd('s main')
        self.__r2.cmd('aei')
        self.__r2.cmd('aeim')
        self.__r2.cmd('aeip')

    def __set_relocations_table(self):
        relocations = self.__r2.cmdj('irj')
        self.__rel_table = RelocationTable(relocations)

    def __get_instruction(self):
        data = self.__r2.cmdj('pdj 1 @eip')[0]
        self.__instruction = Instruction(data)

    def __get_current_address(self):
        return self.__instruction.address

    def __get_register(self, register):
        return self.__r2.cmd('aer '+register).strip()

    def __get_value_from_address(self, address):
        return self.__r2.cmd('pf x @'+str(address)).split()[-1]

    def __get_string_from_address(self, address):
        return self.__r2.cmd('ps @'+str(address)).strip()

    def __step(self):
        address = self.__get_current_address()
        if self.__rel_table.contains_vaddr(address):
            function = self.__rel_table.get_relocation(address).get_function_name()
            self.__emulate_function(function)
            self.__execute_return()
        else:
            self.__r2.cmd('aes')
        if self.__instruction.get_operation() == 'call':
            print(self.__instruction.asm+': address @'+self.__get_register('eip'))
        self.__get_instruction()

    def __emulate_function(self, function_name):
        print('emulating function '+function_name+':')
        if self.__api.contains_function(function_name):
            arguments = self.__api.get_function_arguments(function_name)
            arguments = self.__fill_function_arguments(arguments)
            for arg in arguments: print('\t'+arg.name+' = '+arg.value)
            self.__api.emulate_function(function_name, arguments)

    def __execute_return(self):
        self.__r2.cmd('ae esp,[4],eip,=,4,esp,+=')
        self.__refresh_program_counter()

    def __refresh_program_counter(self):
        eip = self.__get_register('eip')
        self.__r2.cmd('aepc '+eip)
        print('\treturn to @'+eip)

    def __fill_function_arguments(self, params):
        esp = int(self.__get_register('esp'), 16)
        for i in range(len(params)):
            address = esp+4 + 4*i
            value = self.__get_value_from_address(address)
            if params[i].typed == FunctionParam.STRING:
                value = self.__get_string_from_address(value)
            params[i].value = value
        return params

    def run(self):
        while self.__instruction.asm != 'ret':
            self.__step()
            self.__get_instruction
    

if __name__ == "__main__":
    executable = sys.argv[1]
    api = Api()
    emulator = Emulator(executable, api)
    emulator.run()
