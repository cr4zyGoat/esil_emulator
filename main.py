#!/usr/bin/python3

import sys, r2pipe

from api import Api
from api_classes import FunctionParam
from classes import Instruction, RelocationTable, MemoryStack

class Emulator:
    def __init__(self, file, memory, api):
        self.__rel_table = None
        self.__instruction = None
        self.__last_instruction = None
        self.__r2 = r2pipe.open(file)
        self.__memory_stack = memory
        self.__api = api

        self.__set_environment()
        self.__set_relocations_table()
        self.__get_instruction()
        self.__get_last_instruction()

    def __set_environment(self):
        self.__r2.cmd('aaa')
        self.__r2.cmd('e asm.emu=true')
        self.__r2.cmd('e asm.esil=true')
        self.__r2.cmd('e io.cache=true')
        self.__r2.cmd('e esil.stack.depth=64')
        self.__r2.cmd('s main')
        self.__r2.cmd('aei')
        self.__r2.cmd('aeim {m.address} {m.size}'.format(m=self.__memory_stack))
        self.__r2.cmd('aeip')

    def __set_relocations_table(self):
        relocations = self.__r2.cmdj('irj')
        self.__rel_table = RelocationTable(relocations)

    def __get_instruction(self):
        data = self.__r2.cmdj('pdj 1 @eip')[0]
        self.__instruction = Instruction(data)

    def __get_last_instruction(self):
        data = self.__r2.cmdj('pdfj')['ops'][-1]
        self.__last_instruction = Instruction(data)

    def __get_current_address(self):
        return self.__instruction.address

    def __get_register(self, register):
        return self.__r2.cmd(f'aer {register}').strip()

    def __set_register(self, register, value):
        self.__r2.cmd(f'aer {register}={value}')

    def __write_bytes(self, string, address):
        self.__r2.cmd(f'wx {string} @{address}')

    def __get_value_from_address(self, address):
        return self.__r2.cmd(f'pf x @{address}').split()[-1]

    def __get_string_from_address(self, address):
        return self.__r2.cmd(f'ps @{address}').strip()

    def __step(self):
        address = self.__get_current_address()
        if self.__rel_table.contains_vaddr(address):
            function = self.__rel_table.get_relocation(address).get_function_name()
            self.__emulate_function(function)
            self.__execute_return()
            print(f"\treturn to @{self.__get_register('eip')}")
        else:
            self.__r2.cmd('aes')
        if self.__instruction.get_operation() == 'call':
            print('{ci.asm}: from address @{ci.address} to @{ca}'
                .format(ci=self.__instruction, ca=self.__get_register('eip')))

    def __emulate_function(self, function_name):
        print(f'emulating function {function_name}:')
        if self.__api.contains_function(function_name):
            arguments = self.__api.get_function_arguments(function_name)
            arguments = self.__fill_function_arguments(arguments)
            for arg in arguments: print(f'\t{arg.name} = {arg.value}')
            results = self.__api.emulate_function(function_name, arguments)
            self.__apply_function_results(results)

    def __apply_function_results(self, result):
        value = result.value
        typed = result.typed
        if typed == FunctionParam.BYTES:
            nbytes = len(value)/2
            address = self.__memory_stack.malloc(nbytes)
            self.__write_bytes(value, address)
            value = address
        self.__set_register(result.name, value)
        print(f'\tresult: {value}')

    def __execute_return(self):
        self.__r2.cmd('ae esp,[4],eip,=,4,esp,+=')
        self.__refresh_program_counter()

    def __refresh_program_counter(self):
        eip = self.__get_register('eip')
        self.__r2.cmd('aepc '+eip)

    def __fill_function_arguments(self, params):
        esp = int(self.__get_register('esp'), 16)
        for i in range(len(params)):
            address = esp+4 + 4*i
            value = self.__get_value_from_address(address)
            typed = params[i].typed
            if typed == FunctionParam.STRING:
                value = self.__get_string_from_address(value)
            if typed == FunctionParam.NUMBER:
                value = int(value, 16)
            params[i].value = value
        return params

    def run(self):
        while self.__get_current_address() != self.__last_instruction.address:
            self.__step()
            self.__get_instruction()
    

if __name__ == "__main__":
    executable = sys.argv[1]
    api = Api()
    memory = MemoryStack(0x100000, 0xf0000)
    emulator = Emulator(executable, memory, api)
    emulator.run()
