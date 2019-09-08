import r2pipe

import emulator_objects as emo
from api.parameters import *
import utilities as util

class Emulator:
    def __init__(self, file, memory, api, output):
        self.__rel_table = None
        self.__instruction = None
        self.__last_instruction = None
        self.__r2 = r2pipe.open(file)
        self.__memory_stack = memory
        self.__api = api
        self.__output = output
        self.__emulation_finished = False

        self.__set_environment()
        self.__set_relocations_table()
        self.__get_last_instruction()

    def __set_environment(self):
        self.__r2.cmd('aaaa')
        self.__r2.cmd('e asm.emu=true')
        self.__r2.cmd('e io.cache=true')
        self.__r2.cmd('e esil.stack.depth=64')
        self.__r2.cmd('aeim {m.address} {m.size}'.format(m=self.__memory_stack))

    def __set_relocations_table(self):
        relocations = self.__r2.cmdj('irj')
        self.__rel_table = emo.RelocationTable(relocations)

    def __get_instruction(self):
        data = self.__r2.cmdj('pdj 1 @eip')[0]
        self.__instruction = emo.Instruction(data)

    def __get_last_instruction(self):
        data = self.__r2.cmdj('pdfj')['ops'][-1]
        self.__last_instruction = emo.Instruction(data)

    def __get_current_address(self):
        return self.__instruction.address

    def __get_register(self, register):
        return self.__r2.cmd(f'aer {register}').strip()

    def __set_register(self, register, value):
        if type(value) == bytes: value = value.hex()        
        self.__r2.cmd(f'aer {register}={value}')

    def __write_bytes(self, string, address):
        if type(string) == bytes: string = string.hex()
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
        else:
            self.__r2.cmd('aes')

    def __inform_step(self):
        params = self.__instruction.get_params()
        if self.__instruction.is_call():
            self.__output.write_call(params)
        elif self.__instruction.is_return():
            self.__output.write_return()

    def __emulate_function(self, function_name):
        arguments, results = [], []
        if self.__api.contains_function(function_name):
            arguments = self.__api.get_function_arguments(function_name)
            arguments = self.__fill_function_arguments(arguments)
            results = self.__api.emulate_function(function_name, arguments)
            self.__apply_function_results(results)
        self.__output.write_reallocated_call(function_name, arguments)
        self.__execute_return()
        self.__output.write_return(results)

    def __apply_function_results(self, results):
        for result in results:
            target, typed = result.target, result.typed
            if typed == FunctionResult.EXIT_PROCESS:
                self.__emulation_finished = True
                continue
            if result.to_reference:
                if typed == FunctionResult.NUMBER:
                    result.value = self.__memory_stack.malloc(result.value)
                elif typed == FunctionResult.BYTES:
                    size = len(result.value)
                    address = self.__memory_stack.malloc(size)
                    self.__write_bytes(result.value, address)
                    result.value = address
                typed = 'address'
            if util.is_address(target):
                self.__write_bytes(result.value, target)
            else:
                self.__set_register(target, result.value)

    def __execute_return(self):
        self.__r2.cmd('ae esp,[4],eip,=,4,esp,+=')
        eip = self.__get_register('eip')
        self.__r2.cmd('aepc '+eip)

    def __fill_function_arguments(self, arguments):
        esp = int(self.__get_register('esp'), 16)
        for i in range(len(arguments)):
            address = esp+4 + 4*i
            value = self.__get_value_from_address(address)
            typed = arguments[i].typed
            if typed == FunctionArgument.STRING:
                value = self.__get_string_from_address(value)
            elif typed == FunctionArgument.POINTED_VALUE:
                value = self.__get_value_from_address(value)
            elif typed == FunctionArgument.NUMBER:
                value = int(value, 16)
            arguments[i].value = value
        return arguments

    def setup_tcp_server(self, port):
        self.__r2.cmd(f'& .:{port}')

    def run(self):
        while not self.__emulation_finished:
            self.__get_instruction()
            self.__step()
            self.__inform_step()
            if self.__get_current_address() == self.__last_instruction.address:
                self.__emulation_finished = True
