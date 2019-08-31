import utilities as util

class Instruction:
    def __init__(self, content):
        self.address = content.get('offset', '')
        self.esil = content.get('esil', '')
        self.asm = content.get('disasm', '')
        self.type = content.get('type', '')

        self.__operation = self.asm.split()[0] if self.asm else None

    def get_operation(self):
        return self.__operation

    def get_params(self):
        return self.asm.split()[1:]

    def is_valid(self):
        return self.type == 'invalid'

    def is_call(self):
        return self.get_operation() == 'call'

    def is_return(self):
        return self.get_operation() == 'ret'

    def is_comparison(self):
        return util.is_comparison(self.get_operation())

class Relocation:
    def __init__(self, content):
        self.name = content.get('name', '')
        self.type = content.get('type', '')
        self.vaddr = content.get('vaddr', '')
        self.paddr = content.get('paddr', '')

    def get_function_name(self):
        return self.name.split('_')[-1]

class RelocationTable:
    def __init__(self, relocations):
        self.__imports = {}
        for item in relocations:
            item = Relocation(item)
            self.__imports[item.vaddr] = item

    def contains_vaddr(self, vaddr):
        return vaddr in self.__imports

    def get_relocation(self, vaddr):
        return self.__imports[vaddr]
