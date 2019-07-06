class Instruction:
    def __init__(self, content):
        self.address = content.get('offset', '')
        self.esil = content.get('esil', '')
        self.asm = content.get('disasm', '')

    def get_operation(self):
        return self.asm.split()[0] if self.asm else None

    def get_params(self):
        return self.asm.split()[1:]

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