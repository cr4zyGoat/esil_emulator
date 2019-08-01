class Memory:
    def __init__(self, address, size):
        self.size = size
        self.address = address
        self.__free_address = address
        
    def malloc(self, size):
        pointer = self.__free_address
        self.__free_address += size
        return pointer
