from api.base import ApiBase
from api.parameters import *

class HeapApi(ApiBase):
    def __init__(self):
        super().__init__()
        self._add_functions({
            'HeapAlloc': [self.__heap_alloc, self.__heap_alloc_arguments],
        })

    __heap_alloc_arguments = [
        FunctionArgument('hHeap', FunctionArgument.ADDRESS),
        FunctionArgument('dwFlags', FunctionArgument.NUMBER),
        FunctionArgument('dwBytes', FunctionArgument.NUMBER)
    ]

    def __heap_alloc(self, hHeap, dwFlags, dwBytes):
        result = FunctionResult(dwBytes, FunctionResult.NUMBER, to_reference=True)
        return self._wrap_results(result)
