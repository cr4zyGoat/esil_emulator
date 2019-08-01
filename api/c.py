from api.base import ApiBase
from api.parameters import *

class CApi(ApiBase):
    def __init__(self):
        super().__init__()
        self._add_functions({
            'malloc': [self.__malloc, self.__malloc_arguments],
            'printf': [self.__printf, self.__printf_arguments],
            'strlen': [self.__strlen, self.__strlen_arguments],
            'strncmp': [self.__strncmp, self.__strncmp_arguments]
        })

    __malloc_arguments = [
        FunctionArgument('size_t', FunctionArgument.NUMBER)
    ]

    def __malloc(self, size_t):
        result = FunctionResult(size_t, FunctionResult.NUMBER, to_reference=True)
        return self._wrap_results(result)

    __printf_arguments = [
        FunctionArgument('format', FunctionArgument.STRING)
    ]

    def __printf(self, format):
        result = FunctionResult(len(format), FunctionArgument.NUMBER)
        return self._wrap_results(result)

    __strlen_arguments = [
        FunctionArgument('string', FunctionArgument.STRING)
    ]

    def __strlen(self, string):
        result = FunctionResult(len(string), FunctionArgument.NUMBER)
        return self._wrap_results(result)

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
        return self._wrap_results(result)
