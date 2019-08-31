from api.base import ApiBase
from api.parameters import *

class Processthreadsapi(ApiBase):
    def __init__(self):
        super().__init__()
        self._add_functions({
            'ExitProcess': [self.__exit_process, self.__exit_process_arguments],
        })

    __exit_process_arguments = [
        FunctionArgument('uExitCode', FunctionArgument.NUMBER)
    ]

    def __exit_process(self, uExitCode):
        result = FunctionResult(uExitCode, FunctionResult.EXIT_PROCESS)
        return self._wrap_results(result)
