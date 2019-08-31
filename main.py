#!/usr/bin/python3

import sys

from memory import Memory
from emulator import Emulator
from output import Output
from api.container import ApiContainer
from api import winbase, processthreadsapi, c


if __name__ == "__main__":
    executable = sys.argv[1]

    api_container = ApiContainer()
    api_container.load_api(winbase.WinBase())
    api_container.load_api(processthreadsapi.Processthreadsapi())
    api_container.load_api(c.CApi())

    memory = Memory(0x100000, 0xf0000)
    output = Output()

    emulator = Emulator(executable, memory, api_container, output)

    emulator.run()
