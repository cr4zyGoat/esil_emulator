#!/usr/bin/python3

import argparse

from memory import Memory
from emulator import Emulator
from output import Output
from api.container import ApiContainer
from api import winbase, processthreadsapi, c

def get_arguments():
    parser =  argparse.ArgumentParser(description='Emulate an executable binary with ESIL & Radare2')
    parser.add_argument('file', type=str, help='the executable binary to emulate')
    parser.add_argument('-p', type=int, dest='port', help='it runs a tcp server which listens on this port')
    return parser.parse_args()


if __name__ == "__main__":

    args = get_arguments()

    api_container = ApiContainer()
    api_container.load_api(winbase.WinBase())
    api_container.load_api(processthreadsapi.Processthreadsapi())
    api_container.load_api(c.CApi())

    memory = Memory(0x100000, 0xf0000)
    output = Output()

    emulator = Emulator(args.file, memory, api_container, output)

    if args.port:
        emulator.setup_tcp_server(args.port)

    emulator.run()
