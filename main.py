#!/usr/bin/python3

import argparse, os

from memory import Memory
from emulator import Emulator
from output import Output
from api.container import ApiContainer
from api import winbase, processthreadsapi, heapapi, c


def get_arguments():
    parser =  argparse.ArgumentParser(description='Emulate an executable binary with ESIL & Radare2')
    parser.add_argument('file', type=str, help='the executable binary to emulate')
    parser.add_argument('-p', type=int, dest='port', help='it runs a tcp server which listens on this port')
    return parser.parse_args()


def unpack(filename):
    if 'UPX' in os.popen(f'file {filename}').read():
        i = filename.rfind('.')
        new_file = f'{filename[:i]}_unpacked{filename[i:]}'
        os.system(f'upx -d {filename} -o {new_file}')
        filename = new_file
    return filename


if __name__ == "__main__":

    args = get_arguments()
    output = Output()

    api_container = ApiContainer()
    api_container.load_api(winbase.WinBase())
    api_container.load_api(processthreadsapi.Processthreadsapi())
    api_container.load_api(c.CApi())
    api_container.load_api(heapapi.HeapApi())

    output.write_title('unpacking')
    executable = unpack(args.file)

    memory = Memory(0x100000, 0xf0000)
    emulator = Emulator(executable, memory, api_container, output)

    if args.port:
        emulator.setup_tcp_server(args.port)

    output.write_title('beginning the emulation')
    emulator.run()
    output.write_title('emulation done')
