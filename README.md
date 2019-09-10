```
 ____  ___  _  _       ____  __  __  _   _  _    _____  _______  _____  _____
|  __||  _|| || |     |  __||  \/  || | | || |  |  _  ||__   __||  _  ||  _  |
| |_  | |_ | || |     | |_  |      || | | || |  | |_| |   | |   | | | || |_| |
|  _| |_  || || |     |  _| | |\/| || | | || |  |  _  |   | |   | | | ||    _|
| |__  _| || || |_    | |__ | |  | || |_| || |_ | | | |   | |   | |_| || |\ \
|____||___||_||___|   |____||_|  |_||_____||___||_| |_|   |_|   |_____||_| \_|

```

# Introduction

This tool has been made to emulate completely a binary executable file, through ESIL and the Radare2 engine. Although ESIL emulation already exists, that usually doesn’t finish because of the following main reasons:
- Libraries and APIs loaded dynamically.
- Syscalls not executed, so its results not applied.

# Requirements

The following requirements must be covered to run this tools:
- Python 3.6+
- r2pipe (can be installed through pip)
- Radare2
- UPX packer
- GNU/Linux Host

# Execution

The entry file to run that tool is *main.py*, which can be executed with the following format and arguments:

```
usage: main.py [-h] [-p PORT] file

Emulate an executable binary with ESIL & Radare2

positional arguments:
  file        the executable binary to emulate

optional arguments:
  -h, --help  show this help message and exit
  -p PORT     it runs a tcp server which listens on this port  
```

# Improvements

There are some possible implementations which would improve the tool to achieve that more and more executable files could finish the emulation, without reach invalid memory addresses or keep in infinite loops.

However, the main way to improve this tool is implementing more API functionalities. It’s possible to just implement functions of one already existing API in the *api/* folder or create another API class and load this in the *main.py* file.
