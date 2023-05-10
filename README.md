# Gadget-Planner

Gadget-Planner is a research protoype tool to construct code-reuse gadget chains on binary file, especially on obfuscated programs.

## Pre-requisites:
1. Gadget-Planner is written in Python3.6. All dependencies can be found in *requirements.txt* and installed throguth local environment or a python virtual environment.
2. *angr-dev* needs to install for development. [Link](https://github.com/angr/angr-dev)

## How to run:
1. Set the target of the plan in "\tools\planning.py", the name of the exploit and the values of each needed register.
For example:
            targets = {
                'execve': {'rax': 57,
                        'rdi': 160256,
                        'rsi': Pointer(0),
                        'rdx': Pointer(0)
                        },
            }
2. Run the program by following command: "python3 main.py /path/to/target/binary --fancy"

## Benchmark:
The Benchmark folder contains the testing programs that can be obfuscated by Obfuscator-LLVM and Tigress.


