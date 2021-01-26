# CodeCrusher
Tool that convert C/ASM/Binary program into shellcode.

## Requirements
- objdump
- C compiler (ex: gcc)

## Usage
```
usage: crusher.py [-h] [-f FUNCTION] [-i {0,1,2}] [-F {0,1,2}] [-o OUTPUT]
                   [-c COMPILER] [-O EXTRA_OPTIONS] [-v VARIABLE] [-e]
                   file

Convert C/ASM/Binary program to shellcode

positional arguments:
  file                  path to C program

optional arguments:
  -h, --help            show this help message and exit
  -f FUNCTION, --function FUNCTION
                        select function to convert (main function is converted
                        by default)
  -i {0,1,2}, --input-format {0,1,2}
                        select input format (0: C source 1: Assembly source 2:
                        Raw binary) (default: 0)
  -F {0,1,2}, --output-format {0,1,2}
                        select shellcode format (0: C char array 1: Raw hex 2:
                        Raw binary) (default: 0)
  -o OUTPUT, --output OUTPUT
                        path to output (default: /dev/stdout)
  -c COMPILER, --compiler COMPILER
                        choose compiler
  -O EXTRA_OPTIONS, --extra-options EXTRA_OPTIONS
                        add compiler extra options
  -v VARIABLE, --variable VARIABLE
                        change var name of C char array format (default:
                        payload)
  -e, --embed           embed C char array into shellcode executer program
```
