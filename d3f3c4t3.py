#!/usr/bin/env python
#-*-encoding:utf-8-*-

# d3f3c4t3: convert C/ASM/Binary program to shellcode
# by okb

from __future__ import print_function
import argparse
import time
import sys
import os

class ObjdumpParser:
	""" Parse objdump result """

	def __init__(self, dump):
		self.dump = dump
		self.functions = {}

	def run(self):
		function = ""
		for line in self.dump.splitlines():
			if line == "":
				function = ""
			elif "..." in line:
				continue
			elif line.startswith(" "):
				bytecode = line.split("\t")[1].strip()
				for _byte in bytecode.split(" "):
					self.functions[function] += chr(int(_byte, base=16))
			elif line.startswith("0"):
				identifier = line.split(" ")[1]
				function = identifier[identifier.index("<")+1:identifier.index(">")]
				self.functions[function] = ""

def build_parser():
	""" Build argument parser """
	parser = argparse.ArgumentParser(description="Convert C/ASM/Binary program to shellcode")
	parser.add_argument("file", 
		type=str, 
		help="path to C program")
	parser.add_argument("-f", "--function", 
		type=str, default="main",
		help="select function to convert (all functions are converted by default)")
	parser.add_argument("-i", "--input-format",
		type=int, default=0, choices=[0, 1, 2],
		help="select input format (0: C source 1: Assembly source 2: Raw binary) (default: 0)")
	parser.add_argument("-F", "--output-format", 
		type=int, default=0, choices=[0, 1, 2],
		help="select shellcode format (0: C char array 1: Raw hex 2: Raw binary) (default: 0)")
	parser.add_argument("-o", "--output",
		type=str, default="/dev/stdout",
		help="path to output (default: /dev/stdout)")
	parser.add_argument("-c", "--compiler",
		type=str, default="gcc",
		help="choose compiler")
	parser.add_argument("-O", "--extra-options",
		type=str, default="",
		help="add compiler extra options")	
	parser.add_argument("-v", "--variable",
		type=str, default="payload",
		help="change var name of C char array format (default: payload)")
	parser.add_argument("-e", "--embed",
		action="store_true",
		help="embed C char array into shellcode executer program")
	return parser

def file_type(path):
	""" Return file type """
	return os.popen("file {path}".format(path=path)).read().split(":")[1].strip()

def detect(compiler):
	""" Check if compiler exists """
	env = os.getenv("PATH") + ":{pwd}/".format(pwd=os.getcwd())
	for directory in env.split(":"):
		if os.path.exists(os.path.join(directory, compiler)):
			return True
	return False

def objdump(path):
	""" Run objdump """
	return os.popen("objdump -D {path}".format(path=path)).read()

def build(compiler, path, options):
	""" Compile source """
	tmp = "build.{ts}.out".format(ts=time.time())
	os.popen("{compiler} {options} -o {path_1} {path_2}".format(compiler=compiler, options=options, path_1=tmp, path_2=path))
	return tmp

def build_assembly(compiler, path, options):
	""" Compile Assembly source """
	tmp = build(compiler, path, options)
	if compiler == "gcc":
		return tmp+".elf"	
	os.popen("ld -o {result} {tmp}".format(result=tmp+".elf", tmp=tmp))
	return tmp+".elf"

def error(prompt):
	""" Print error and quit """
	print("error: {prompt}".format(prompt=prompt))
	exit(1)

# Parse arguments
args = build_parser().parse_args()

# Check files
if not os.path.exists(args.file):
	error("cannot find input file {path}".format(path=args.file))
if not detect(args.compiler):
	error("cannot find compiler {compiler}".format(compiler=args.compiler))

# Compile and dump
if args.input_format == 0 and "ASCII" in file_type(args.file):
	output = build(args.compiler, args.file, args.extra_options)
elif args.input_format == 1 and "ASCII" in file_type(args.file):
	output = build_assembly(args.compiler, args.file, args.extra_options)
elif args.input_format == 2 and "ELF" in file_type(args.file):
	output = args.file
else:
	error("file type detection and input format doesnt match")

dump = objdump(output)

if args.input_format != 2:
	os.remove(output)

# Parse
o_parser = ObjdumpParser(dump)
o_parser.run()

if not args.function in o_parser.functions.keys():
	error("{function} function not detected".format(function=args.function))

# Format result
if args.output_format == 0:
	result = "char {var}[] = ".format(var=args.variable) + "{"
else:
	result = ""
for character in o_parser.functions[args.function]:
	if args.output_format == 0:
		result = result + hex(ord(character)) + ","
	elif args.output_format == 1:
		result += format(ord(character), "02x")
	else:
		result += character
if args.output_format == 0:
	result = result[:-1] + "}"
result += "\n"

# Embed array
if args.embed:
	result += "\nint main() {\n"
	result += "\tint (*function)();\n"	
	result += "\tfunction = (int (*)()) {variable};\n".format(variable=args.variable)
	result += "\t(int)(*function)();\n"
	result += "}\n"

# Write result to output
with open(args.output, "wb") as handler:
	handler.write(result)


