#!/usr/bin/python3

#TODO: also don't patch if the first instructions of the function use r11

import os
import sys
import r2pipe
import json

if (len(sys.argv) - 1 != 1):
	print("Pass a binary to generate fuzzing code!")
	exit(-1)

# Initialization	
r = r2pipe.open(sys.argv[1])
r.cmd("aaa")
functions = r.cmdj("aflj")

# Get the address of the .text section
sections = r.cmdj("iSj")
text_addr = 0

for section in sections:
	if section["name"] == ".text":
		text_addr=int(section["paddr"])

# Get all basic blocks and write them into a file which gets compiled
# into the fuzzer program
bbs = []
entry_bb = []
for function in functions:
	blocks = r.cmdj("afbj " + str(function["offset"]))
	print(function["name"])
	
	for bb in blocks:
		if int(bb["addr"]) >= text_addr and text_addr <= int(bb["addr"]) + int(bb["size"]):
			bbs += [hex(int(bb["addr"]))]
			
			if int(bb["addr"]) == int(function["offset"]):
				print("\t[t][e] BB @ " + hex(int(bb["addr"])))
				entry_bb += [True]
			else:
				print("\t[t][n] BB @ " + hex(int(bb["addr"])))
				entry_bb += [False]
		else:
			print("\t[n][n] BB @ " + hex(int(bb["addr"])))

# Subtract .text address from the basic block addresses	
for i in range(0,len(bbs)):
	bbs[i] = str(hex(int(bbs[i], 16) - text_addr))

# Create the C header file
f_c = open("bb.h", "w")
f_c.write("#pragma once\n")
f_c.write("#define BINARY_PATH \"./" + sys.argv[1] + "\"\n");
f_c.write("#define BB_COUNT " + str(len(bbs)) + "\nunsigned char bb_patched_byte[BB_COUNT];\nunsigned long bb_addr[BB_COUNT]={\n")

for bb in bbs:
	f_c.write(bb + ",\n")
	
# Create the asm source file. It contains section definitions for libfuzzer.
f_asm = open("bb.S", "w")

# PC table
# M: mergable section. Set entsize (character size) to size of whole section since linker might remove duplicate entries.
f_asm.write(".section __sancov_pcs , \"awM\", @progbits, " + str(len(bbs) * 8) + "\n");
f_asm.write(".globl __start__sancov_pcs\n");
f_asm.write("__start__sancov_pcs:\n");

for i in range(0, len(bbs)):
	f_asm.write(".quad 0\n")
	if entry_bb[i]:
		f_asm.write(".quad 1\n")
	else:
		f_asm.write(".quad 0\n")
		
f_asm.write(".globl __stop__sancov_pcs\n");
f_asm.write("__stop__sancov_pcs:\n");

# 8-bit counters
# M: mergable section. Set entsize (character size) to size of whole section since linker might remove duplicate entries.
f_asm.write(".section __sancov_bools , \"awM\", @progbits, " + str(len(bbs)) + "\n");
f_asm.write(".globl __start__sancov_bools\n");
f_asm.write("__start__sancov_bools:\n");

for i in range(0, len(bbs)):
	f_asm.write(".byte 0\n")

f_asm.write(".globl __stop__sancov_bools\n");
f_asm.write("__stop__sancov_bools:\n");

# Cleanup
f_c.write("};\n")
f_c.close()
