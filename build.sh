#!/bin/bash

rm -rf build
mkdir build

echo "Using binary: $1"
echo "Using Clang path: $2"

./build.py $1

clang -Wall patch_elf.c -o build/patch_elf
cp $1 build/$(basename -- "$1")
cd build
echo "Patching ELF: $(basename -- "$1")"
./patch_elf $(basename -- "$1")
echo "Done"
cd ..

#-fsanitize=fuzzer
$2 -g -O1 -I./ -c main.c -o build/main.o
$2 -c bb.S -o build/bb.o
$2 -fsanitize=fuzzer build/main.o build/bb.o -o build/fuzz -ldl -v

# Testing the build: TODO: remove this
echo "Now testing the build:"
cd build
./fuzz
cd ..
