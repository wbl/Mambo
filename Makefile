CC= clang-mp-3.2 -march=core2 -g
CFLAGS=-std=c99 -O3  -Wall -Wextra -emit-llvm
all: time test test_crypt time_crypt
.PHONY: all
time: impl.o time.o
test: impl.o test.o
test_crypt: encrypt.o impl.o test_crypt.o
time_crypt: encrypt.o impl.o time_crypt.o
