CC=x86_64-w64-mingw32-gcc
OBJCOPY=x86_64-w64-mingw32-objcopy
CFLAGS=-O2 -Wall -Wextra -ffreestanding -fno-builtin -fno-tree-loop-distribute-patterns -fno-asynchronous-unwind-tables -fno-unwind-tables -fno-exceptions -fno-stack-protector -mno-stack-arg-probe

.PHONY: all clean

all: cdptk_bof.o cdptk-c.exe

cdptk_bof.o: cdptk_bof.c beacon.h
	$(CC) $(CFLAGS) -DBOF -c -o $@ cdptk_bof.c -I .
	$(OBJCOPY) --remove-section .pdata --remove-section .xdata --remove-section .eh_frame $@

cdptk-c.exe: cdptk_bof.c
	$(CC) -O2 -Wall -Wextra -o $@ cdptk_bof.c -lwinhttp -lcrypt32

clean:
	rm -f cdptk_bof.o cdptk-c.exe
