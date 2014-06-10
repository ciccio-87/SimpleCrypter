CC=i586-mingw32msvc-gcc
CPPC=i586-mingw32msvc-g++
OBJCOPY=objcopy --input binary --output elf32-i386 --binary-architecture i386

all: hypwrite loader

loader: loader.o c_des.o utils.o pass_pe.o enc_win_pe.o
	$(CPPC) loader.o c_des.o utils.o pass_pe.o enc_win_pe.o -o loader.exe

c_des.o: c_des.c
	$(CC) -c c_des.c -o c_des.o

utils.o: utils.c c_des.o
	$(CC) -c utils.c c_des.o -o utils.o

loader.o: loadEXE.cpp
	$(CPPC) -c loadEXE.cpp -o loader.o

enc_win_pe.o: enc_win
	$(OBJCOPY) enc_win enc_win_pe.o
	
pass_pe.o: pass
	$(OBJCOPY) pass pass_pe.o
	
hypwrite: hypwrite.c c_des.o utils.o
	$(CC) hypwrite.c c_des.o utils.o -o hypwrite.exe

clean:
	rm -rf *o loader.exe hypwrite.exe