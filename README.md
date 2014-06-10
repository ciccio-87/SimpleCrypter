SimpleCrypter
=============

A simple/PoC Hyperion quasi-clone


Just another loader/crypter, using the CREATE_SUSPENDED techique and an Hyperion-like
approach for crypting, binding of the crypt file is done through objcopy, but it should
work directly from file (iexpress bound?) with few modifications.

The loader is a slightly modified version of loadEXE, which sources and explanation you can find [here](https://web.archive.org/web/20131004045556/http://www.security.org.sg/code/loadexe.html) or googling a bit.

The DES implementation is taken from [here](https://github.com/chrishulbert/crypto).

It got tested with MinGW32 on windows XP and it probably needs some modifications to run on newer systems (and x64).

A hacky makefile is included, which builds the hypwrite utility (the one to prepare enc and pass file, needed later), then tries to generate the pass_pe and enc_pe object files with objcopy and then to build the loader;
obviously it fails mid-job the first time due to the absence of enc and crypt files.
