#ifndef __CUSTOM_MODULELOADER_H__
#define __CUSTOM_MODULELOADER_H__

#if defined (_MSC_VER) && (_MSC_VER >= 1020)
#pragma once
#endif

#include <windows.h>

typedef struct _LOADEDMODULE 
{
	PIMAGE_NT_HEADERS	pHeaders;
	PBYTE				pCodeBase;
	HINSTANCE *			pModules;
	INT					nModules;
	BOOL				fInitialized;
	BOOL				fRelocated;
	DWORD				dwPageSize;
} LOADEDMODULE, *PLOADEDMODULE;

typedef PVOID HLOADEDMODULE;

PLOADEDMODULE _LoadModuleFromInstance(HINSTANCE hInstance);
__checkReturn __success(return != NULL) PLOADEDMODULE LoadModuleFromMemory(PVOID lpData, DWORD dwSize);
FARPROC _GetProcAddress(PLOADEDMODULE pModule, LPCSTR FuncName);
void FreeLibraryResources(PLOADEDMODULE pModule);
__checkReturn __success(return == TRUE) BOOL IsPEHeaderValid(__in PVOID lpData, __in DWORD dwSize);
PVOID _FindResource(PLOADEDMODULE module, LPCTSTR name, LPCTSTR type);
LPVOID _LoadResource(PLOADEDMODULE module, PVOID resource);
DWORD _SizeofResource(PLOADEDMODULE module, PVOID resource);

// Section data from file header
typedef struct _SECTIONDATA
{
	LPVOID pAddress;
	LPVOID pAlignedAddress;
	uintptr_t  Size;
	DWORD  dwCharacteristics;
	BOOL   fLast;
} SECTIONDATA, *PSECTIONDATA;


#define ARCHITECTURE_TYPE_X86 0x00000000
#define ARCHITECTURE_TYPE_X64 0x00000001

// MIN/MAX of address aligned
#define MIN_ALIGNED(address, alignment) (LPVOID)((uintptr_t)(address) & ~((alignment) - 1))
#define MAX_ALIGNED(value, alignment) (((value) + (alignment) - 1) & ~((alignment) - 1))

typedef BOOL(WINAPI *DllEntryProc)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved);

#define DEFAULT_LANGUAGE        MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL)

#endif /* __CUSTOM_MODULELOADER_H__ */