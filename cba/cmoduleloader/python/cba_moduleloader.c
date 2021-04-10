/*
  Copyright (C) 2021 SCYTHE, Inc.

  Authors:
    Originally written by Benjamin Dagana.
    Updated by Ateeq Sharfuddin to support TLS.
    Updated by Jonathan Lim to support AMD64.
    Updated by Ateeq Sharfuddin to support in-memory Python embedding.

  Based on John Levine's "Loaders and Linkers" (ISBN: 1558604960).

  This software is provided 'as-is', without any express or implied
  warranty.  In no event will the authors be held liable for any damages
  arising from the use of this software.

  Permission is granted to anyone to use this software for any purpose,
  including commercial applications, and to alter it and redistribute it
  freely, subject to the following restrictions:

  1. The origin of this software must not be misrepresented; you must not
     claim that you wrote the original software. If you use this software
     in a product, an acknowledgment in the product documentation would be
     appreciated but is not required.
  2. Altered source versions must be plainly marked as such, and must not be
     misrepresented as being the original software.
  3. This notice may not be removed or altered from any source distribution.

*/

#include "cba_moduleloader.h"

extern void* PyWin_DLLhModule;
PLOADEDMODULE PyWin_DllLoadedModule = NULL;

static BOOL CopySectionTable(PUCHAR pData,
    size_t size,
    PIMAGE_NT_HEADERS pNtheaders,
    PLOADEDMODULE pLoadedModule)
{
    INT i, section_size;
    PUCHAR pCodeBase = pLoadedModule->pCodeBase;
    unsigned char *dest;
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(pLoadedModule->pHeaders);
    for (i = 0; i < pLoadedModule->pHeaders->FileHeader.NumberOfSections; i++, section++)
    {
        if (section->SizeOfRawData == 0)
        {
            // section doesn't contain data in the dll itself, but may define
            // uninitialized data
            section_size = pNtheaders->OptionalHeader.SectionAlignment;
            if (section_size > 0)
            {
                dest = (unsigned char *)VirtualAlloc(pCodeBase + section->VirtualAddress,
                    section_size,
                    MEM_COMMIT,
                    PAGE_READWRITE);
                if (dest == NULL)
                {
                    return FALSE;
                }

                // Always use position from file to support alignments smaller
                // than page size.
                dest = pCodeBase + section->VirtualAddress;
                section->Misc.PhysicalAddress = (DWORD)(uintptr_t)dest;
                ZeroMemory(dest, section_size);
            }

            // section is empty
            continue;
        }

        if (size < section->PointerToRawData + section->SizeOfRawData)
        {
            return FALSE;
        }

        // commit memory block and copy data from dll
        dest = (unsigned char *)VirtualAlloc(pCodeBase + section->VirtualAddress,
            section->SizeOfRawData,
            MEM_COMMIT,
            PAGE_READWRITE);
        if (dest == NULL)
        {
            return FALSE;
        }

        // Always use position from file to support alignments smaller
        // than page size.
        dest = pCodeBase + section->VirtualAddress;
        memcpy(dest, pData + section->PointerToRawData, section->SizeOfRawData);
        section->Misc.PhysicalAddress = (DWORD)(uintptr_t)dest;
    }

    return TRUE;
}

/**
* Function: PerformBaseRelocation
*
* The DLL's preferred load address conflicts with memory that’s already in use
* so we need to “rebases” the DLL by loading it at a different address that does
* not overlap and then adjust all addresses.
*
* Arguments:
*	pLoadedModule - The DLL we are loading/rebasing
*	delta - The overlap delta
*
* Return: TRUE if relocation was successful.
*/
static BOOL
PerformBaseRelocation(PLOADEDMODULE pLoadedModule, ptrdiff_t delta)
{
    unsigned char *codeBase = pLoadedModule->pCodeBase;
    PIMAGE_BASE_RELOCATION relocation;
    PIMAGE_DATA_DIRECTORY directory = &(pLoadedModule)->pHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (directory->Size == 0)
    {
        return (delta == 0);
    }

    relocation = (PIMAGE_BASE_RELOCATION)(codeBase + directory->VirtualAddress);
    for (; relocation->VirtualAddress > 0; )
    {
        DWORD i;
        unsigned char *dest = codeBase + relocation->VirtualAddress;
        unsigned short *RelInfo = (unsigned short *)((unsigned char *)relocation + sizeof(IMAGE_BASE_RELOCATION));
        for (i = 0; i < ((relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2); i++, RelInfo++)
        {
            DWORD *patchAddrHL;
#ifdef _WIN64
            ULONGLONG *patchAddr64;
#endif
            INT type, offset;

            // the upper 4 bits define the type of relocation
            type = *RelInfo >> 12;
            // the lower 12 bits define the offset
            offset = *RelInfo & 0xfff;

            switch (type)
            {
            case IMAGE_REL_BASED_ABSOLUTE:
                // skip relocation
                break;

            case IMAGE_REL_BASED_HIGHLOW:
                // change complete 32 bit address
                patchAddrHL = (DWORD *)(dest + offset);
                *patchAddrHL += (DWORD)delta;
                break;

#ifdef _WIN64
            case IMAGE_REL_BASED_DIR64:
                patchAddr64 = (ULONGLONG *)(dest + offset);
                *patchAddr64 += (ULONGLONG)delta;
                break;
#endif

            default:
                break;
            }
        }

        // advance to next relocation block
        relocation = (PIMAGE_BASE_RELOCATION)(((char *)relocation) + relocation->SizeOfBlock);
    }
    return TRUE;
}

/**
* Function: BuildImportTable
*
* Build the import address table.
*
* Arguments:
*	pLoadedModule - Handle to the loaded module (DLL)
*
* Return - TRUE if success otherwise FALSE
*/
static BOOL
BuildImportTable(PLOADEDMODULE pLoadedModule)
{
    unsigned char *codeBase = pLoadedModule->pCodeBase;
    PIMAGE_IMPORT_DESCRIPTOR importDesc;
    BOOL result = TRUE;

    PIMAGE_DATA_DIRECTORY directory = &(pLoadedModule)->pHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (directory->Size == 0)
    {
        return TRUE;
    }

    importDesc = (PIMAGE_IMPORT_DESCRIPTOR)(codeBase + directory->VirtualAddress);
    __try
    {
        // Protect against bad importDesc
        for (; importDesc && importDesc->Name; importDesc++)
        {
            uintptr_t *thunkRef;
            FARPROC *funcRef;
            HINSTANCE  *tmp;
            HINSTANCE  handle = NULL;

            char* import_name = (char*)(codeBase + importDesc->Name);
            BOOL is_python_runtime = FALSE;
            /* CHECK IF IT'S PYTHON RUNTIME DLL */
            if (strlen(import_name) >= 6 &&
                !strncmp(import_name, "python", 6)) {
                char* pch;

                /* Ensure python prefix is followed only
                   by numbers to the end of the basename */
                pch = import_name + 6;
#ifdef _DEBUG
                while (*pch && pch[0] != '_' && pch[1] != 'd' && pch[2] != '.') {
#else
                while (*pch && *pch != '.') {
#endif
                    if (*pch >= '0' && *pch <= '9') {
                        pch++;
                    }
                    else {
                        pch = NULL;
                        break;
                    }
                }

                if (pch) {
                    /* Found it - return the name */
                    is_python_runtime = TRUE;
                }
            }
            /* END CHECK */
            
            if (is_python_runtime) {
                handle = PyWin_DLLhModule;
                if (NULL == PyWin_DllLoadedModule) {
                    /* need to do it only once. */
                    PyWin_DllLoadedModule = _LoadModuleFromInstance(handle);
                }
            }
            else {
                handle = LoadLibraryA((LPCSTR)(codeBase + importDesc->Name));
            }
            if (handle == NULL)
            {
                SetLastError(ERROR_MOD_NOT_FOUND);
                return FALSE;
            }

            tmp = (HINSTANCE  *)realloc(pLoadedModule->pModules, (pLoadedModule->nModules + 1)*(sizeof(HINSTANCE)));
            if (NULL == tmp)
            {
                SetLastError(ERROR_NOT_ENOUGH_MEMORY);
                return FALSE;
            }

            pLoadedModule->pModules = tmp;
            pLoadedModule->pModules[pLoadedModule->nModules++] = handle;

            if (importDesc->OriginalFirstThunk)
            {
                thunkRef = (uintptr_t *)(codeBase + importDesc->OriginalFirstThunk);
                funcRef = (FARPROC *)(codeBase + importDesc->FirstThunk);
            }
            else
            {
                thunkRef = (uintptr_t *)(codeBase + importDesc->FirstThunk);
                funcRef = (FARPROC *)(codeBase + importDesc->FirstThunk);
            }
            for (; *thunkRef; thunkRef++, funcRef++)
            {
                if (IMAGE_SNAP_BY_ORDINAL(*thunkRef))
                {
                    if (!is_python_runtime) {
                        *funcRef = (FARPROC)GetProcAddress(handle, (LPCSTR)IMAGE_ORDINAL(*thunkRef));
                    }
                    else {
                        *funcRef = (FARPROC)_GetProcAddress(PyWin_DllLoadedModule, (LPCSTR)IMAGE_ORDINAL(*thunkRef));
                    }
                }
                else
                {
                    PIMAGE_IMPORT_BY_NAME thunkData = (PIMAGE_IMPORT_BY_NAME)(codeBase + (*thunkRef));
                    if (!is_python_runtime) {
                        *funcRef = (FARPROC)GetProcAddress(handle, (LPCSTR)&thunkData->Name);
                    }
                    else {
                        *funcRef = (FARPROC)_GetProcAddress(PyWin_DllLoadedModule, (LPCSTR)&thunkData->Name);
                    }
                }
                if (*funcRef == 0)
                {
                    result = FALSE;
                    break;
                }
            }

            if (!result)
            {
                FreeLibrary(handle);
                SetLastError(ERROR_PROC_NOT_FOUND);
                break;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return FALSE;
    }

    return result;
}
/**
* Function: GetRealSectionSize
*	Determine section size
*
* Arguments:
*	pModule - Pointer to the DLL module in memory
*	section - Pointer to the image section
*
* Return: Section size
*/
static DWORD
GetRealSectionSize(PLOADEDMODULE pModule, PIMAGE_SECTION_HEADER section)
{
    DWORD size = section->SizeOfRawData;
    if (size == 0) {
        if (section->Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA)
        {
            size = pModule->pHeaders->OptionalHeader.SizeOfInitializedData;
        }
        else if (section->Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA)
        {
            size = pModule->pHeaders->OptionalHeader.SizeOfUninitializedData;
        }
    }
    return size;
}

/**
* Function ProtectSection
*	VirtualProtect section based on Characteristics flags.
*
* Arguments:
*	pModule - Pointer to the DLL module in memory
*	section - Pointer to the image section
*
* Return: Section size
*/
static BOOL
ProtectSection(PLOADEDMODULE pModule, PSECTIONDATA SectionData)
{
    DWORD protection, oldprotection;

    if (SectionData->Size == 0)
    {
        return TRUE;
    }

    // See if section is not needed any more and can be safely freed
    if (SectionData->dwCharacteristics & IMAGE_SCN_MEM_DISCARDABLE)
    {
        if (SectionData->pAddress == SectionData->pAlignedAddress &&
            (SectionData->fLast || pModule->pHeaders->OptionalHeader.SectionAlignment == pModule->dwPageSize ||
            (SectionData->Size % pModule->dwPageSize) == 0))
        {
            // Only allowed to decommit whole pages
#pragma warning(push)
#pragma warning(disable:  6250)
            VirtualFree(SectionData->pAddress, SectionData->Size, MEM_DECOMMIT);
#pragma warning(pop)
        }
        return TRUE;
    }

    // determine protection flags based on Characteristics
    if (SectionData->dwCharacteristics & IMAGE_SCN_CNT_CODE)
        SectionData->dwCharacteristics |= IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;

    // We rotate the upper 3 important bits down so the resulting value is in the range 0-7. 
    // Meaning of bits: 1: execute, 2: read, 4: write 
    switch ((DWORD)SectionData->dwCharacteristics >> (32 - 3))
    {
    case 1: protection = PAGE_EXECUTE; break;
    case 0:										// case 0: what does it mean?
    case 2: protection = PAGE_READONLY; break;
    case 3: protection = PAGE_EXECUTE_READ; break;
    case 4:
    case 6: protection = PAGE_READWRITE; break;
    case 5:
    default: protection = PAGE_EXECUTE_READWRITE; break;
    }

    if (SectionData->dwCharacteristics & IMAGE_SCN_MEM_NOT_CACHED)
    {
        protection |= PAGE_NOCACHE;
    }

    // Change memory access flags
    if (VirtualProtect(SectionData->pAddress, SectionData->Size, protection, &oldprotection) == 0)
    {
        return FALSE;
    }

    return TRUE;
}

/**
* Function ProtectSections
*	Set protection of memory pages.
*
* Arguments:
*	pModule - Pointer to the DLL module in memory
*
* Return: TRUE if successful.  FALSE otherwise
*/
static BOOL ProtectSections(PLOADEDMODULE pModule)
{
    INT i;
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(pModule->pHeaders);
#ifdef _WIN64
    uintptr_t imageOffset = (pModule->pHeaders->OptionalHeader.ImageBase & 0xffffffff00000000);
#else
#define imageOffset 0
#endif
    SECTIONDATA SectionData;
    SectionData.pAddress = (PVOID)((uintptr_t)section->Misc.PhysicalAddress | imageOffset);
    SectionData.pAlignedAddress = MIN_ALIGNED(SectionData.pAddress, pModule->dwPageSize);
    SectionData.Size = GetRealSectionSize(pModule, section);
    SectionData.dwCharacteristics = section->Characteristics;
    SectionData.fLast = FALSE;
    section++;

    // Loop through all sections and change access flags
    for (i = 1; i < pModule->pHeaders->FileHeader.NumberOfSections; i++, section++)
    {
        PVOID SectionAddress = (PVOID)((uintptr_t)section->Misc.PhysicalAddress | imageOffset);
        PVOID AlignedAddress = MIN_ALIGNED(SectionAddress, pModule->dwPageSize);
        DWORD SectionSize = GetRealSectionSize(pModule, section);
        if (SectionData.pAlignedAddress == AlignedAddress ||
            (uintptr_t)SectionData.pAddress + SectionData.Size > (uintptr_t)AlignedAddress)
        {
            // Section shares page with previous section
            if ((section->Characteristics & IMAGE_SCN_MEM_DISCARDABLE) == 0 ||
                (SectionData.dwCharacteristics & IMAGE_SCN_MEM_DISCARDABLE) == 0) {
                SectionData.dwCharacteristics = (SectionData.dwCharacteristics | section->Characteristics) & ~IMAGE_SCN_MEM_DISCARDABLE;
            }
            else
            {
                SectionData.dwCharacteristics |= section->Characteristics;
            }
            SectionData.Size = (((uintptr_t)SectionAddress) + SectionSize) - (uintptr_t)SectionData.pAddress;
            continue;
        }

        if (!ProtectSection(pModule, &SectionData))
        {
            return FALSE;
        }
        SectionData.pAddress = SectionAddress;
        SectionData.pAlignedAddress = AlignedAddress;
        SectionData.Size = SectionSize;
        SectionData.dwCharacteristics = section->Characteristics;
    }
    SectionData.fLast = TRUE;
    if (!ProtectSection(pModule, &SectionData))
    {
        return FALSE;
    }

#ifndef _WIN64
#undef imageOffset
#endif
    return TRUE;
}

/**
* Function: FreeLibraryResources
*
* Free all resources allocated for a loaded module
*
* Arguments:
*		pModule:	Pointer to loaded module
*
* Return: No return value
*/
void FreeLibraryResources(PLOADEDMODULE pModule)
{
    if (pModule == NULL)
    {
        return;
    }

    if (pModule->fInitialized)
    {
        // Tell library to detach from process
        DllEntryProc DllEntry = (DllEntryProc)(PVOID)(pModule->pCodeBase + pModule->pHeaders->OptionalHeader.AddressOfEntryPoint);
        (*DllEntry)((HINSTANCE)pModule->pCodeBase, DLL_PROCESS_DETACH, 0);
    }

    if (pModule->pCodeBase != NULL)
    {
        // release memory of library
        VirtualFree(pModule->pCodeBase, 0, MEM_RELEASE);
    }

    HeapFree(GetProcessHeap(), 0, pModule);
}

/**
* Function: _GetProcAddress
*
* Retrieve address of an exported function from our modules DLL.  This is
* our version of GetProcAddress.
*
* Arguments:
*	pModule:	Pointer to our loaded DLL structure
*	FuncName:	The exported function name
*
* Return: Function pointer or NULL if error
*/
FARPROC _GetProcAddress(PLOADEDMODULE pModule, LPCSTR FuncName)
{
    DWORD idx = 0;
    PIMAGE_EXPORT_DIRECTORY exports;
    PIMAGE_DATA_DIRECTORY directory;

    if (pModule == NULL)
    {
        SetLastError(ERROR_PROC_NOT_FOUND);
        return NULL;
    }

    directory = &(pModule->pHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
    if (directory->Size == 0)
    {
        // no export table found
        SetLastError(ERROR_PROC_NOT_FOUND);
        return NULL;
    }

    exports = (PIMAGE_EXPORT_DIRECTORY)(pModule->pCodeBase + directory->VirtualAddress);
    if (exports->NumberOfNames == 0 || exports->NumberOfFunctions == 0)
    {
        // Our modules must export 3 functions.
        SetLastError(ERROR_PROC_NOT_FOUND);
        return NULL;
    }

    if (HIWORD(FuncName) == 0)
    {
        // load function by ordinal value
        if (LOWORD(FuncName) < exports->Base)
        {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return NULL;
        }

        idx = LOWORD(FuncName) - exports->Base;
    }
    else {
        // search function name in list of exported names
        DWORD i;
        DWORD *nameRef = (DWORD *)(pModule->pCodeBase + exports->AddressOfNames);
        WORD *ordinal = (WORD *)(pModule->pCodeBase + exports->AddressOfNameOrdinals);
        BOOL found = FALSE;
        for (i = 0; i < exports->NumberOfNames; i++, nameRef++, ordinal++) {
            if (_stricmp(FuncName, (const char *)(pModule->pCodeBase + (*nameRef))) == 0)
            {
                idx = *ordinal;
                found = TRUE;
                break;
            }
        }

        if (!found)
        {
            // exported symbol not found
            SetLastError(ERROR_PROC_NOT_FOUND);
            return NULL;
        }
    }

    if (idx > exports->NumberOfFunctions)
    {
        // name <-> ordinal number don't match
        SetLastError(ERROR_PROC_NOT_FOUND);
        return NULL;
    }

    // AddressOfFunctions contains the RVAs to the "real" functions
    return (FARPROC)(PVOID)(pModule->pCodeBase + (*(DWORD *)(pModule->pCodeBase + exports->AddressOfFunctions + (idx * 4))));
}


PLOADEDMODULE _LoadModuleFromInstance(HINSTANCE hInstance)
{
    PLOADEDMODULE pLoadedModule = NULL;
    PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_NT_HEADERS pNtHeaders;
    SYSTEM_INFO sysInfo = { 0 };


    // Check header for valid signatures
    pDosHeader = (PIMAGE_DOS_HEADER)hInstance;
    pNtHeaders = (PIMAGE_NT_HEADERS)&((PUCHAR)(hInstance))[pDosHeader->e_lfanew];
    if ((pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) || (pNtHeaders->Signature != IMAGE_NT_SIGNATURE))
    {
        SetLastError(ERROR_BAD_EXE_FORMAT);
        goto ErrorExit;
    }

#ifdef _WIN64
    if (pNtHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
    {
#else
    if (pNtHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_I386)
    {
#endif
        SetLastError(ERROR_BAD_EXE_FORMAT);
        goto ErrorExit;
    }

    GetNativeSystemInfo(&sysInfo);	// need system PageSize

    pLoadedModule = (PLOADEDMODULE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(LOADEDMODULE));
    if (pLoadedModule == NULL)
    {
        SetLastError(ERROR_OUTOFMEMORY);
        goto ErrorExit;
    }

    pLoadedModule->pHeaders = pNtHeaders;
    pLoadedModule->pCodeBase = (PVOID)pNtHeaders->OptionalHeader.ImageBase;
    pLoadedModule->pModules = NULL;
    pLoadedModule->nModules = 0;
    pLoadedModule->fRelocated = FALSE;
    pLoadedModule->dwPageSize = sysInfo.dwPageSize;

    // Get entry point and call DLL_PROCESS_ATTACH
    if (pLoadedModule->pHeaders->OptionalHeader.AddressOfEntryPoint != 0)
    {
        pLoadedModule->fInitialized = TRUE;
    }

    return pLoadedModule;

ErrorExit:
    if (pLoadedModule != NULL)
    {
        HeapFree(GetProcessHeap(), 0, pLoadedModule);
    }

    return NULL;

}


__checkReturn __success(return != NULL) PLOADEDMODULE LoadModuleFromMemory(PVOID lpData, DWORD dwSize)
{
    PLOADEDMODULE pLoadedModule = NULL;
    PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_NT_HEADERS pNtHeaders;
    PIMAGE_SECTION_HEADER pSection;

    PIMAGE_TLS_DIRECTORY tls;
    PIMAGE_TLS_CALLBACK* callback;
    PIMAGE_DATA_DIRECTORY directory;

    size_t lastSectionEnd = 0;
    SYSTEM_INFO sysInfo = { 0 };
    size_t ImageSize;
    PUCHAR pHeaders, pImage = NULL;
    ptrdiff_t locationDelta;
    DWORD i;

    // Check header for valid signatures
    pDosHeader = (PIMAGE_DOS_HEADER)lpData;
    pNtHeaders = (PIMAGE_NT_HEADERS)&((PUCHAR)(lpData))[pDosHeader->e_lfanew];
    if ((pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) || (pNtHeaders->Signature != IMAGE_NT_SIGNATURE))
    {
        SetLastError(ERROR_BAD_EXE_FORMAT);
        goto ErrorExit;
    }

    // Check sizes
    if ((dwSize < sizeof(IMAGE_DOS_HEADER)) ||
        (dwSize < pNtHeaders->OptionalHeader.SizeOfHeaders) ||
        (dwSize < pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS)))
    {
        SetLastError(ERROR_INVALID_DATA);
        goto ErrorExit;
    }

#ifdef _WIN64
    if (pNtHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
    {
#else
    if (pNtHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_I386)
    {
#endif
        SetLastError(ERROR_BAD_EXE_FORMAT);
        goto ErrorExit;
    }


    pSection = IMAGE_FIRST_SECTION(pNtHeaders);
    for (i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++, pSection++)
    {
        size_t endOfSection;
        if (pSection->SizeOfRawData == 0)
        {
            // Section without data in the DLL
            endOfSection = pSection->VirtualAddress + pNtHeaders->OptionalHeader.SectionAlignment;
        }
        else
        {
            endOfSection = pSection->VirtualAddress + pSection->SizeOfRawData;
        }

        if (endOfSection > lastSectionEnd)
        {
            lastSectionEnd = endOfSection;
        }
    }

    GetNativeSystemInfo(&sysInfo);	// need system PageSize
    ImageSize = MAX_ALIGNED(pNtHeaders->OptionalHeader.SizeOfImage, sysInfo.dwPageSize);
    if (ImageSize != MAX_ALIGNED(lastSectionEnd, sysInfo.dwPageSize))
    {
        SetLastError(ERROR_BAD_EXE_FORMAT);
        goto ErrorExit;
    }

    // Reserve pages at specified image base.
    pImage = VirtualAlloc((PVOID)pNtHeaders->OptionalHeader.ImageBase,
        ImageSize,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE);
    if (pImage == NULL) {
        // Allow system to determine where to allocate the region
        pImage = (PUCHAR)VirtualAlloc(NULL, ImageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (pImage == NULL)
        {
            SetLastError(ERROR_OUTOFMEMORY);
            goto ErrorExit;
        }
    }

    pLoadedModule = (PLOADEDMODULE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(LOADEDMODULE));
    if (pLoadedModule == NULL)
    {
        SetLastError(ERROR_OUTOFMEMORY);
        goto ErrorExit;
    }

    pLoadedModule->pCodeBase = pImage;
    pLoadedModule->dwPageSize = sysInfo.dwPageSize;

    // Commit memory for headers
    pHeaders = (PUCHAR)VirtualAlloc(pImage, pNtHeaders->OptionalHeader.SizeOfHeaders, MEM_COMMIT, PAGE_READWRITE);
    if (NULL == pHeaders)
    {
        SetLastError(ERROR_OUTOFMEMORY);
        goto ErrorExit;
    }

    // Copy PE header to code
    memcpy(pHeaders, pDosHeader, pNtHeaders->OptionalHeader.SizeOfHeaders);
    pLoadedModule->pHeaders = (PIMAGE_NT_HEADERS)&((const unsigned char *)(pHeaders))[pDosHeader->e_lfanew];

    // Update position in case we didn't get preferred base
    pLoadedModule->pHeaders->OptionalHeader.ImageBase = (uintptr_t)pImage;

    // Copy section table
    if (!CopySectionTable((PUCHAR)lpData, dwSize, pNtHeaders, pLoadedModule))
    {
        goto ErrorExit;
    }

    // Adjust base address of imported data
    locationDelta = (ptrdiff_t)pLoadedModule->pHeaders->OptionalHeader.ImageBase - pNtHeaders->OptionalHeader.ImageBase;
    if (locationDelta != 0)
    {
        pLoadedModule->fRelocated = PerformBaseRelocation(pLoadedModule, locationDelta);
    }
    else
    {
        pLoadedModule->fRelocated = TRUE;
    }

    // Adjust function table of imports
    if (!BuildImportTable(pLoadedModule))
    {
        goto ErrorExit;
    }

    // Mark memory pages depending on characteristics of the section headers
    if (!ProtectSections(pLoadedModule))
    {
        goto ErrorExit;
    }

    // Thread Local Storage (TLS) callbacks are executed BEFORE the main loading
    directory = &(pLoadedModule->pHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS]);
    if (directory->VirtualAddress != 0)
    {
        tls = (PIMAGE_TLS_DIRECTORY)(pLoadedModule->pCodeBase + directory->VirtualAddress);
        callback = (PIMAGE_TLS_CALLBACK *)tls->AddressOfCallBacks;
        if (callback) {
            while (*callback)
            {
                (*callback)((PVOID)pLoadedModule->pCodeBase, DLL_PROCESS_ATTACH, NULL);
                callback++;
            }
        }
    }

    // Get entry point and call DLL_PROCESS_ATTACH
    if (pLoadedModule->pHeaders->OptionalHeader.AddressOfEntryPoint != 0)
    {
        DllEntryProc DllEntry = (DllEntryProc)(PVOID)(pLoadedModule->pCodeBase + pLoadedModule->pHeaders->OptionalHeader.AddressOfEntryPoint);
        // Notify library about attaching to process
        BOOL successful = (*DllEntry)((HINSTANCE)pLoadedModule->pCodeBase, DLL_PROCESS_ATTACH, 0);
        if (!successful)
        {
            SetLastError(ERROR_DLL_INIT_FAILED);
            goto ErrorExit;
        }
        pLoadedModule->fInitialized = TRUE;
    }

    return pLoadedModule;

ErrorExit:
    if (pImage != NULL)
    {
        VirtualFree(pImage, 0, MEM_RELEASE);
    }
    if (pLoadedModule != NULL)
    {
        HeapFree(GetProcessHeap(), 0, pLoadedModule);
    }

    return NULL;
}


static PIMAGE_RESOURCE_DIRECTORY_ENTRY SearchResourceEntry(
    void *root,
    PIMAGE_RESOURCE_DIRECTORY resources,
    LPCTSTR key)
{
    PIMAGE_RESOURCE_DIRECTORY_ENTRY entries = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(resources + 1);
    PIMAGE_RESOURCE_DIRECTORY_ENTRY result = NULL;
    DWORD start;
    DWORD end;
    DWORD middle;

    // entries are stored as ordered list of named entries,
    // followed by an ordered list of id entries - we can do
    // a binary search to find faster...
    if (IS_INTRESOURCE(key)) {
        WORD check = (WORD)(uintptr_t)key;
        start = resources->NumberOfNamedEntries;
        end = start + resources->NumberOfIdEntries;

        while (end > start) {
            WORD entryName;
            middle = (start + end) >> 1;
            entryName = (WORD)entries[middle].Name;
            if (check < entryName) {
                end = (end != middle ? middle : middle - 1);
            }
            else if (check > entryName) {
                start = (start != middle ? middle : middle + 1);
            }
            else {
                result = &entries[middle];
                break;
            }
        }
    }
    else {
        LPCWSTR searchKey;
        size_t searchCount = 0;
        size_t searchKeyLen = wcslen((wchar_t *)key);
#if defined(UNICODE)
        searchKey = key;
#else
        // Resource names are always stored using 16bit characters, need to
        // convert string we search for.
#define MAX_LOCAL_KEY_LENGTH 2048
        // In most cases resource names are short, so optimize for that by
        // using a pre-allocated array.
        wchar_t _searchKeySpace[MAX_LOCAL_KEY_LENGTH + 1];

        LPWSTR _searchKey;
        if (searchKeyLen > MAX_LOCAL_KEY_LENGTH) {
            size_t _searchKeySize = (searchKeyLen + 1) * sizeof(wchar_t);
            _searchKey = (LPWSTR)malloc(_searchKeySize);
            if (_searchKey == NULL) {
                SetLastError(ERROR_OUTOFMEMORY);
                return NULL;
            }
        }
        else {
            _searchKey = &_searchKeySpace[0];
        }

        mbstowcs_s(&searchCount, _searchKey, searchKeyLen, key, searchKeyLen - 1);
        _searchKey[searchKeyLen] = 0;
        searchKey = _searchKey;
#endif
        start = 0;
        end = resources->NumberOfNamedEntries;
        while (end > start) {
            int cmp;
            PIMAGE_RESOURCE_DIR_STRING_U resourceString;
            middle = (start + end) >> 1;
            resourceString = (PIMAGE_RESOURCE_DIR_STRING_U)(((char *)root) + (entries[middle].Name & 0x7FFFFFFF));
            cmp = _wcsnicmp(searchKey, resourceString->NameString, resourceString->Length);
            if (cmp == 0) {
                // Handle partial match
                cmp = (int)searchKeyLen - (int)resourceString->Length;
            }
            if (cmp < 0) {
                end = (middle != end ? middle : middle - 1);
            }
            else if (cmp > 0) {
                start = (middle != start ? middle : middle + 1);
            }
            else {
                result = &entries[middle];
                break;
            }
        }
#if !defined(UNICODE)
        if (searchKeyLen > MAX_LOCAL_KEY_LENGTH) {
            free(_searchKey);
        }
#undef MAX_LOCAL_KEY_LENGTH
#endif
    }

    return result;
}

PVOID _FindResourceEx(PLOADEDMODULE module, LPCTSTR name, LPCTSTR type, WORD language)
{
    unsigned char *codeBase = ((PLOADEDMODULE)module)->pCodeBase;
    PIMAGE_DATA_DIRECTORY directory = &(module)->pHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];
    PIMAGE_RESOURCE_DIRECTORY rootResources;
    PIMAGE_RESOURCE_DIRECTORY nameResources;
    PIMAGE_RESOURCE_DIRECTORY typeResources;
    PIMAGE_RESOURCE_DIRECTORY_ENTRY foundType;
    PIMAGE_RESOURCE_DIRECTORY_ENTRY foundName;
    PIMAGE_RESOURCE_DIRECTORY_ENTRY foundLanguage;

    if (directory->Size == 0)
    {
        // no resource table found
        SetLastError(ERROR_RESOURCE_DATA_NOT_FOUND);
        return NULL;
    }

    if (language == DEFAULT_LANGUAGE)
    {
        // use language from current thread
        language = LANGIDFROMLCID(GetThreadLocale());
    }

    // resources are stored as three-level tree
    // - first node is the type
    // - second node is the name
    // - third node is the language
    rootResources = (PIMAGE_RESOURCE_DIRECTORY)(codeBase + directory->VirtualAddress);
    foundType = SearchResourceEntry(rootResources, rootResources, type);
    if (foundType == NULL)
    {
        SetLastError(ERROR_RESOURCE_TYPE_NOT_FOUND);
        return NULL;
    }

    typeResources = (PIMAGE_RESOURCE_DIRECTORY)(codeBase + directory->VirtualAddress + (foundType->OffsetToData & 0x7fffffff));
    foundName = SearchResourceEntry(rootResources, typeResources, name);
    if (foundName == NULL)
    {
        SetLastError(ERROR_RESOURCE_NAME_NOT_FOUND);
        return NULL;
    }

    nameResources = (PIMAGE_RESOURCE_DIRECTORY)(codeBase + directory->VirtualAddress + (foundName->OffsetToData & 0x7fffffff));
    foundLanguage = SearchResourceEntry(rootResources, nameResources, (LPCTSTR)(uintptr_t)language);
    if (foundLanguage == NULL)
    {
        // requested language not found, use first available
        if (nameResources->NumberOfIdEntries == 0)
        {
            SetLastError(ERROR_RESOURCE_LANG_NOT_FOUND);
            return NULL;
        }

        foundLanguage = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(nameResources + 1);
    }

    return (codeBase + directory->VirtualAddress + (foundLanguage->OffsetToData & 0x7fffffff));
}

PVOID _FindResource(PLOADEDMODULE module, LPCTSTR name, LPCTSTR type)
{
    if (NULL == module)
    {
        // If module is NULL, we need to search the module used to create the current process.
        // For now, return NULL
        return NULL;
    }

    return _FindResourceEx(module, name, type, DEFAULT_LANGUAGE);
}

DWORD _SizeofResource(PLOADEDMODULE module, PVOID resource)
{
    PIMAGE_RESOURCE_DATA_ENTRY entry;
    UNREFERENCED_PARAMETER(module);
    entry = (PIMAGE_RESOURCE_DATA_ENTRY)resource;
    if (entry == NULL) {
        return 0;
    }

    return entry->Size;
}

LPVOID _LoadResource(PLOADEDMODULE module, PVOID resource)
{
    unsigned char *codeBase = ((PLOADEDMODULE)module)->pCodeBase;
    PIMAGE_RESOURCE_DATA_ENTRY entry = (PIMAGE_RESOURCE_DATA_ENTRY)resource;
    if (entry == NULL) {
        return NULL;
    }

    return codeBase + entry->OffsetToData;
}

__checkReturn __success(return == TRUE) BOOL IsPEHeaderValid(__in PVOID lpData, __in DWORD dwSize)
{
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpData;
    PIMAGE_NT_HEADERS pNtHeaders;

    // Check header for valid signatures    
    if (pDosHeader->e_magic == IMAGE_DOS_SIGNATURE)
    {
        // Dos header has 'MZ'.  Make sure size is at least size of PE header
        if (dwSize < (sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER)))
        {
            return FALSE;
        }

        // Ok to touch optional header
        pNtHeaders = (PIMAGE_NT_HEADERS)&((PUCHAR)(lpData))[pDosHeader->e_lfanew];
        if ((dwSize < pNtHeaders->OptionalHeader.SizeOfHeaders) ||
            (dwSize < pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS)))
        {
            return FALSE;
        }
        
        // Check for the correct architecture.
#ifdef _WIN64
        if (pNtHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
        {
#else
        if (pNtHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_I386)
        {
#endif
//            LOG(LOG_LEVEL_ERROR, L"Incorrect architecture type: %x", pNtHeaders->FileHeader.Machine);
            return FALSE;
        }
        
        // Check to see if the image is really a DLL
        if (!(pNtHeaders->FileHeader.Characteristics & IMAGE_FILE_DLL))
        {
            return FALSE;   // File is not a DLL
        }
    }
    else
    {
        return FALSE;
    }

    return TRUE;
}