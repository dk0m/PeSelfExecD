module ntapi;
import core.sys.windows.windows;
import std.stdio;

pragma(lib, "ntdll.lib");

alias NTSTATUS = uint;

bool NT_SUCCESS(NTSTATUS status) {
    return (status >= 0);
}

void PRINT_NTAPI_ERROR(string fnName, NTSTATUS status) {
    writefln("[-] %s Failed With Code: 0x%x", fnName, status);
}

struct UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR  Buffer;
};

struct OBJECT_ATTRIBUTES {
  ULONG           Length;
  HANDLE          RootDirectory;
  UNICODE_STRING* ObjectName;
  ULONG           Attributes;
  PVOID           SecurityDescriptor;
  PVOID           SecurityQualityOfService;
};

struct CLIENT_ID {
    HANDLE UniqueProcessId;
    HANDLE UniqueThreadId;
}

extern (Windows) NTSTATUS NtOpenProcess(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    OBJECT_ATTRIBUTES* ObjectAttributes,
    CLIENT_ID* ClientId
);

extern (Windows) NTSTATUS NtCreateThreadEx(
  PHANDLE hThread,
  ACCESS_MASK DesiredAccess,
  PVOID ObjectAttributes,
  HANDLE ProcessHandle,
  PVOID lpStartAddress,
  PVOID lpParameter,
  ULONG Flags,
  SIZE_T StackZeroBits,
  SIZE_T SizeOfStackCommit,
  SIZE_T SizeOfStackReserve,
  PVOID lpBytesBuffer
);


extern (Windows) NTSTATUS NtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

extern (Windows) NTSTATUS NtWriteVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
);

