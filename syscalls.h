#ifndef SYSCALLS_H
#define SYSCALLS_H

#include <windows.h>

extern "C" {
    NTSTATUS NTAPI NtAllocateVirtualMemory(
        HANDLE ProcessHandle,
        PVOID* BaseAddress,
        ULONG ZeroBits,
        PSIZE_T RegionSize,
        ULONG AllocationType,
        ULONG Protect
    );

    NTSTATUS NTAPI NtWriteVirtualMemory(
        HANDLE ProcessHandle,
        PVOID BaseAddress,
        PVOID Buffer,
        ULONG BufferSize,
        PULONG NumberOfBytesWritten
    );

    NTSTATUS NTAPI NtProtectVirtualMemory(
        HANDLE ProcessHandle,
        PVOID* BaseAddress,
        PSIZE_T RegionSize,
        ULONG NewProtect,
        PULONG OldProtect
    );

    NTSTATUS NTAPI NtResumeThread(
        HANDLE ThreadHandle,
        PULONG SuspendCount
    );
}

#endif // SYSCALLS_H
