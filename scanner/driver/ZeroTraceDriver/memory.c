/*
 * ZeroTrace Kernel Driver - Physical Memory & VAD Tree Scanner
 *
 * Physical memory reads are the nuclear option for detecting DMA cheats and
 * memory-hiding rootkits: because MmMapIoSpace maps raw hardware RAM, no
 * software hook in the kernel can intercept or filter the read.
 *
 * VAD tree scanning walks all memory regions of a process using the kernel's
 * own ZwQueryVirtualMemory, which queries the EPROCESS->VadRoot AVL tree
 * directly. Executable-private regions (MEM_PRIVATE + PAGE_EXECUTE_*) have
 * no file backing and indicate injected shellcode or a reflectively loaded
 * DLL.
 */
#include <ntddk.h>
#include <wdm.h>
#include "memory.h"
#include "ioctl.h"

/* ZwQueryVirtualMemory is not declared in all WDK headers; declare it here. */
NTSYSAPI NTSTATUS NTAPI ZwQueryVirtualMemory(
    HANDLE                   ProcessHandle,
    PVOID                    BaseAddress,
    ULONG                    MemoryInformationClass, /* 0 = MemoryBasicInformation */
    PVOID                    MemoryInformation,
    SIZE_T                   MemoryInformationLength,
    PSIZE_T                  ReturnLength OPTIONAL);

/* PAGE_* flags that mark a region as executable */
#define EXEC_PROTECT_MASK \
    (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)

/* ── Physical memory read ─────────────────────────────────────────────────── */
NTSTATUS ZtReadPhysicalMemory(PHYSICAL_ADDRESS PhysAddress, PVOID Buffer, SIZE_T Length)
{
    if (!Buffer || Length == 0 || Length > ZTRACE_PHYS_READ_MAX)
        return STATUS_INVALID_PARAMETER;

    PVOID mapped = MmMapIoSpace(PhysAddress, Length, MmNonCached);
    if (!mapped)
        return STATUS_INSUFFICIENT_RESOURCES;

    __try
    {
        RtlCopyMemory(Buffer, mapped, Length);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        MmUnmapIoSpace(mapped, Length);
        return GetExceptionCode();
    }

    MmUnmapIoSpace(mapped, Length);
    return STATUS_SUCCESS;
}

/* ── VAD tree enumeration ─────────────────────────────────────────────────── */
NTSTATUS ZtEnumerateVadTree(ULONG ProcessId, PZTRACE_VAD_LIST Out)
{
    if (!Out) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Out, sizeof(*Out));
    Out->ProcessId = ProcessId;

    PEPROCESS process;
    NTSTATUS status = PsLookupProcessByProcessId(
        (HANDLE)(ULONG_PTR)ProcessId, &process);
    if (!NT_SUCCESS(status)) return status;

    /* Open a kernel handle with just enough access to query memory */
    HANDLE hProcess = NULL;
    status = ObOpenObjectByPointer(
        process,
        OBJ_KERNEL_HANDLE,
        NULL,
        PROCESS_QUERY_INFORMATION,
        *PsProcessType,
        KernelMode,
        &hProcess);

    ObDereferenceObject(process);
    if (!NT_SUCCESS(status)) return status;

    PVOID address = NULL;

    /* MemoryBasicInformation = 0 */
    typedef struct {
        PVOID  BaseAddress;
        PVOID  AllocationBase;
        ULONG  AllocationProtect;
        ULONG  PartitionId;
        SIZE_T RegionSize;
        ULONG  State;
        ULONG  Protect;
        ULONG  Type;
    } MBI;

    while (Out->Count < ZTRACE_MAX_VAD_ENTRIES)
    {
        MBI mbi = { 0 };
        SIZE_T returned = 0;

        status = ZwQueryVirtualMemory(hProcess, address, 0,
            &mbi, sizeof(mbi), &returned);
        if (!NT_SUCCESS(status)) break;

        PZTRACE_VAD_ENTRY entry = &Out->Entries[Out->Count++];
        entry->BaseAddress = (ULONG64)mbi.BaseAddress;
        entry->RegionSize  = (ULONG64)mbi.RegionSize;
        entry->State       = mbi.State;
        entry->Protect     = mbi.Protect;
        entry->Type        = mbi.Type;

        /* FLAG_EXECUTABLE = 0x1 */
        if (mbi.Protect & EXEC_PROTECT_MASK)
            entry->Flags |= 0x1;

        /* FLAG_EXEC_PRIVATE = 0x2 — executable memory with no file backing:
         * the primary signature of reflective DLL injection or shellcode. */
        if ((mbi.Protect & EXEC_PROTECT_MASK) &&
            mbi.Type  == 0x20000 &&  /* MEM_PRIVATE */
            mbi.State == 0x1000)     /* MEM_COMMIT  */
            entry->Flags |= 0x2;

        /* Advance past this region; guard against zero-size or overflow */
        ULONG_PTR next = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
        if (next <= (ULONG_PTR)address || next >= 0x7FFFFFFFFFFF)
            break;
        address = (PVOID)next;
    }

    ZwClose(hProcess);
    return STATUS_SUCCESS;
}
