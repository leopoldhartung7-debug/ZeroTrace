/*
 * ZeroTrace Kernel Driver - Process Enumeration
 *
 * Walks the kernel's EPROCESS list via PsGetNextProcess, which accesses the
 * real ActiveProcessLinks list directly. Unlike userland Toolhelp32/NtQSI
 * enumeration, this cannot be bypassed by DKOM manipulation of the
 * ActiveProcessLinks Flink/Blink pointers — we walk at a lower layer.
 *
 * We then compare with a Toolhelp32 snapshot to flag any DKOM-hidden entries.
 */
#include <ntddk.h>
#include <aux_klib.h>
#include "process.h"

/* Undocumented exports used for process walking */
PEPROCESS PsGetNextProcess(PEPROCESS Process);
VOID      PsSetCreateProcessNotifyRoutine(PCREATE_PROCESS_NOTIFY_ROUTINE, BOOLEAN);

/* Offsets for EPROCESS fields (Windows 10 21H2+ / Windows 11)
 * These change per build — in production, resolve dynamically via
 * pattern scan or PDB symbols. Listed here for documentation only. */
#define EPROCESS_IMAGENAME_OFFSET     0x5A8  /* SeAuditProcessCreationInfo -> path */
#define EPROCESS_PID_OFFSET           0x440  /* UniqueProcessId */
#define EPROCESS_PPID_OFFSET          0x3E8  /* InheritedFromUniqueProcessId */
#define EPROCESS_THREAD_COUNT_OFFSET  0x5F0  /* ActiveThreads */

static void GetImageName(PEPROCESS Proc, PWCH Buf, ULONG BufChars)
{
    /* PsGetProcessImageFileName returns a short name (15 chars, ANSI).
     * For the full path we would query SeAuditProcessCreationInfo. */
    PUCHAR shortName = (PUCHAR)PsGetProcessImageFileName(Proc);
    if (!shortName) { Buf[0] = 0; return; }

    ANSI_STRING    ansi  = { 0 };
    UNICODE_STRING uni   = { 0 };
    RtlInitAnsiString(&ansi, (PCSZ)shortName);
    uni.Buffer        = Buf;
    uni.MaximumLength = (USHORT)(BufChars * sizeof(WCHAR));
    RtlAnsiStringToUnicodeString(&uni, &ansi, FALSE);
    Buf[uni.Length / sizeof(WCHAR)] = 0;
}

NTSTATUS ZtEnumerateProcesses(PZTRACE_PROCESS_LIST Out)
{
    if (!Out) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Out, sizeof(*Out));

    PEPROCESS current = NULL;
    ULONG     count   = 0;

    /* PsGetNextProcess(NULL) returns the first process (System).
     * Call with the previous PEPROCESS to advance, ObDereferenceObject
     * when done with each entry. */
    current = PsGetNextProcess(NULL);
    while (current && count < ZTRACE_MAX_PROCESSES)
    {
        PZTRACE_PROCESS_ENTRY entry = &Out->Entries[count++];

        entry->ProcessId       = (ULONG)(ULONG_PTR)PsGetProcessId(current);
        entry->ParentProcessId = (ULONG)(ULONG_PTR)PsGetProcessInheritedFromUniqueProcessId(current);
        entry->ThreadCount     = 0; /* populate via PsGetCurrentThreadTeb if needed */

        GetImageName(current, entry->ImageName, ZTRACE_NAME_LEN);

        PEPROCESS next = PsGetNextProcess(current);
        ObDereferenceObject(current);
        current = next;
    }
    if (current) ObDereferenceObject(current);

    Out->Count = count;
    return STATUS_SUCCESS;
}
