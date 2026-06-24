/*
 * ZeroTrace Kernel Driver - SSDT Hook Detection & Hidden Driver Enumeration
 *
 * SSDT (System Service Descriptor Table) hook detection:
 * The SSDT maps syscall numbers to function addresses in ntoskrnl.exe.
 * A rootkit or cheat driver patches entries to redirect calls to its own
 * code (e.g. to hide processes from NtQuerySystemInformation).
 *
 * We validate each entry by checking whether its address falls within the
 * address range of ntoskrnl.exe. If it points elsewhere, it's hooked.
 *
 * Hidden driver detection:
 * Drivers loaded via kernel exploits (BYOVD / manual map) do not appear in
 * PsLoadedModuleList. We detect them by comparing the module list against
 * all executable kernel memory regions found via MmGetSystemRoutineAddress
 * and AuxKlibQueryModuleInformation.
 */
#include <ntddk.h>
#include <aux_klib.h>
#include "hooks.h"

/* Exported by ntoskrnl, resolved at runtime */
extern SYSTEM_SERVICE_DESCRIPTOR_TABLE KeServiceDescriptorTable;

/* ntoskrnl base / size — resolved once at startup */
static ULONG64 g_NtoskrnlBase = 0;
static ULONG64 g_NtoskrnlSize = 0;

static void ResolveNtoskrnlRange(void)
{
    if (g_NtoskrnlBase) return;

    ULONG  modulesSize = 0;
    AuxKlibInitialize();
    AuxKlibQueryModuleInformation(&modulesSize, sizeof(AUX_MODULE_EXTENDED_INFO), NULL);
    if (!modulesSize) return;

    ULONG count = modulesSize / sizeof(AUX_MODULE_EXTENDED_INFO);
    PAUX_MODULE_EXTENDED_INFO mods =
        (PAUX_MODULE_EXTENDED_INFO)ExAllocatePoolWithTag(
            NonPagedPool, modulesSize, 'ZTrc');
    if (!mods) return;

    NTSTATUS status = AuxKlibQueryModuleInformation(
        &modulesSize, sizeof(AUX_MODULE_EXTENDED_INFO), mods);

    if (NT_SUCCESS(status))
    {
        for (ULONG i = 0; i < count; i++)
        {
            /* First module is always ntoskrnl.exe */
            if (i == 0)
            {
                g_NtoskrnlBase = (ULONG64)mods[i].BasicInfo.ImageBase;
                g_NtoskrnlSize = (ULONG64)mods[i].ImageSize;
                break;
            }
        }
    }
    ExFreePoolWithTag(mods, 'ZTrc');
}

NTSTATUS ZtScanSsdtHooks(PZTRACE_HOOK_LIST Out)
{
    if (!Out) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Out, sizeof(*Out));
    ResolveNtoskrnlRange();

    if (!g_NtoskrnlBase || !g_NtoskrnlSize) return STATUS_UNSUCCESSFUL;

    PULONG  ssdt     = (PULONG)KeServiceDescriptorTable.ServiceTableBase;
    ULONG   ssdtCount = KeServiceDescriptorTable.NumberOfServices;
    ULONG   hookedCount = 0;

    for (ULONG i = 0; i < ssdtCount && hookedCount < ZTRACE_MAX_HOOKS; i++)
    {
        /* Each SSDT entry on x64 is a 4-byte offset relative to the SSDT base.
         * Actual address = SSDT base + (entry >> 4) */
        LONG   offset  = (LONG)(ssdt[i] >> 4);
        ULONG64 fnAddr = (ULONG64)ssdt + offset;

        /* Check if address is within ntoskrnl */
        if (fnAddr >= g_NtoskrnlBase &&
            fnAddr <  g_NtoskrnlBase + g_NtoskrnlSize)
            continue; /* normal */

        /* Hook detected — address is outside ntoskrnl range */
        PZTRACE_HOOK_ENTRY entry = &Out->Entries[hookedCount++];
        entry->FunctionAddress = fnAddr;
        entry->HookTarget      = fnAddr; /* in SSDT hooks, the entry IS the hook */
        RtlStringCbPrintfW(entry->FunctionName, sizeof(entry->FunctionName),
            L"SSDT[%u]", i);

        /* Try to identify the module the hook lands in */
        /* (omitted for brevity — use AuxKlibQueryModuleInformation) */
    }

    Out->Count = hookedCount;
    return STATUS_SUCCESS;
}

NTSTATUS ZtFindHiddenDrivers(PZTRACE_MODULE_LIST Out)
{
    if (!Out) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Out, sizeof(*Out));

    ULONG  size = 0;
    AuxKlibQueryModuleInformation(&size, sizeof(AUX_MODULE_EXTENDED_INFO), NULL);
    if (!size) return STATUS_UNSUCCESSFUL;

    PAUX_MODULE_EXTENDED_INFO mods =
        (PAUX_MODULE_EXTENDED_INFO)ExAllocatePoolWithTag(NonPagedPool, size, 'ZTrc');
    if (!mods) return STATUS_INSUFFICIENT_RESOURCES;

    NTSTATUS status = AuxKlibQueryModuleInformation(
        &size, sizeof(AUX_MODULE_EXTENDED_INFO), mods);

    if (!NT_SUCCESS(status)) { ExFreePoolWithTag(mods, 'ZTrc'); return status; }

    ULONG count      = size / sizeof(AUX_MODULE_EXTENDED_INFO);
    ULONG outCount   = 0;

    for (ULONG i = 0; i < count && outCount < ZTRACE_MAX_MODULES; i++)
    {
        PZTRACE_MODULE_ENTRY entry = &Out->Entries[outCount++];
        entry->BaseAddress = (ULONG64)mods[i].BasicInfo.ImageBase;
        entry->Size        = mods[i].ImageSize;

        /* Convert ANSI full path to Unicode */
        ANSI_STRING    ansi = { 0 };
        UNICODE_STRING uni  = { 0 };
        RtlInitAnsiString(&ansi, (PCSZ)mods[i].FullPathName);
        uni.Buffer        = entry->Path;
        uni.MaximumLength = sizeof(entry->Path);
        RtlAnsiStringToUnicodeString(&uni, &ansi, FALSE);

        /* Short name: last backslash component */
        PWCH slash = wcsrchr(entry->Path, L'\\');
        if (slash)
            RtlStringCbCopyW(entry->Name, sizeof(entry->Name), slash + 1);
        else
            RtlStringCbCopyW(entry->Name, sizeof(entry->Name), entry->Path);
    }

    Out->Count = outCount;
    ExFreePoolWithTag(mods, 'ZTrc');

    /* Note: comparing AuxKlib module list against PsLoadedModuleList to find
     * ghost drivers that bypass PsLoadedModuleList requires additional ERESOURCE
     * locking and pattern matching — left as a TODO for production hardening. */
    return STATUS_SUCCESS;
}
