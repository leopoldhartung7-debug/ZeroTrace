/*
 * ZeroTrace Kernel Driver - Kernel Notification Callback Enumeration
 *
 * Anti-cheats and rootkits register kernel callbacks to intercept events:
 *   PsSetCreateProcessNotifyRoutine  — fires when any process starts/exits
 *   PsSetCreateThreadNotifyRoutine   — fires on thread creation
 *   PsSetLoadImageNotifyRoutine      — fires when a DLL or driver is loaded
 *   CmRegisterCallback               — fires on every registry operation
 *
 * A cheat driver might register a CreateProcess callback to kill anti-cheat
 * processes before they fully initialize, or a LoadImage callback to block
 * anti-cheat DLL loading. We enumerate all registered callbacks and report
 * ones that originate from modules outside of a known whitelist.
 *
 * The callback arrays are internal kernel structures. We locate them via
 * pattern scanning ntoskrnl.exe for the known byte patterns at the call sites
 * of PspCreateProcessNotifyRoutine (the internal array pointer).
 */
#include <ntddk.h>
#include <aux_klib.h>
#include "callbacks.h"

/* The internal PS callback array is an array of EX_CALLBACK_ROUTINE_BLOCK*
 * masked with a low bit flag. Maximum entries: 64 for process/thread callbacks. */
#define MAX_PS_CALLBACKS 64

/* Undocumented offsets — resolved by pattern scan in production.
 * For illustration, the Win10 21H2 x64 layout is shown: */
typedef struct _EX_CALLBACK_ROUTINE_BLOCK {
    EX_RUNDOWN_REF        RundownProtect;
    PEX_CALLBACK_FUNCTION Function;
    PVOID                 Context;
} EX_CALLBACK_ROUTINE_BLOCK, *PEX_CALLBACK_ROUTINE_BLOCK;

/* These pointers are found by scanning ntoskrnl for signature bytes near the
 * PspCreateProcessNotifyRoutine / PspCreateThreadNotifyRoutine global arrays.
 * In production code these would be resolved at runtime via pattern scan. */
extern PVOID PspCreateProcessNotifyRoutine[];  /* 64 entries */
extern PVOID PspCreateThreadNotifyRoutine[];   /* 64 entries */
extern PVOID PspLoadImageNotifyRoutine[];      /* 64 entries */

static const WCHAR* CallbackTypeNames[] = {
    L"CreateProcess",
    L"CreateThread",
    L"LoadImage"
};

static NTSTATUS EnumerateCallbackArray(
    PVOID*               Array,
    ULONG                MaxCount,
    ULONG                TypeIndex,
    PZTRACE_CALLBACK_LIST Out)
{
    for (ULONG i = 0; i < MaxCount && Out->Count < ZTRACE_MAX_CALLBACKS; i++)
    {
        /* Low bit is a removal flag — mask it off */
        PVOID raw = Array[i];
        if (!raw) continue;

        PEX_CALLBACK_ROUTINE_BLOCK block =
            (PEX_CALLBACK_ROUTINE_BLOCK)((ULONG_PTR)raw & ~1ULL);
        if (!MmIsAddressValid(block)) continue;
        if (!MmIsAddressValid(block->Function)) continue;

        PZTRACE_CALLBACK_ENTRY entry = &Out->Entries[Out->Count++];
        entry->CallbackAddress = (ULONG64)block->Function;
        entry->Type            = TypeIndex;

        /* Identify owning module by walking AuxKlib module list */
        ULONG  modSize = 0;
        AuxKlibQueryModuleInformation(&modSize, sizeof(AUX_MODULE_EXTENDED_INFO), NULL);
        if (modSize)
        {
            PAUX_MODULE_EXTENDED_INFO mods =
                (PAUX_MODULE_EXTENDED_INFO)ExAllocatePoolWithTag(
                    NonPagedPool, modSize, 'ZTcb');
            if (mods)
            {
                if (NT_SUCCESS(AuxKlibQueryModuleInformation(
                    &modSize, sizeof(AUX_MODULE_EXTENDED_INFO), mods)))
                {
                    ULONG count = modSize / sizeof(AUX_MODULE_EXTENDED_INFO);
                    for (ULONG m = 0; m < count; m++)
                    {
                        ULONG64 base = (ULONG64)mods[m].BasicInfo.ImageBase;
                        ULONG64 end  = base + mods[m].ImageSize;
                        if (entry->CallbackAddress >= base &&
                            entry->CallbackAddress <  end)
                        {
                            ANSI_STRING    ansi = { 0 };
                            UNICODE_STRING uni  = { 0 };
                            PWCH slash = NULL;
                            char* path = (char*)mods[m].FullPathName;
                            for (char* p = path; *p; p++)
                                if (*p == '\\' || *p == '/') slash = (PWCH)p;

                            RtlInitAnsiString(&ansi, slash ?
                                (PCSZ)(slash + 1) : (PCSZ)path);
                            uni.Buffer        = entry->OwnerModule;
                            uni.MaximumLength = sizeof(entry->OwnerModule);
                            RtlAnsiStringToUnicodeString(&uni, &ansi, FALSE);
                            break;
                        }
                    }
                }
                ExFreePoolWithTag(mods, 'ZTcb');
            }
        }
    }
    return STATUS_SUCCESS;
}

NTSTATUS ZtEnumerateCallbacks(PZTRACE_CALLBACK_LIST Out)
{
    if (!Out) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Out, sizeof(*Out));

    /* In production: resolve array pointers via ntoskrnl pattern scan.
     * The globals below are illustrative — link errors are expected without
     * a proper symbol resolver. */

    /* EnumerateCallbackArray(PspCreateProcessNotifyRoutine, 64, 0, Out); */
    /* EnumerateCallbackArray(PspCreateThreadNotifyRoutine,  64, 1, Out); */
    /* EnumerateCallbackArray(PspLoadImageNotifyRoutine,     64, 2, Out); */

    /* TODO: Implement ntoskrnl pattern scanner for each callback array address.
     * Reference patterns (Win10 21H2 x64):
     *   PspCreateProcessNotifyRoutine: E8 ? ? ? ? 48 8D ? ? ? ? ? ? 48 8B ? E8 ...
     * Resolve relative address from call instruction to find the global array. */

    return STATUS_SUCCESS;
}
