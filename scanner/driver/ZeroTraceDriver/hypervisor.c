/*
 * ZeroTrace Kernel Driver - Hypervisor / VM Detection
 *
 * Detecting a hypervisor matters because:
 *   a) Cheats running in a separate VM (Type-1/bare-metal hypervisor) are
 *      invisible to the OS-level scan running in the guest. The presence
 *      of a nested hypervisor (e.g. Hyper-V inside VMware) is a red flag.
 *   b) Some cheat loaders use a custom Type-2 hypervisor to hide ring-0
 *      driver pages from the kernel's loaded-module list and PatchGuard.
 *   c) A bare gaming PC should NOT be running inside a VM. Detecting a
 *      bare-metal hypervisor (HVCI aside) is therefore suspicious.
 *
 * HVCI (Hypervisor-Protected Code Integrity) is a Windows Security Feature
 * that itself requires Hyper-V. We identify and whitelist it so we don't
 * report a false positive on hardened Windows 11 machines.
 */
#include <ntddk.h>
#include <intrin.h>
#include "hypervisor.h"
#include "ioctl.h"

/* ── Inline helper ────────────────────────────────────────────────────────── */
static void CpuidLeaf(ULONG32 leaf, ULONG32* eax, ULONG32* ebx, ULONG32* ecx, ULONG32* edx)
{
    int info[4];
    __cpuid(info, (int)leaf);
    *eax = (ULONG32)info[0]; *ebx = (ULONG32)info[1];
    *ecx = (ULONG32)info[2]; *edx = (ULONG32)info[3];
}

/* ── Hypervisor detection ─────────────────────────────────────────────────── */
NTSTATUS ZtDetectHypervisor(PZTRACE_HYPERVISOR_INFO Out)
{
    if (!Out) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Out, sizeof(*Out));

    ULONG32 eax, ebx, ecx, edx;

    /* ── Step 1: HV_PRESENT bit ────────────────────────────────────────────── */
    CpuidLeaf(1, &eax, &ebx, &ecx, &edx);
    if (!(ecx & (1u << 31)))
    {
        /* No hypervisor present */
        Out->Present = FALSE;
        Out->Type    = ZTRACE_HV_NONE;
        return STATUS_SUCCESS;
    }

    Out->Present = TRUE;

    /* ── Step 2: Vendor identification ─────────────────────────────────────── */
    CpuidLeaf(0x40000000, &eax, &ebx, &ecx, &edx);
    Out->MaxLeaf = eax;

    /* Vendor string: EBX + ECX + EDX = 12 ASCII bytes */
    RtlCopyMemory(&Out->VendorString[0], &ebx, 4);
    RtlCopyMemory(&Out->VendorString[4], &ecx, 4);
    RtlCopyMemory(&Out->VendorString[8], &edx, 4);
    Out->VendorString[12] = '\0';

    /* Classify known vendors */
    if (RtlCompareMemory(Out->VendorString, "Microsoft Hv", 12) == 12)
        Out->Type = ZTRACE_HV_HYPER_V;
    else if (RtlCompareMemory(Out->VendorString, "VMwareVMware", 12) == 12)
        Out->Type = ZTRACE_HV_VMWARE;
    else if (RtlCompareMemory(Out->VendorString, "KVMKVMKVM\0\0\0", 12) == 12)
        Out->Type = ZTRACE_HV_KVM;
    else if (RtlCompareMemory(Out->VendorString, "XenVMMXenVMM", 12) == 12)
        Out->Type = ZTRACE_HV_XEN;
    else if (RtlCompareMemory(Out->VendorString, "VBoxVBoxVBox", 12) == 12)
        Out->Type = ZTRACE_HV_VIRTUALBOX;
    else if (RtlCompareMemory(Out->VendorString, "prl hyperv  ", 12) == 12)
        Out->Type = ZTRACE_HV_PARALLELS;
    else
        Out->Type = ZTRACE_HV_UNKNOWN;

    /* ── Step 3: RDTSC timing (VM-exit cost measurement) ───────────────────── */
    /* Execute CPUID three times: first two warm up caches, third is measured */
    ULONG32 dummy0, dummy1, dummy2, dummy3;
    CpuidLeaf(1, &dummy0, &dummy1, &dummy2, &dummy3);
    CpuidLeaf(1, &dummy0, &dummy1, &dummy2, &dummy3);

    ULONG64 t1 = __rdtsc();
    CpuidLeaf(1, &dummy0, &dummy1, &dummy2, &dummy3);
    ULONG64 t2 = __rdtsc();
    ULONG64 cycles = (t2 > t1) ? (t2 - t1) : 0;

    Out->CpuidCycles = cycles;
    /* Bare-metal CPUID: ~20-300 cycles. Hypervisor VM-exit: typically >500.
     * Use 1000 cycles as the threshold to reduce false positives on slow CPUs. */
    Out->TimingAnomalyDetected = (cycles > 1000);

    return STATUS_SUCCESS;
}
