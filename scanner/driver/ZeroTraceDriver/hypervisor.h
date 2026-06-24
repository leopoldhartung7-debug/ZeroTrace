/*
 * ZeroTrace Kernel Driver - Hypervisor / VM Detection
 *
 * Detects whether the system is running inside a hypervisor using two
 * complementary techniques:
 *
 *   1. CPUID leaf 1, ECX bit 31 (HV_PRESENT flag)
 *      Intel/AMD standardized this bit; all major hypervisors set it.
 *
 *   2. CPUID leaf 0x40000000 (Hypervisor CPUID Interface)
 *      Returns a 12-byte ASCII vendor string in EBX/ECX/EDX.
 *      Known vendors: "Microsoft Hv", "VMwareVMware", "KVMKVMKVM\0\0\0",
 *      "XenVMMXenVMM", "VBoxVBoxVBox", "prl hyperv\0\0" (Parallels).
 *
 *   3. RDTSC timing
 *      A CPUID instruction causes a VM-exit on all hypervisors; on bare
 *      metal the CPUID latency is 20-200 cycles; inside a VM it typically
 *      exceeds 1000 cycles. We measure the RDTSC delta across CPUID(1).
 */
#pragma once
#include <ntddk.h>
#include "ioctl.h"

NTSTATUS ZtDetectHypervisor(PZTRACE_HYPERVISOR_INFO Out);
