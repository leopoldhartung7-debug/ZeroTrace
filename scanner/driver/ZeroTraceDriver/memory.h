/*
 * ZeroTrace Kernel Driver - Physical Memory & VAD Tree Scanner
 *
 * Provides two capabilities:
 *   1. Direct physical memory reads via MmMapIoSpace — bypasses any
 *      userland/kernel memory hooks that filter VirtualReadMemory.
 *   2. Virtual Address Descriptor (VAD) enumeration via ZwQueryVirtualMemory —
 *      reports all committed memory regions in a target process, including
 *      executable-private regions that indicate code injection.
 */
#pragma once
#include <ntddk.h>
#include "ioctl.h"

/* Read `Length` bytes from the physical address `PhysAddress` into `Buffer`.
 * Uses MmMapIoSpace (no cache); maximum length is ZTRACE_PHYS_READ_MAX.
 * Returns STATUS_INSUFFICIENT_RESOURCES if MmMapIoSpace fails. */
NTSTATUS ZtReadPhysicalMemory(PHYSICAL_ADDRESS PhysAddress, PVOID Buffer, SIZE_T Length);

/* Enumerate all virtual memory regions of process `ProcessId` by calling
 * ZwQueryVirtualMemory while holding an object reference to the process.
 * Flags executable-private regions (MEM_PRIVATE + PAGE_EXECUTE_*) as
 * potential code injection sites (Flags |= 0x2). */
NTSTATUS ZtEnumerateVadTree(ULONG ProcessId, PZTRACE_VAD_LIST Out);
