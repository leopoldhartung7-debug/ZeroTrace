/*
 * ZeroTrace Kernel Driver - IOCTL Interface
 * Shared between driver (ring-0) and userland (ring-3) bridge.
 *
 * Build with: WDK 11 (Windows Driver Kit), Visual Studio 2022
 * Target: Windows 10 1903+ x64, kernel mode
 */
#pragma once

#ifdef _KERNEL_MODE
#include <ntddk.h>
#include <wdm.h>
#else
#include <windows.h>
#endif

/* ── Device paths ─────────────────────────────────────────────────────────── */
#define ZTRACE_DEVICE_NAME      L"\\Device\\ZeroTrace"
#define ZTRACE_SYMLINK_NAME     L"\\DosDevices\\ZeroTrace"
#define ZTRACE_USERLAND_PATH    L"\\\\.\\ZeroTrace"
#define ZTRACE_DEVICE_TYPE      FILE_DEVICE_UNKNOWN

/* ── IOCTL codes ──────────────────────────────────────────────────────────── */
#define ZTRACE_BASE 0x800

/* Returns ZTRACE_PROCESS_LIST: full kernel-level process list (cannot be DKOM-hidden) */
#define IOCTL_ZTRACE_GET_PROCESSES \
    CTL_CODE(FILE_DEVICE_UNKNOWN, ZTRACE_BASE + 0, METHOD_BUFFERED, FILE_READ_ACCESS)

/* Returns ZTRACE_HOOK_LIST: hooked NT syscall entries (SSDT scan) */
#define IOCTL_ZTRACE_GET_HOOKS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, ZTRACE_BASE + 1, METHOD_BUFFERED, FILE_READ_ACCESS)

/* Returns ZTRACE_MODULE_LIST: loaded kernel modules not in PsLoadedModuleList */
#define IOCTL_ZTRACE_GET_HIDDEN_DRIVERS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, ZTRACE_BASE + 2, METHOD_BUFFERED, FILE_READ_ACCESS)

/* Returns ZTRACE_CALLBACK_LIST: registered PsSetCreateProcess/Thread callbacks */
#define IOCTL_ZTRACE_GET_CALLBACKS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, ZTRACE_BASE + 3, METHOD_BUFFERED, FILE_READ_ACCESS)

/* Returns ZTRACE_HANDLE_RESULT: cross-process VM_READ handles to game processes */
#define IOCTL_ZTRACE_SCAN_HANDLES \
    CTL_CODE(FILE_DEVICE_UNKNOWN, ZTRACE_BASE + 4, METHOD_BUFFERED, FILE_READ_ACCESS)

/* Input: ZTRACE_PHYSICAL_READ_REQUEST; Output: ZTRACE_PHYSICAL_READ_RESULT.
 * Reads raw physical RAM via MmMapIoSpace, bypassing all software memory hooks. */
#define IOCTL_ZTRACE_READ_PHYSICAL \
    CTL_CODE(FILE_DEVICE_UNKNOWN, ZTRACE_BASE + 5, METHOD_BUFFERED, FILE_READ_ACCESS)

/* Input: ZTRACE_VAD_REQUEST (PID); Output: ZTRACE_VAD_LIST.
 * Enumerates all virtual memory regions of the target process and flags
 * executable-private regions (code injection / reflective DLL). */
#define IOCTL_ZTRACE_GET_VAD \
    CTL_CODE(FILE_DEVICE_UNKNOWN, ZTRACE_BASE + 6, METHOD_BUFFERED, FILE_READ_ACCESS)

/* Output: ZTRACE_HYPERVISOR_INFO.
 * CPUID-based hypervisor detection with RDTSC timing verification. */
#define IOCTL_ZTRACE_DETECT_HYPERVISOR \
    CTL_CODE(FILE_DEVICE_UNKNOWN, ZTRACE_BASE + 7, METHOD_BUFFERED, FILE_READ_ACCESS)

/* ── Shared structures ────────────────────────────────────────────────────── */
#define ZTRACE_MAX_PROCESSES    2048
#define ZTRACE_MAX_HOOKS         512
#define ZTRACE_MAX_MODULES       512
#define ZTRACE_MAX_CALLBACKS     128
#define ZTRACE_MAX_HANDLES       256
#define ZTRACE_MAX_VAD_ENTRIES  4096
#define ZTRACE_PHYS_READ_MAX    4096
#define ZTRACE_NAME_LEN           64

#pragma pack(push, 8)

typedef struct _ZTRACE_PROCESS_ENTRY {
    ULONG  ProcessId;
    ULONG  ParentProcessId;
    ULONG  ThreadCount;
    ULONG  Flags;               /* 0x1 = hidden from userland Toolhelp32 */
    ULONG64 CreateTime;
    WCHAR  ImageName[ZTRACE_NAME_LEN];
    WCHAR  FullPath[260];
} ZTRACE_PROCESS_ENTRY;

typedef struct _ZTRACE_PROCESS_LIST {
    ULONG               Count;
    ULONG               HiddenCount;  /* entries with Flags & 0x1 */
    ZTRACE_PROCESS_ENTRY Entries[ZTRACE_MAX_PROCESSES];
} ZTRACE_PROCESS_LIST;

typedef struct _ZTRACE_HOOK_ENTRY {
    ULONG64 FunctionAddress;
    ULONG64 HookTarget;             /* where the JMP/INT3 redirects to */
    WCHAR   FunctionName[ZTRACE_NAME_LEN];
    WCHAR   TargetModuleName[ZTRACE_NAME_LEN];
    UCHAR   OriginalBytes[8];
    UCHAR   CurrentBytes[8];
} ZTRACE_HOOK_ENTRY;

typedef struct _ZTRACE_HOOK_LIST {
    ULONG             Count;
    ZTRACE_HOOK_ENTRY Entries[ZTRACE_MAX_HOOKS];
} ZTRACE_HOOK_LIST;

typedef struct _ZTRACE_MODULE_ENTRY {
    ULONG64 BaseAddress;
    ULONG   Size;
    ULONG   Flags;          /* 0x1 = not in PsLoadedModuleList (ghost driver) */
    WCHAR   Name[ZTRACE_NAME_LEN];
    WCHAR   Path[260];
} ZTRACE_MODULE_ENTRY;

typedef struct _ZTRACE_MODULE_LIST {
    ULONG              Count;
    ZTRACE_MODULE_ENTRY Entries[ZTRACE_MAX_MODULES];
} ZTRACE_MODULE_LIST;

typedef struct _ZTRACE_CALLBACK_ENTRY {
    ULONG64 CallbackAddress;
    ULONG   Type;           /* 0=CreateProcess, 1=CreateThread, 2=LoadImage */
    WCHAR   OwnerModule[ZTRACE_NAME_LEN];
} ZTRACE_CALLBACK_ENTRY;

typedef struct _ZTRACE_CALLBACK_LIST {
    ULONG               Count;
    ZTRACE_CALLBACK_ENTRY Entries[ZTRACE_MAX_CALLBACKS];
} ZTRACE_CALLBACK_LIST;

typedef struct _ZTRACE_HANDLE_ENTRY {
    ULONG  OwnerPid;
    ULONG  VictimPid;
    ULONG  GrantedAccess;
    WCHAR  OwnerName[ZTRACE_NAME_LEN];
    WCHAR  VictimName[ZTRACE_NAME_LEN];
} ZTRACE_HANDLE_ENTRY;

typedef struct _ZTRACE_HANDLE_RESULT {
    ULONG              Count;
    ZTRACE_HANDLE_ENTRY Entries[ZTRACE_MAX_HANDLES];
} ZTRACE_HANDLE_RESULT;

/* ── Physical memory ──────────────────────────────────────────────────────── */
typedef struct _ZTRACE_PHYSICAL_READ_REQUEST {
    ULONG64 PhysicalAddress;
    ULONG   Length;          /* 1 .. ZTRACE_PHYS_READ_MAX bytes */
    ULONG   Reserved;
} ZTRACE_PHYSICAL_READ_REQUEST, *PZTRACE_PHYSICAL_READ_REQUEST;

typedef struct _ZTRACE_PHYSICAL_READ_RESULT {
    ULONG BytesRead;
    ULONG Reserved;
    UCHAR Buffer[ZTRACE_PHYS_READ_MAX];
} ZTRACE_PHYSICAL_READ_RESULT, *PZTRACE_PHYSICAL_READ_RESULT;

/* ── Virtual Address Descriptor (VAD) ────────────────────────────────────── */
typedef struct _ZTRACE_VAD_REQUEST {
    ULONG ProcessId;
} ZTRACE_VAD_REQUEST, *PZTRACE_VAD_REQUEST;

typedef struct _ZTRACE_VAD_ENTRY {
    ULONG64 BaseAddress;
    ULONG64 RegionSize;
    ULONG   State;    /* MEM_COMMIT=0x1000, MEM_RESERVE=0x2000, MEM_FREE=0x10000 */
    ULONG   Protect;  /* PAGE_* constants */
    ULONG   Type;     /* MEM_IMAGE=0x1000000, MEM_MAPPED=0x40000, MEM_PRIVATE=0x20000 */
    ULONG   Flags;    /* 0x1=executable, 0x2=exec-private (injection indicator) */
} ZTRACE_VAD_ENTRY, *PZTRACE_VAD_ENTRY;

typedef struct _ZTRACE_VAD_LIST {
    ULONG           Count;
    ULONG           ProcessId;
    ZTRACE_VAD_ENTRY Entries[ZTRACE_MAX_VAD_ENTRIES];
} ZTRACE_VAD_LIST, *PZTRACE_VAD_LIST;

/* ── Hypervisor ───────────────────────────────────────────────────────────── */
typedef enum _ZTRACE_HV_TYPE {
    ZTRACE_HV_NONE        = 0,
    ZTRACE_HV_UNKNOWN     = 1,
    ZTRACE_HV_HYPER_V     = 2, /* Microsoft Hyper-V / HVCI */
    ZTRACE_HV_VMWARE      = 3,
    ZTRACE_HV_KVM         = 4,
    ZTRACE_HV_XEN         = 5,
    ZTRACE_HV_VIRTUALBOX  = 6,
    ZTRACE_HV_PARALLELS   = 7,
} ZTRACE_HV_TYPE;

typedef struct _ZTRACE_HYPERVISOR_INFO {
    BOOLEAN        Present;
    BOOLEAN        TimingAnomalyDetected; /* RDTSC delta > 1000 cycles */
    UCHAR          Padding[2];
    ZTRACE_HV_TYPE Type;
    ULONG          MaxLeaf;           /* highest supported hypervisor CPUID leaf */
    CHAR           VendorString[16];  /* 12 ASCII chars + NUL */
    ULONG64        CpuidCycles;       /* RDTSC delta across CPUID(1) — VM-exit cost */
} ZTRACE_HYPERVISOR_INFO, *PZTRACE_HYPERVISOR_INFO;

#pragma pack(pop)
