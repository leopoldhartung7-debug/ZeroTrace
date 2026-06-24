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

/* ── Shared structures ────────────────────────────────────────────────────── */
#define ZTRACE_MAX_PROCESSES  2048
#define ZTRACE_MAX_HOOKS       512
#define ZTRACE_MAX_MODULES     512
#define ZTRACE_MAX_CALLBACKS   128
#define ZTRACE_MAX_HANDLES     256
#define ZTRACE_NAME_LEN         64

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

#pragma pack(pop)
