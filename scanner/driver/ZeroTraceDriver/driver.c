/*
 * ZeroTrace Kernel Driver - Entry Point & IRP Dispatch
 *
 * Build prerequisites:
 *   - Windows Driver Kit (WDK) 11 / Visual Studio 2022
 *   - Platform: x64 Kernel Mode Driver
 *   - Requires EV code-signing certificate for production use
 *   - Enable test-signing for development:
 *       bcdedit /set testsigning on
 *
 * Load / unload:
 *   sc create ZeroTrace type= kernel binPath= <path>\ZeroTraceDriver.sys
 *   sc start  ZeroTrace
 *   sc stop   ZeroTrace
 *   sc delete ZeroTrace
 */
#include <ntddk.h>
#include <wdm.h>
#include "ioctl.h"
#include "process.h"
#include "hooks.h"
#include "callbacks.h"

/* ── Forwards ─────────────────────────────────────────────────────────────── */
static NTSTATUS ZtDispatchCreate (PDEVICE_OBJECT DevObj, PIRP Irp);
static NTSTATUS ZtDispatchClose  (PDEVICE_OBJECT DevObj, PIRP Irp);
static NTSTATUS ZtDispatchControl(PDEVICE_OBJECT DevObj, PIRP Irp);
       VOID     DriverUnload     (PDRIVER_OBJECT DriverObj);

static PDEVICE_OBJECT g_DeviceObject = NULL;

/* ── DriverEntry ──────────────────────────────────────────────────────────── */
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    UNICODE_STRING devName = RTL_CONSTANT_STRING(ZTRACE_DEVICE_NAME);
    UNICODE_STRING symName = RTL_CONSTANT_STRING(ZTRACE_SYMLINK_NAME);

    /* Create device */
    NTSTATUS status = IoCreateDevice(
        DriverObject,
        0,
        &devName,
        ZTRACE_DEVICE_TYPE,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &g_DeviceObject);

    if (!NT_SUCCESS(status))
    {
        DbgPrint("[ZeroTrace] IoCreateDevice failed: 0x%08X\n", status);
        return status;
    }

    g_DeviceObject->Flags |= DO_BUFFERED_IO;
    g_DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    /* Create symbolic link so userland can open "\\\\.\\ZeroTrace" */
    status = IoCreateSymbolicLink(&symName, &devName);
    if (!NT_SUCCESS(status))
    {
        IoDeleteDevice(g_DeviceObject);
        DbgPrint("[ZeroTrace] IoCreateSymbolicLink failed: 0x%08X\n", status);
        return status;
    }

    DriverObject->DriverUnload                          = DriverUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE]          = ZtDispatchCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]           = ZtDispatchClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]  = ZtDispatchControl;

    DbgPrint("[ZeroTrace] Driver loaded successfully\n");
    return STATUS_SUCCESS;
}

/* ── DriverUnload ─────────────────────────────────────────────────────────── */
VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    UNICODE_STRING symName = RTL_CONSTANT_STRING(ZTRACE_SYMLINK_NAME);
    IoDeleteSymbolicLink(&symName);

    if (g_DeviceObject)
        IoDeleteDevice(g_DeviceObject);

    DbgPrint("[ZeroTrace] Driver unloaded\n");
}

/* ── IRP_MJ_CREATE / CLOSE ────────────────────────────────────────────────── */
static NTSTATUS ZtDispatchCreate(PDEVICE_OBJECT DevObj, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DevObj);
    Irp->IoStatus.Status      = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS ZtDispatchClose(PDEVICE_OBJECT DevObj, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DevObj);
    Irp->IoStatus.Status      = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

/* ── IRP_MJ_DEVICE_CONTROL ────────────────────────────────────────────────── */
static NTSTATUS ZtDispatchControl(PDEVICE_OBJECT DevObj, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DevObj);

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG  code    = stack->Parameters.DeviceIoControl.IoControlCode;
    PVOID  outBuf  = Irp->AssociatedIrp.SystemBuffer;
    ULONG  outLen  = stack->Parameters.DeviceIoControl.OutputBufferLength;
    ULONG  written = 0;
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;

    switch (code)
    {
    case IOCTL_ZTRACE_GET_PROCESSES:
        if (outBuf && outLen >= sizeof(ZTRACE_PROCESS_LIST))
        {
            status = ZtEnumerateProcesses((PZTRACE_PROCESS_LIST)outBuf);
            if (NT_SUCCESS(status)) written = sizeof(ZTRACE_PROCESS_LIST);
        }
        else status = STATUS_BUFFER_TOO_SMALL;
        break;

    case IOCTL_ZTRACE_GET_HOOKS:
        if (outBuf && outLen >= sizeof(ZTRACE_HOOK_LIST))
        {
            status = ZtScanSsdtHooks((PZTRACE_HOOK_LIST)outBuf);
            if (NT_SUCCESS(status)) written = sizeof(ZTRACE_HOOK_LIST);
        }
        else status = STATUS_BUFFER_TOO_SMALL;
        break;

    case IOCTL_ZTRACE_GET_HIDDEN_DRIVERS:
        if (outBuf && outLen >= sizeof(ZTRACE_MODULE_LIST))
        {
            status = ZtFindHiddenDrivers((PZTRACE_MODULE_LIST)outBuf);
            if (NT_SUCCESS(status)) written = sizeof(ZTRACE_MODULE_LIST);
        }
        else status = STATUS_BUFFER_TOO_SMALL;
        break;

    case IOCTL_ZTRACE_GET_CALLBACKS:
        if (outBuf && outLen >= sizeof(ZTRACE_CALLBACK_LIST))
        {
            status = ZtEnumerateCallbacks((PZTRACE_CALLBACK_LIST)outBuf);
            if (NT_SUCCESS(status)) written = sizeof(ZTRACE_CALLBACK_LIST);
        }
        else status = STATUS_BUFFER_TOO_SMALL;
        break;

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status      = status;
    Irp->IoStatus.Information = written;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}
