#pragma once
#include <ntddk.h>
#include "ioctl.h"

NTSTATUS ZtScanSsdtHooks   (PZTRACE_HOOK_LIST   Out);
NTSTATUS ZtFindHiddenDrivers(PZTRACE_MODULE_LIST Out);
