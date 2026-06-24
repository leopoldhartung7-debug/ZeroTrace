#pragma once
#include <ntddk.h>
#include "ioctl.h"

NTSTATUS ZtEnumerateProcesses(PZTRACE_PROCESS_LIST Out);
