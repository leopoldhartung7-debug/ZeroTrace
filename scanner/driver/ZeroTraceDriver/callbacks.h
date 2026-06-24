#pragma once
#include <ntddk.h>
#include "ioctl.h"

NTSTATUS ZtEnumerateCallbacks(PZTRACE_CALLBACK_LIST Out);
