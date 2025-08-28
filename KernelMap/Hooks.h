#pragma once
#include <Windows.h>
#include <winternl.h>

EXTERN_C PVOID HookTable[];
EXTERN_C PVOID* FunctionTable;

#define MM_GET_SYSTEM_ROUTINE_ADDRESS 0
#define PS_GET_VERSION 1

typedef PVOID (NTAPI* MmGetSystemRoutineAddressType)(PUNICODED_STRING RoutineName);

PVOID KmMmGetSystemRoutineAddress(PUNICODE_STRING RoutineName);

NTSTATUS KmPsGetVersion(PULONG MajorVersion, PULONG MinorVersion, PULONG BuildNumber, PUNICODE_STRING CSDVersion);
