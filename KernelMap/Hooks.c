#include <Windows.h>
#include <winternl.h>
#include "Hooks.h"
#include "Standard.h"

PVOID HookTable[] = {
	KmMmGetSystemRoutineAddress,
	KmPsGetVersion
};

PVOID* FunctionTable;

PVOID KmMmGetSystemRoutineAddress(PUNICODE_STRING RoutineName) {
	// No idea why %wZ doesn't work.
	PVOID function = FunctionTable[MM_GET_SYSTEM_ROUTINE_ADDRESS];

	if (RoutineName->Length >= 1024) goto end;

	PVOID buf = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 1024);
	if (buf == NULL) goto end;

	RtlCopyMemory2(RoutineName->Buffer, buf, RoutineName->Length);
	PrintFW(L"[HOOK] Get system routine address for %s\n", buf);


	if (RtlCompareMemory(buf, L"PsGetVersion", 24) == 24) {
		PrintFW(L"	[HOOK] Runtime-hooking import for %s\n", buf);
		function = HookTable[PS_GET_VERSION];
	}

	HeapFree(GetProcessHeap(), 0, buf);

end:
	return function;
}

NTSTATUS KmPsGetVersion(PULONG MajorVersion, PULONG MinorVersion, PULONG BuildNumber, PUNICODE_STRING CSDVersion) {
	if (MajorVersion) *MajorVersion = 10;
	if (MinorVersion) *MinorVersion = 10;
	if (BuildNumber) *BuildNumber = 10;

	return 0;
}