#include <Windows.h>
#include <strsafe.h>
#include <Shlwapi.h>
#include "Standard.h"
#include "Hooks.h"

typedef enum _KERNELMAP_FLAGS {
	None = 0,
	MapToExisting = 1 << 0,
	MapToNew = 1 << 1,
	NoHooks = 1 << 2,
	FakeEnvironment = 1 << 3,
	ShowDebugInfo = 1 << 4,
} KERNELMAP_FLAGS;

INT32 Main() {
	FunctionTable = (PVOID*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 4096);

	if (AddDllDirectory(L"C:\\Windows\\System32\\drivers\\") == NULL) {
		PrintF("Could not add \\drivers\\ to dll search directory! %d\n", GetLastError());
		return GetLastError();
	}

	PrintF("Welcome to KernelBox's KernelMap!\n");
	PrintF("Give it a star, will ya? github.com/vlltx/KernelBox\n");
	PrintF("Donate for my Mercedes, will ya?\n\n");

	INT32 argCount = 0;
	LPWSTR* commandLine = CommandLineToArgvW(GetCommandLineW(), &argCount);
	KERNELMAP_FLAGS flags = None;
	DWORD pid = 0;
	LPWSTR newPath = NULL;

	if (argCount == 1) {
		PrintF("No arguments specified!\n");
		PrintF("Usage: KernelBox.exe [OPTIONS] <File Path>\n");
		PrintF("Options are:\n");
		//PrintF("	-p <pid>	Choose the process to map the file into.\n");
		//PrintF("	-px <path>	Start the process to map the file into. Incompatible with -p.\n");
		PrintF("	-u		Don't do any hooks. Just execute driver code.\n");
		PrintF("	-f		Fake the environment as System process.\n");
		PrintF("	-d		Show debug information (displays cool stuff).\n");
		PrintF("Including no options means none of them are activated and the driver is mapped on current process.\n");
		return 1;
	}

	SIZE_T argLength = 0;

	INT32 Index = 1;
	do{
		HRESULT result = StringCchLengthW(commandLine[Index], 1024, &argLength);
		if (result != S_OK) {
			PrintF("There was a problem parsing the command line arguments. %d\n", result);
			return result;
		}

		if (CompareStringEx(LOCALE_NAME_INVARIANT, NORM_IGNORECASE, commandLine[Index], argLength, L"-p", -1, NULL, 0, NULL) == CSTR_EQUAL && !(argCount < (Index +1))) {
			if (CHECK_FLAG(flags, MapToNew)) {
				PrintF("Incompatible flags found!\n");
				return 1;
			}

			flags |= MapToExisting;
			if (!StrToIntExW(commandLine[Index + 1], STIF_SUPPORT_HEX, &pid)) {
				PrintF("There was a problem parsing the pid for -p argument!\n");
				return 1;
			}

			Index++; // Index + 1 equals to our PID and should be skipped.
		} else if (CompareStringEx(LOCALE_NAME_INVARIANT, NORM_IGNORECASE, commandLine[Index], argLength, L"-f", -1, NULL, 0, NULL) == CSTR_EQUAL) {
			flags |= FakeEnvironment;
		}
		else if (CompareStringEx(LOCALE_NAME_INVARIANT, NORM_IGNORECASE, commandLine[Index], argLength, L"-d", -1, NULL, 0, NULL) == CSTR_EQUAL) {
			flags |= ShowDebugInfo;
		} else if (CompareStringEx(LOCALE_NAME_INVARIANT, NORM_IGNORECASE, commandLine[Index], argLength, L"-px", -1, NULL, 0, NULL) == CSTR_EQUAL && !(argCount < (Index + 1))) {
			if (CHECK_FLAG(flags, MapToExisting)) {
				PrintF("Incompatible flags found!\n");
				return 1;
			}

			flags |= MapToNew;
			newPath = commandLine[Index + 1];

			Index++; // Index + 1 equals to our path and should be skipped.
		} else if (CompareStringEx(LOCALE_NAME_INVARIANT, NORM_IGNORECASE, commandLine[Index], argLength, L"-u", -1, NULL, 0, NULL) == CSTR_EQUAL) {
			flags |= NoHooks;
		}

		Index++;
	} while (Index <= argCount - 1 - 1); // -1 because last argument HAS to be the path to driver. And another -1 because the arrays start from 0.

	PrintF("Finished reading command line arguments. Loading driver into memory...\n");
	HANDLE hFile = CreateFileW(commandLine[argCount - 1], FILE_READ_ACCESS | FILE_WRITE_ACCESS | FILE_EXECUTE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		PrintFW(L"Could not open file %s, %d!\n", commandLine[argCount - 1], GetLastError());
		return GetLastError();
	}

	UINT64 fileSize;
	if (!GetFileSizeEx(hFile, &fileSize)) {
		PrintF("Could not get file size %d.\n", GetLastError());
		return GetLastError();
	}

	HANDLE hMap = CreateFileMapping2(hFile, NULL, SECTION_ALL_ACCESS, PAGE_READONLY, SEC_IMAGE, 0, NULL, NULL, NULL);
	if (hMap == NULL) {
		PrintFW(L"Could not map file, %d!\n", GetLastError());
		return GetLastError();
	}

	HANDLE hProcess;

	if (CHECK_FLAG(flags, MapToExisting)) {
		hProcess = OpenProcess(MAXIMUM_ALLOWED, FALSE, pid);
		if (hProcess == NULL) {
			PrintFW(L"Could not open process %d, %d!", pid, GetLastError());
			return GetLastError();
		}
	}
	else if (CHECK_FLAG(flags, MapToNew)) {
		STARTUPINFOW startupInfo;
		PROCESS_INFORMATION processInfo;

		RtlSecureZeroMemory(&startupInfo, sizeof(startupInfo));
		RtlSecureZeroMemory(&processInfo, sizeof(processInfo));

		if (!CreateProcessW(newPath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &startupInfo, &processInfo)) {
			PrintFW(L"Could not launch process %s, %d!", newPath, GetLastError());
			return GetLastError();
		}
	}
	else {
		hProcess = GetCurrentProcess();
	}

	PVOID pMap = MapViewOfFile3(hMap, hProcess, NULL, 0, 0, 0, PAGE_EXECUTE_READWRITE, NULL, NULL);
	if (pMap == NULL) {
		PrintF("Could not map file view, %d!", GetLastError());
		return GetLastError();
	}

	DWORD bytesWritten, oldProtection;

	PrintFW(L"File loaded into memory %s, analyzing...\n", commandLine[argCount - 1]);

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)pMap;
	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(dosHeader->e_lfanew + (PUINT8)pMap);

	if (ntHeaders->OptionalHeader.Subsystem != IMAGE_SUBSYSTEM_NATIVE) {
		PrintF("While its possible for KernelBox to map any PE file and execute it in its environment, that's not its purpose.\n");
		PrintF("(This file is not a kernel driver PE)\n");
		PrintF("(get a driver dawg)\n");
		return 1;
	}

	IMAGE_DATA_DIRECTORY importDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	PIMAGE_IMPORT_DESCRIPTOR importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((PUINT8)pMap + importDirectory.VirtualAddress);

	PrintFW(L"Fixing import table...\n", commandLine[argCount - 1]);

	HMODULE ntdll = GetModuleHandleA("ntdll.dll");

	for (; importDescriptor->Name; importDescriptor++) {
		PCHAR dllName = (PCHAR)((PUINT8)pMap + importDescriptor->Name);
		if (CHECK_FLAG(flags,ShowDebugInfo))
			PrintF("[DEBUG] Found dll import: %s\n", dllName);

		// DONT_RESOLVE_DLL_REFERENCES is required to load fltmgr.sys. No idea why.
		HMODULE mod = LoadLibraryExA(dllName, NULL, LOAD_LIBRARY_SEARCH_DEFAULT_DIRS | DONT_RESOLVE_DLL_REFERENCES);
		if (mod == NULL) {
			PrintF("Could not load %s, %d!\n", dllName, GetLastError());
			return GetLastError();
		}

		PIMAGE_THUNK_DATA thunkData = (PIMAGE_THUNK_DATA)((PUINT8)pMap + importDescriptor->FirstThunk);

		while (thunkData->u1.AddressOfData) {
			PVOID procAddress = NULL;

			LPSTR procName;

			if (IMAGE_SNAP_BY_ORDINAL((UINT64)thunkData)) {
				procName = (LPCSTR)IMAGE_ORDINAL(thunkData->u1.Ordinal);
				procAddress = GetProcAddress(mod, procName);
				if (procAddress == NULL) {
					PrintF("Could not get procedure address... %d\n", GetLastError());
					return GetLastError();
				}
			}
			else {
				PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)((PUINT8)pMap + thunkData->u1.AddressOfData);
				procName = importByName->Name;
				procAddress = GetProcAddress(mod, procName);
				if (procAddress == NULL) {
					PrintF("Could not get procedure address... %d\n", GetLastError());
					return GetLastError();
				}
			}

			if (CHECK_FLAG(flags, ShowDebugInfo))
				PrintF("	[DEBUG] Found function import: %s\n", procName);

			// There we hook

			if (!CHECK_FLAG(flags, NoHooks)) {
				// In theory, most of Zw functions can be redirected to their user-mode Nt counterparts.
				if (RtlCompareMemory(procName, "Zw", 2) == 2) {
					procAddress = GetProcAddress(ntdll, procName);
				}

				if (RtlCompareMemory(procName, "MmGetSystemRoutineAddress", 25) == 25) {
					FunctionTable[MM_GET_SYSTEM_ROUTINE_ADDRESS] = procAddress;
					procAddress = HookTable[MM_GET_SYSTEM_ROUTINE_ADDRESS];
				}
			}

			if (procAddress != NULL)
			{
				if (!VirtualProtectEx(hProcess, thunkData, 1024, PAGE_EXECUTE_READWRITE, &oldProtection)) {
					PrintF("Could not unprotect the mapped image, %d!\n", GetLastError());
					return GetLastError();
				}
				thunkData->u1.Function = procAddress;
			}
			thunkData++;
		}
	}

	PrintF("Patching security checks...\n");

	// These are the fastfail instructions used by stack security checker.

	UINT8 stackCheckFail2[] = { 0xB9, 0x02, 0x00, 0x00, 0x00, 0xCD, 0x29 };
	UINT8 stackCheckFail[] = { 0xB9, 0x06, 0x00, 0x00, 0x00, 0xCD, 0x29};
	UINT8 stackCookiePatch[] = {0xC3};
	PVOID stackFail2 = RtlFindPattern(pMap, ntHeaders->OptionalHeader.SizeOfImage, stackCheckFail2, 7);
	PVOID stackFail = RtlFindPattern(pMap, ntHeaders->OptionalHeader.SizeOfImage, stackCheckFail, 7);

	if (stackFail2 != NULL) {
		// Sanity checks.
		if (!VirtualProtectEx(hProcess, stackFail2, 1024, PAGE_EXECUTE_READWRITE, &oldProtection)) {
			PrintF("[WARN] Could not unprotect the stack check function. Skipping security cookie initialization...\n");
			goto execution;
		}

		if (!WriteProcessMemory(hProcess, stackFail2, stackCookiePatch, 1, &bytesWritten)) {
			PrintF("[WARN] Could not patch the stack check function. Skipping security cookie initialization...\n");
			goto execution;
		}
	}

	if (stackFail != NULL) {
		if (!VirtualProtectEx(hProcess, stackFail, 1024, PAGE_EXECUTE_READWRITE, &oldProtection)) {
			PrintF("[WARN] Could not unprotect the stack check function. Skipping security cookie initialization...\n");
			goto execution;
		}

		if (!WriteProcessMemory(hProcess, stackFail, stackCookiePatch, 1, &bytesWritten)) {
			PrintF("[WARN] Could not patch the stack check function. Skipping security cookie initialization...\n");
			goto execution;
		}
	}

execution:

	PrintF("Begin execution from DriverEntry...\n");
	
	DWORD threadId;
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 1024 * 64, (LPTHREAD_START_ROUTINE)((PUINT8)pMap + ntHeaders->OptionalHeader.AddressOfEntryPoint), NULL, CREATE_SUSPENDED, &threadId);
	if (hThread == NULL) {
		PrintF("Could not begin execution from entrypoint, %d\n", GetLastError());
		return GetLastError();
	}

	PrintF("Setting initial parameters...\n");

	PDRIVER_OBJECT driverObject = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(DRIVER_OBJECT));

	RtlInitUnicodeString(&driverObject->DriverName, L"KernelBox");
	driverObject->DriverSize = fileSize;

	HKEY key;
	LSTATUS status = RegCreateKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\KernelBox\\Sandbox", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_READ, NULL, &key, NULL);
	if (status != ERROR_SUCCESS) {
		PrintF("Could not create key for driver, %d!", status);
		return status;
	}

	CloseHandle(key);

	PUNICODE_STRING registryPath = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(UNICODE_STRING));

	RtlInitUnicodeString(registryPath, L"\\Registry\\Machine\\Software\\KernelBox\\Sandbox");

	CONTEXT ctx;
	RtlSecureZeroMemory(&ctx, sizeof(ctx));

	ctx.ContextFlags = CONTEXT_ALL;

	if (!GetThreadContext(hThread, &ctx)) {
		PrintF("Could not get initial thread context, %d!\n", GetLastError());
		return GetLastError();
	}

	ctx.Rip = ((PUINT8)pMap + ntHeaders->OptionalHeader.AddressOfEntryPoint);
	ctx.Rcx = driverObject;
	ctx.Rdx = registryPath;

	if (!SetThreadContext(hThread, &ctx)) {
		PrintF("Could not set initial thread context, %d!\n", GetLastError());
		return GetLastError();
	}

	DebugBreak();

	ResumeThread(hThread);

	PrintF("Thread began execution with id %d!\n", threadId);

	return 0;
}