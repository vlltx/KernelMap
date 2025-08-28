#pragma once
#include <Windows.h>
#include <winternl.h>

/*
	@brief Just makes the life a bit easier.

	@param f	The flags enum to check against.
	@param x	The flag to check with.

*/
#define CHECK_FLAG(f, x) ((f & x) == x)

/*
	@brief Wrapper around WriteConsole with formatting.

	Because I hate std. And I am not willing to allocate, strlen strings everytime I want to print something out.
	
	@param Format	Format of the string to display. Does not strictly have to be Unicode.
*/
VOID PrintFW(LPWSTR Format, ...);
VOID PrintF(LPSTR Format, ...);


/*
	@brief Searches for a pattern in memory area.

	Returns after the first match, ignores the rest!

	@param Source	Source memory block.
	@param SourceLength	Length of the source memory block.
	@param Pattern	Pattern to search for.
	@param PatternLength	Length of the pattern.

	@return First match of the pattern
*/
PVOID RtlFindPattern(PVOID Source, SIZE_T SourceLength, PVOID Pattern, SIZE_T PatternLength);

/*
	@brief Copies memory from source to destination.

	I cannot believe there is no actual implementation of RtlCopyMemory, and that somehow RtlCopyDeviceMemory isn "unreferenced".

	@param Source	Source memory block to copy from.
	@param Destination	Destination memory block to copy to.
	@param Length	Length of the block to copy and write to.
*/
VOID RtlCopyMemory2(PVOID Source, PVOID Destination, SIZE_T Length);

EXTERN_C NTSTATUS LdrLoadDll(PWCHAR PathToFile, ULONG Flags, PUNICODE_STRING ModuleName, PHANDLE Handle);

typedef struct _BASE_RELOCATION_BLOCK {
	DWORD PageAddress;
	DWORD BlockSize;
} BASE_RELOCATION_BLOCK, *PBASE_RELOCATION_BLOCK;

typedef struct _BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, *PBASE_RELOCATION_ENTRY;

typedef struct _DRIVER_OBJECT {
	SHORT	Type;
	SHORT	Size;
	PVOID	DeviceObject;
	ULONG	Flags;
	PVOID	DriverStart;
	ULONG	DriverSize;
	PVOID	DriverSection;
	PVOID	DriverExtension;
	UNICODE_STRING	DriverName;
	PUNICODE_STRING	HardwareDatabase;
	PVOID	FastIoDispatch;
	PVOID	DriverInit;
	PVOID	DriverStartIo;
	PVOID	DriverUnload;
	PVOID	MajorFunction[0x1B + 1];
} DRIVER_OBJECT, * PDRIVER_OBJECT;