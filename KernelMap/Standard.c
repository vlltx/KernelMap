#include <Windows.h>
#include <strsafe.h>

VOID PrintFW(LPWSTR Format, ...) {
	WCHAR buf[1024];
	RtlSecureZeroMemory(buf, 1024 * 2);

	va_list argList;
	va_start(argList, Format);
	wvsprintfW(buf, Format, argList);
	va_end(argList);
	DWORD written;
	SIZE_T realLen;
	StringCbLengthW(buf, 1024, &realLen);
	WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), buf, realLen, &written, NULL);
}

VOID PrintF(LPSTR Format, ...) {
	CHAR buf[1024];
	RtlSecureZeroMemory(buf, 1024);

	va_list argList;
	va_start(argList, Format);
	wvsprintfA(buf, Format, argList);
	va_end(argList);
	DWORD written;
	SIZE_T realLen;
	StringCbLengthA(buf, 1024, &realLen);
	WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), buf, realLen, &written, NULL);
}

PVOID RtlFindPattern(PVOID Source, SIZE_T SourceLength, PVOID Pattern, SIZE_T PatternLength) {
	SIZE_T Index;

	for (Index = 0; Index <= SourceLength - PatternLength; ++Index) {
		if (RtlCompareMemory((PUINT8)(Source)+Index, Pattern, PatternLength) == PatternLength) return (PUINT8)(Source)+Index;
	}

	return NULL;
}

VOID RtlCopyMemory2(PVOID Source, PVOID Destination, SIZE_T Length) {
	PUINT8 Src = (PUINT8)Source;
	PUINT8 Dst = (PUINT8)Destination;

	SIZE_T Index;
	for (Index = 0; Index <= Length; ++Index) {
		Dst[Index] = Src[Index];
	}
}