#include <ntifs.h>

DRIVER_UNLOAD DriverUnload;

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    OBJECT_ATTRIBUTES Attributes;
    InitializeObjectAttributes(&Attributes, NULL, 0, NULL, NULL);

    Attributes.ObjectName = RegistryPath;

    HANDLE Key;
    NTSTATUS Status = ZwOpenKey(&Key, KEY_ALL_ACCESS, &Attributes);
    if (!NT_SUCCESS(Status))
        return STATUS_UNSUCCESSFUL;

    DriverObject->DriverUnload = DriverUnload;

    UNICODE_STRING Name;
    RtlInitUnicodeString(&Name, L"PsGetVersion");

    PVOID Function = MmGetSystemRoutineAddress(&Name);
    UNREFERENCED_PARAMETER(Function);

    ZwClose(Key);

    return STATUS_SUCCESS;
}

VOID
DriverUnload(
    _In_ PDRIVER_OBJECT DriverObject
)
{
    UNREFERENCED_PARAMETER(DriverObject);
}