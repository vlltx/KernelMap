# KernelMap
Map and execute kernel drivers in usermode.

## TL;DR
- Map any kernel drivers to current process memory.
- Signed or unsigned, maps them all.
- Bypasses stack security checks (/GS).
- Automatically resolves imports (fltmgr.sys etc.)
- Redirects Zw functions to their ntdll counterparts.
- Allocates the DRIVER_OBJECT and RegistryPath for the DriverEntry.
- Most runtime functions work out of the box (RtlInitUnicodeString, MmGetSystemRoutineAddress etc.)
- Extensible and easy hook for any other imported method (using IAT hooking)
- Supports and works only on x86_64.

## Why?
Because there is no simple and extensible way to test drivers, and you have to restart your computer everytime you get a MEMORY_MANAGEMENT.
Even though the main purpose of KernelMap is to learn and have fun, I believe it adds much more than that.

## How?
A .sys file, just like an .exe and a .dll, is a Portable Executable file format that differs no more than the others mentioned.
The only thing keeping us away from actually executing a kernel driver in usermode is its subsystem, which is NATIVE instead of Console like most other .exe files are.
So we map the file, we find the entrypoint, we hook our IAT and set the thread context to begin execution from DriverEntry.

## WARNING
This does NOT execute drivers in kernel mode. The concept of IRQL, privileged instructions and unsupervised memory access are non existent (but easily fakeable with bytecode patches).
Most of the Nt kernel functions aren't hooked, but its not hard to do so.

THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT ANY WARRANTY OR RESPONSIBILITY FROM THE DEVELOPER.
