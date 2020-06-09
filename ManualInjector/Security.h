#pragma once
#include <string>
#include <sysinfoapi.h>
#include <WinBase.h>
#include <TlHelp32.h>
#include "Xor.h"
#include <iostream>


typedef NTSTATUS(WINAPI* TNtReadVirtualMemory)(HANDLE, PVOID, PVOID, ULONG, PULONG);
typedef NTSTATUS(WINAPI* TNtWriteVirtualMemory)(HANDLE, PVOID, PVOID, ULONG, PULONG);


inline bool AntiDebugg3()
{
	__try
	{
		__asm __emit 0xF3 // 0xF3 0x64 disassembles as PREFIX REP:
		__asm __emit 0x64
		__asm __emit 0xF1 // One byte INT 1
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return false;
	}

	return true;
}

inline bool NtGlobals()
{
	DWORD NtGlobalFlags;
	__asm
	{
		mov eax, fs: [30h]
		mov eax, [eax + 68h]
		mov NtGlobalFlags, eax
	}

	if (NtGlobalFlags & 0x70)
		return true;

	return false;
}
