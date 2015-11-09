// Global_API_hook.cpp : 콘솔 응용 프로그램에 대한 진입점을 정의합니다.
//

#include "stdafx.h"

BOOL enable_injection(DWORD pid, char *szDllName)
{
	HANDLE hProc;
	hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (hProc == NULL)
	{
		errorLOG("OpenProcess()");
		return FALSE;
	}

	LPVOID pRemoteBuf = NULL;
	DWORD dwBufSize = strlen(szDllName) + sizeof(char);
	pRemoteBuf = VirtualAllocEx(hProc, NULL, dwBufSize, MEM_COMMIT, PAGE_READWRITE);
	if (pRemoteBuf == NULL)
	{
		errorLOG("VirtualAllocEx()");
		return FALSE;
	}

	if (WriteProcessMemory(hProc, pRemoteBuf, (LPVOID)szDllName, dwBufSize, NULL) == FALSE)
	{
		errorLOG("WriteProcessMemory()");
		return FALSE;
	}

	FARPROC pThreadProc = NULL;
	pThreadProc = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");
	if (pThreadProc == NULL)
	{
		errorLOG("GetProcAddress()");
		return FALSE;
	}

	if (CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)pThreadProc, pRemoteBuf, 0, NULL) == NULL)
	{
		errorLOG("CreateRemoteThread()");
		return FALSE;
	}

	//if (WaitForSingleObject(hProc, INFINITE) == WAIT_FAILED)
	//{
	//	errorLOG("WaitForSingleObject()");
	//	return FALSE;
	//}
		
	//if (!VirtualFreeEx(hProc, pRemoteBuf, 0, MEM_RELEASE))
	//{
	//	errorLOG("VirtualFreeEx()");
	//	return FALSE;
	//}

	//if (!CloseHandle(hProc))
	//{
	//	errorLOG("CloseHandle()");
	//	return FALSE;
	//}

	return TRUE;
}

BOOL disable_injection(DWORD pid, char *szDllName, LPCTSTR szDllPath)
{
	BOOL bMore = FALSE, bFound = FALSE;
	HANDLE   hSnapshot, hProcess, hThread;
	MODULEENTRY32 me = { sizeof(me) };
	LPTHREAD_START_ROUTINE  pThreadProc;

	if (INVALID_HANDLE_VALUE ==	(hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid)))
		return FALSE;

	bMore = Module32First(hSnapshot, &me);
	for (; bMore; bMore = Module32Next(hSnapshot, &me))
	{
		if (!_wcsicmp(me.szModule, szDllPath) || !_wcsicmp(me.szExePath, szDllPath))
		{
			bFound = TRUE;
			break;
		}
	}

	if (!bFound)
	{
		CloseHandle(hSnapshot);
		return FALSE;
	}

	if (!(hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid)))
	{
		errorLOG("OpenProcess()");
		CloseHandle(hSnapshot);
		return FALSE;
	}
	
	pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "FreeLibrary");
	if (pThreadProc == NULL)
	{
		errorLOG("GetProcAddress()");
		return FALSE;
	}

	hThread = CreateRemoteThread(hProcess, NULL, 0,	pThreadProc, me.modBaseAddr, 0, NULL);
	{
		errorLOG("CreateRemoteThread()");
		return FALSE;
	}

	//if (WaitForSingleObject(hProcess, INFINITE) == WAIT_FAILED)
	//{
	//	errorLOG("WaitForSingleObject()");
	//	return FALSE;
	//}

	if (!CloseHandle(hThread))
	{
		errorLOG("CloseHandle()");
		return FALSE;
	}

	if (!CloseHandle(hProcess))
	{
		errorLOG("CloseHandle()");
		return FALSE;
	}

	if (!CloseHandle(hSnapshot))
	{
		errorLOG("CloseHandle()");
		return FALSE;
	}

	return TRUE;
}

BOOL global_api_hook(BOOL mode, LPCTSTR szDllPath)
{
	DWORD dwPID = 0;
	HANDLE hSnapShot = INVALID_HANDLE_VALUE;
	PROCESSENTRY32 pe;

	char *szDllName;
	int strSize = WideCharToMultiByte(CP_ACP, 0, szDllPath, -1, NULL, 0, NULL, NULL);
	szDllName = new char[strSize];
	WideCharToMultiByte(CP_ACP, 0, szDllPath, -1, szDllName, strSize, 0, 0);

	pe.dwSize = sizeof(PROCESSENTRY32);
	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);

	Process32First(hSnapShot, &pe);
	do
	{
		dwPID = pe.th32ProcessID;

		if (dwPID < 100)
			continue;

		if (mode == TRUE)
		{
			printf("enable_injection : %d\n", dwPID);
			enable_injection(dwPID, szDllName);
		}
			
		else
		{
			printf("disable_injection : %d\n", dwPID);
			disable_injection(dwPID, szDllName, szDllPath);
		}
			
	} while (Process32Next(hSnapShot, &pe));

	CloseHandle(hSnapShot);

	return TRUE;
}

int _tmain(int argc, _TCHAR* argv[])
{
	_wsetlocale(LC_ALL, L"korean");

	//if (argc != 3)
	//{
	//	wprintf(L"usage : %s <-enable | -disable> <dll_path>", argv[0]);
	//	return -1;
	//}

	argv[1] = L"-enable";
	argv[2] = L"stealth.dll";

	BOOL hook_status;
	if (!_wcsicmp(argv[1], L"-enable"))
		hook_status = TRUE;
	else if (!_wcsicmp(argv[1], L"-disable"))
		hook_status = FALSE;
	else
	{
		wprintf(L"usage : %s <-enable | -disable> <dll_path>", argv[0]);
		return -1;
	}

	if (SetPrivilege(SE_DEBUG_NAME, TRUE) == FALSE)
		return FALSE;

	if (global_api_hook(hook_status, argv[2]) == FALSE)
	{
		errorLOG("global_api_hook()");
		return -1;
	}

	return 0;
}

