// dll_injection.cpp : 콘솔 응용 프로그램에 대한 진입점을 정의합니다.
//

#include "stdafx.h"

BOOL injection(DWORD pid, char *szDllName)
{
	HANDLE hProc;
	hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (hProc == NULL)
	{
		errorLOG("OpenProcess()");
		return FALSE;
	}

	TCHAR szProcessName[MAX_PATH];
	if (GetModuleFileNameExW(hProc, NULL, szProcessName, MAX_PATH) == 0)
	{
		errorLOG("GetModuleFileNameExW()");
		return FALSE;
	}
	wprintf(L"path : %s\n", szProcessName);

	LPVOID pRemoteBuf = NULL;
	DWORD dwBufSize = strlen(szDllName) + sizeof(char);
	pRemoteBuf = VirtualAllocEx(hProc, NULL, dwBufSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
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

	return TRUE;
}

int _tmain(int argc, _TCHAR *argv[])
{
	_wsetlocale(LC_ALL, L"korean");

	//if (argc != 3)
	//{
	//	wprintf(L"usage : %s <pid> <dll_path>", argv[0]);
	//	return -1;
	//}

	argv[1] = L"11424";
	argv[2] = L"stealth.dll";

	char *szDllName;
	int strSize = WideCharToMultiByte(CP_ACP, 0, argv[2], -1, NULL, 0, NULL, NULL);
	szDllName = new char[strSize];
	WideCharToMultiByte(CP_ACP, 0, argv[2], -1, szDllName, strSize, 0, 0);

	DWORD pid;
	TCHAR *pEnd;
	pid = wcstol(argv[1], &pEnd, 10);

	if (injection(pid, szDllName) == FALSE)
	{
		errorLOG("injection()");
		return -1;
	}

	return 0;
}
