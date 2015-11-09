// dllmain.cpp : DLL 응용 프로그램의 진입점을 정의합니다.
#include "stdafx.h"

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{

	TCHAR szProcessName[MAX_PATH];
	PTCHAR p = NULL;
	if (GetModuleFileName(NULL, szProcessName, MAX_PATH) == 0)
		return FALSE;

	p = wcsrchr(szProcessName, L'\\');
	if ((p != NULL) && !_wcsicmp(p + 1, L"Global_API_hook.exe"))
		return TRUE;

	if (SetPrivilege(SE_DEBUG_NAME, TRUE) == FALSE)
		return FALSE;

	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		enable_code_hooking(L"kernel32.dll", "CreateProcessA", (PROC)MyCreateProcessA);
		enable_code_hooking(L"kernel32.dll", "CreateProcessW", (PROC)MyCreateProcessW);
		enable_code_hooking(L"ntdll.dll", "NtQuerySystemInformation", (PROC)MyNtQuerySystemInformation);
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		disable_code_hooking(L"kernel32.dll", "CreateProcessA");
		disable_code_hooking(L"kernel32.dll", "CreateProcessW");
		disable_code_hooking(L"ntdll.dll", "NtQuerySystemInformation");
		break;
	}
	return TRUE;
}

