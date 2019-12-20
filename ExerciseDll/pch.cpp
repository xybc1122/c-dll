// pch.cpp: source file corresponding to the pre-compiled header

#include "pch.h"
#include <iostream>
// When you are using pre-compiled headers, this source file is necessary for compilation to succeed.
//+
//call ��ַ
#define _GET_ 0x0C41032
#define _PUT_ 0x0C4118B
#define _DEL_ 0x0C413B6
#define _UP_ 0x0C410F0


DWORD WINAPI ThreadProcTest(LPVOID lpParam) {
	//1 �򿪹����ڴ�
	LPCWSTR map = TEXT("�����ڴ�");
	HANDLE hHandle=OpenFileMapping(FILE_MAP_ALL_ACCESS,FALSE, map);
	if (NULL== hHandle) {
		std::cout << "�򿪹����ڴ�ʧ��" << std::endl;
		return 0;
	}
	//2 ӳ���ڴ�  ����
	LPTSTR lpBuff = (LPTSTR)MapViewOfFile(hHandle, FILE_MAP_ALL_ACCESS, 0, 0, BUFSIZ);
	if (NULL == lpBuff) {
		std::cout << "ӳ���ڴ�ʧ��" << std::endl;
		return 0;
	}
	int dwType = 0;
	while (true)
	{
		//��ȡ�ڴ�����
		CopyMemory(&dwType, lpBuff, 4);
		switch (dwType) {
		case 1:
			printf("���ڹ������� %d ", dwType);
			/*__asm {
				mov eax, _GET_
				call eax
			}*/
			break;
		case 2:
			printf("����PUT���� %d ", dwType);
			/*__asm {
				mov eax, _PUT_
				call eax
			}*/
			break;

		case 3:
			printf("����DEL���� %d ", dwType);
			/*__asm {
				mov eax, _DEL_
				call eax
			}*/
			break;

		case 4:
			printf("����UP���� %d ", dwType);
			/*__asm {
				mov eax, _UP_
				call eax
			}*/
			break;
			/*case 5:
				FreeLibraryAndExitThread(,0);*/
		}


		dwType = 0;
		CopyMemory(lpBuff,&dwType, 4);
		Sleep(1000);
	}
	return 1;
}


typedef struct _LSA_UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
}
UNICODE_STRING, * PUNICODE_STRING;

typedef struct _PEB_LDR_DATA
{
	DWORD Length; // +0x00
	bool Initialized; // +0x04
	PVOID SsHandle; // +0x08
	LIST_ENTRY InLoadOrderModuleList; // +0x0c
	LIST_ENTRY InMemoryOrderModuleList; // +0x14
	LIST_ENTRY InInitializationOrderModuleList;// +0x1c
} PEB_LDR_DATA, * PPEB_LDR_DATA; // +0x24

typedef struct _LDR_MODULE
{
	LIST_ENTRY          InLoadOrderModuleList;
	LIST_ENTRY          InMemoryOrderModuleList;
	LIST_ENTRY          InInitializationOrderModuleList;
	void* BaseAddress;
	void* EntryPoint;
	ULONG               SizeOfImage;
	UNICODE_STRING   FullDllName;
	UNICODE_STRING      BaseDllName;
	ULONG               Flags;
	SHORT               LoadCount;
	SHORT               TlsIndex;
	HANDLE              SectionHandle;
	ULONG               CheckSum;
	ULONG               TimeDateStamp;
} LDR_MODULE, * PLDR_MODULE;


void hudeModule(HMODULE hMod) {
	//��Ҫ���ص�DLL���
	PLIST_ENTRY Head, Cur;
	PPEB_LDR_DATA ldr;
	PLDR_MODULE ldm;

	__asm
	{
		mov eax, fs: [0x30]  //PEB�ĵ�ַ
		mov ecx, [eax + 0x0c] //Ldr   ƫ��
		mov ldr, ecx
	}
	//ȡ�������ַ
	Head = &(ldr->InLoadOrderModuleList);
	Cur = Head->Flink;
	do
	{
		ldm = CONTAINING_RECORD(Cur, LDR_MODULE, InLoadOrderModuleList);
		if (hMod == ldm->BaseAddress)
		{
			//����
			ldm->InLoadOrderModuleList.Blink->Flink = ldm->InLoadOrderModuleList.Flink;

			ldm->InLoadOrderModuleList.Flink->Blink = ldm->InLoadOrderModuleList.Blink;

			ldm->InInitializationOrderModuleList.Blink->Flink = ldm->InInitializationOrderModuleList.Flink;

			ldm->InInitializationOrderModuleList.Flink->Blink = ldm->InInitializationOrderModuleList.Blink;

			ldm->InMemoryOrderModuleList.Blink->Flink = ldm->InMemoryOrderModuleList.Flink;

			ldm->InMemoryOrderModuleList.Flink->Blink = ldm->InMemoryOrderModuleList.Blink;

			break;
		}
		Cur = Cur->Flink;
	} while (Head != Cur);

}