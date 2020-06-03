#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <random>
#include <time.h>


using namespace std;

typedef HMODULE(__stdcall* pLoadLibraryA)(LPCSTR);
typedef FARPROC(__stdcall* pGetProcAddress)(HMODULE, LPCSTR);

typedef INT(__stdcall* dllmain)(HMODULE, DWORD, LPVOID);

//ShowWindow(GetConsoleWindow(), SW_HIDE)


DWORD GetFuncSize(DWORD* Function, DWORD* StubFunction)
{
	DWORD dwFunctionSize = 0, dwOldProtect;
	DWORD* fnA = NULL, * fnB = NULL;

	fnA = (DWORD*)Function;
	fnB = (DWORD*)StubFunction;
	dwFunctionSize = (fnB - fnA);
	VirtualProtect(fnA, dwFunctionSize, PAGE_EXECUTE_READWRITE, &dwOldProtect); // Need to modify our privileges to the memory
	return dwFunctionSize;
}

struct loaderdata
{
	LPVOID ImageBase;

	PIMAGE_NT_HEADERS NtHeaders;
	PIMAGE_BASE_RELOCATION BaseReloc;
	PIMAGE_IMPORT_DESCRIPTOR ImportDirectory;

	pLoadLibraryA fnLoadLibraryA;
	pGetProcAddress fnGetProcAddress;

};
class Color
{
public:
	Color(int desiredColor) {
		consoleHandle = GetStdHandle(STD_OUTPUT_HANDLE);
		color = desiredColor;
	}

	friend ostream& operator<<(ostream& ss, Color obj) {
		SetConsoleTextAttribute(obj.consoleHandle, obj.color);
		return ss;
	}
private:
	int color;
	HANDLE consoleHandle;
	/*
	0 = black
	1 = blue
	2 = green
	3 = light blue
	4 = red
	5 = purple
	6 = gold
	7 = white
	*/
};
void printlogo()
{

	system("cls");
	std::cout << Color(4) << R"(


_________ .__                            __________                
\_   ___ \|__|______   ____  __ __  _____\______   \_______  ____  
/    \  \/|  \_  __ \_/ ___\|  |  \/  ___/|     ___/\_  __ \/  _ \ 
\     \___|  ||  | \/\  \___|  |  /\___ \ |    |     |  | \(  <_> )
 \______  /__||__|    \___  >____//____  >|____|     |__|   \____/ 
        \/                \/           \/                          
V3
        )";
	cout << "\n";
}
/*
void openpornhub()
{
	ShellExecute(0, 0, "http://pornhub.com", 0, 0, SW_SHOW);
}
*/
void randomizetitle()
{
	std::random_device rd;
	std::mt19937 mt(rd());
	std::uniform_int_distribution<> distr(0, 51);
	std::string name = "";
	char alphabet[] = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z' };
	for (int i = 0; i < 15; ++i)
	{
		name = name + alphabet[distr(mt)];
		SetConsoleTitleA(name.c_str());
	}

}
void HideConsole()
{
	::ShowWindow(::GetConsoleWindow(), SW_HIDE);
}

void currenttime()
{
	time_t curr_time;
	curr_time = time(NULL);
	tm* tm_local = localtime(&curr_time);

	cout << Color(7) << "\n[" << tm_local->tm_hour << ":" << tm_local->tm_min << ":" << tm_local->tm_sec << "] ";
}

DWORD GetFuncSize(DWORD* Function)
{
	DWORD dwFunctionSize = 0, dwOldProtect;
	DWORD* fnA = NULL, * fnB = NULL;

	fnA = (DWORD*)Function;
	//fnB = (DWORD*)StubFunction;
	dwFunctionSize = (fnB - fnA);
	VirtualProtect(fnA, dwFunctionSize, PAGE_EXECUTE_READWRITE, &dwOldProtect); // Need to modify our privileges to the memory
	return dwFunctionSize;
}

DWORD FindProcessId(string processName)
{
	PROCESSENTRY32 processInfo;
	processInfo.dwSize = sizeof(processInfo);

	HANDLE processSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (processSnapshot == INVALID_HANDLE_VALUE)
		return 0;

	Process32First(processSnapshot, &processInfo);
	if (!processName.compare(processInfo.szExeFile))
	{
		CloseHandle(processSnapshot);
		return processInfo.th32ProcessID;
	}

	while (Process32Next(processSnapshot, &processInfo))
	{
		if (!processName.compare(processInfo.szExeFile))
		{
			CloseHandle(processSnapshot);
			return processInfo.th32ProcessID;
		}
	}

	CloseHandle(processSnapshot);
	return 0;
}

DWORD __stdcall LibraryLoader(LPVOID Memory)
{

	loaderdata* LoaderParams = (loaderdata*)Memory;

	PIMAGE_BASE_RELOCATION pIBR = LoaderParams->BaseReloc;

	DWORD delta = (DWORD)((LPBYTE)LoaderParams->ImageBase - LoaderParams->NtHeaders->OptionalHeader.ImageBase); // Calculate the delta

	while (pIBR->VirtualAddress)
	{
		if (pIBR->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))
		{
			int count = (pIBR->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			PWORD list = (PWORD)(pIBR + 1);

			for (int i = 0; i < count; i++)
			{
				if (list[i])
				{
					PDWORD ptr = (PDWORD)((LPBYTE)LoaderParams->ImageBase + (pIBR->VirtualAddress + (list[i] & 0xFFF)));
					*ptr += delta;
				}
			}
		}

		pIBR = (PIMAGE_BASE_RELOCATION)((LPBYTE)pIBR + pIBR->SizeOfBlock);
	}

	PIMAGE_IMPORT_DESCRIPTOR pIID = LoaderParams->ImportDirectory;

	// Resolve DLL imports
	while (pIID->Characteristics)
	{
		PIMAGE_THUNK_DATA OrigFirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)LoaderParams->ImageBase + pIID->OriginalFirstThunk);
		PIMAGE_THUNK_DATA FirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)LoaderParams->ImageBase + pIID->FirstThunk);

		HMODULE hModule = LoaderParams->fnLoadLibraryA((LPCSTR)LoaderParams->ImageBase + pIID->Name);

		if (!hModule)
			return FALSE;

		while (OrigFirstThunk->u1.AddressOfData)
		{
			if (OrigFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
			{
				// Import by ordinal
				DWORD Function = (DWORD)LoaderParams->fnGetProcAddress(hModule,
					(LPCSTR)(OrigFirstThunk->u1.Ordinal & 0xFFFF));

				if (!Function)
					return FALSE;

				FirstThunk->u1.Function = Function;
			}
			else
			{
				// Import by name
				PIMAGE_IMPORT_BY_NAME pIBN = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)LoaderParams->ImageBase + OrigFirstThunk->u1.AddressOfData);
				DWORD Function = (DWORD)LoaderParams->fnGetProcAddress(hModule, (LPCSTR)pIBN->Name);
				if (!Function)
					return FALSE;

				FirstThunk->u1.Function = Function;
			}
			OrigFirstThunk++;
			FirstThunk++;
		}
		pIID++;
	}

	if (LoaderParams->NtHeaders->OptionalHeader.AddressOfEntryPoint)
	{
		dllmain EntryPoint = (dllmain)((LPBYTE)LoaderParams->ImageBase + LoaderParams->NtHeaders->OptionalHeader.AddressOfEntryPoint);

		return EntryPoint((HMODULE)LoaderParams->ImageBase, DLL_PROCESS_ATTACH, NULL); // Call the entry point
	}
	return TRUE;
}


DWORD __stdcall stub()
{
	return 0;
}
/*	HWND windowHandle = GetConsoleWindow();
	ShowWindow(windowHandle,SW_HIDE);*/


int main()
{
	HideConsole();
	randomizetitle();
	printlogo();
	currenttime();
//	openpornhub();
	char dll[MAX_PATH] = { 0 };
	GetFullPathName("circuspro.dll", MAX_PATH, dll, NULL);
	DWORD ProcessId = FindProcessId("csgo.exe");
	
	loaderdata LoaderParams;

	HANDLE hFile = CreateFileA(dll, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
		OPEN_EXISTING, 0, NULL); // Open the DLL

	DWORD FileSize = GetFileSize(hFile, NULL);
	PVOID FileBuffer = VirtualAlloc(NULL, FileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	// Read the DLL
	ReadFile(hFile, FileBuffer, FileSize, NULL, NULL);

	// Target Dll's DOS Header
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)FileBuffer;
	// Target Dll's NT Headers
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)FileBuffer + pDosHeader->e_lfanew);

	// Opening target process.
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessId);
	// Allocating memory for the DLL
	PVOID ExecutableImage = VirtualAllocEx(hProcess, NULL, pNtHeaders->OptionalHeader.SizeOfImage,
		MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	// Copy the headers to target process
	WriteProcessMemory(hProcess, ExecutableImage, FileBuffer,
		pNtHeaders->OptionalHeader.SizeOfHeaders, NULL);

	// Target Dll's Section Header
	PIMAGE_SECTION_HEADER pSectHeader = (PIMAGE_SECTION_HEADER)(pNtHeaders + 1);
	// Copying sections of the dll to the target process
	for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++)
	{
		WriteProcessMemory(hProcess, (PVOID)((LPBYTE)ExecutableImage + pSectHeader[i].VirtualAddress),
			(PVOID)((LPBYTE)FileBuffer + pSectHeader[i].PointerToRawData), pSectHeader[i].SizeOfRawData, NULL);
	}

	// Allocating memory for the loader code.
	PVOID LoaderMemory = VirtualAllocEx(hProcess, NULL, 4096, MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE); // Allocate memory for the loader code

	LoaderParams.ImageBase = ExecutableImage;
	LoaderParams.NtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)ExecutableImage + pDosHeader->e_lfanew);

	LoaderParams.BaseReloc = (PIMAGE_BASE_RELOCATION)((LPBYTE)ExecutableImage
		+ pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	LoaderParams.ImportDirectory = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)ExecutableImage
		+ pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	LoaderParams.fnLoadLibraryA = LoadLibraryA;
	LoaderParams.fnGetProcAddress = GetProcAddress;

	// Write the loader information to target process
	WriteProcessMemory(hProcess, LoaderMemory, &LoaderParams, sizeof(loaderdata),
		NULL);
	// Write the loader code to target process
	WriteProcessMemory(hProcess, (PVOID)((loaderdata*)LoaderMemory + 1), LibraryLoader,
		(DWORD)stub - (DWORD)LibraryLoader, NULL);
	// Create a remote thread to execute the loader code
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)((loaderdata*)LoaderMemory + 1),
		LoaderMemory, 0, NULL);

	//std::cout << "Address of Loader: " << std::hex << LoaderMemory << std::endl;
	//std::cout << "Address of Image: " << std::hex << ExecutableImage << std::endl;

	// Wait for the loader to finish executing
	WaitForSingleObject(hThread, INFINITE);

	//std::cin.get();
	// free the allocated loader code
	VirtualFreeEx(hProcess, LoaderMemory, 0, MEM_RELEASE);

	//return 0;
	ExitProcess(0);
}