#include <iostream>
#include <Windows.h>

typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	void* DllBase;
	void* EntryPoint;
	unsigned long SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	unsigned long Flags;
	unsigned short LoadCount;
	unsigned short TlsIndex;
	union
	{
		LIST_ENTRY HashLinks;
		struct
		{
			void* SectionPointer;
			unsigned long CheckSum;
		};
	};
	union
	{
		unsigned long TimeDateStamp;
		void* LoadedImports;
	};
	_ACTIVATION_CONTEXT* EntryPointActivationContext;
	void* PatchInformation;
	LIST_ENTRY ForwarderLinks;
	LIST_ENTRY ServiceTagLinks;
	LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA
{
	ULONG Length;
	BOOLEAN Initialized;
	HANDLE SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID EntryInProgress;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _PEB
{
	BOOLEAN InheritedAddressSpace;
	BOOLEAN ReadImageFileExecOptions;
	BOOLEAN BeingDebugged;
	BOOLEAN SpareBool;
	HANDLE Mutant;
	
	PVOID ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
	
	//.. We don't need more data, although sure there is.

} PEB, * PPEB;

typedef struct _CLIENT_ID
{
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID;

typedef struct _TEB
{
	NT_TIB NtTib;
	PVOID  EnvironmentPointer;
	CLIENT_ID ClientId;
	PVOID ActiveRpcHandle;
	PVOID ThreadLocalStoragePointer;
	PPEB ProcessEnvironmentBlock;

	//.. We don't need more data there aswell.
} TEB, *PTEB;

auto GetTargetLoadedDllBaseAddress( const wchar_t* pwzDllName )
{
	auto peb = NtCurrentTeb()->ProcessEnvironmentBlock;

	// PEB contains information about current process. This includes the list of loaded
	// modules into process memory. We can iterate through each module and get the data 
	// table entry which contains the module base address.

	auto ModulesBase = &peb->Ldr->InMemoryOrderModuleList;
	auto FrontLink = ModulesBase->Flink;

	do
	{
		auto ModuleEntry = reinterpret_cast<PLDR_DATA_TABLE_ENTRY>((uint8_t*)FrontLink - (sizeof( LIST_ENTRY )));
		
		if (!_wcsicmp( ModuleEntry->BaseDllName.Buffer, pwzDllName ))
			return ModuleEntry;

		FrontLink = FrontLink->Flink;
	} while (FrontLink != ModulesBase);

	return (PLDR_DATA_TABLE_ENTRY)nullptr;
}

void* _GetProcAddress( const wchar_t* pwzDllName, const char* pszProcName )
{
	// First we obtain the base address of the library by it's name.
	auto DTE = GetTargetLoadedDllBaseAddress( pwzDllName );
	if (!DTE)
		return nullptr;

	// Every module has a DOS header at the beginning if its address space.
	auto DOSHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(DTE->DllBase);
	if (!DOSHeader)
		return nullptr;

	// NT header is located via the e_lfanew member inside DOS.
	auto NTHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>((uint8_t*)DTE->DllBase + DOSHeader->e_lfanew);
	if (!NTHeaders)
		return nullptr;

	// Get the data directory for exports from optional header located inside NT header.
	auto ExportsDataDirectory = &NTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	if (!ExportsDataDirectory->Size || !ExportsDataDirectory->VirtualAddress)
		return nullptr;

	// Individual export addresses we need are located in this data structure.
	auto ExportDirectory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>((uint8_t*)DTE->DllBase + ExportsDataDirectory->VirtualAddress);
	if (!ExportDirectory)
		return nullptr;

	// These are the individual entry points to our data. They are separated as three rows of data in memory.
	auto AddrFunctions = reinterpret_cast<uint32_t*>((uint8_t*)DTE->DllBase + ExportDirectory->AddressOfFunctions);
	auto AddrNames = reinterpret_cast<uint32_t*>((uint8_t*)DTE->DllBase + ExportDirectory->AddressOfNames);
	auto AddrOrdinals = reinterpret_cast<uint16_t*>((uint8_t*)DTE->DllBase + ExportDirectory->AddressOfNameOrdinals);

	for (uint32_t i = 0; i < ExportDirectory->NumberOfFunctions; i++)
	{
		auto FnName = reinterpret_cast<const char*>((uint8_t*)DTE->DllBase + AddrNames[i]);
		if (!_stricmp( FnName, pszProcName ))
		{
			// We access the function address by its ordinal. Ordinal is like an index into the export table and
			// each exported function has its own ordinal, which we can access it through.
			return reinterpret_cast<uint32_t*>((uint8_t*)DTE->DllBase + AddrFunctions[AddrOrdinals[i]]);
		}
	}

	return nullptr;
}

int main()
{
	// In order to test this, we'll try to get Sleep function which is located inside kernel32.dll
	auto pfnSleep = _GetProcAddress( L"kernel32.dll", "Sleep" );
	printf( "Sleep at 0x%08X\n\n", pfnSleep );

	// Another test is to just get LoadLibraryA and silently load libraries that we want.
	auto pfnLoadLibraryA = (HMODULE(WINAPI*)(LPCSTR))_GetProcAddress( L"kernel32.dll", "LoadLibraryA" );
	printf( "LoadLibraryA at 0x%08X\n\n", LoadLibraryA );

	// And there we load up shell32.dll for our program.
	auto shell32 = pfnLoadLibraryA("shell32.dll");
	printf( "Loaded shell32.dll at 0x%08X\n\n", shell32 );

	system( "pause" );

	return 0;
}