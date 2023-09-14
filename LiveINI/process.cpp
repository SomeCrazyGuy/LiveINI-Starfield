#include "process.h"

#include <TlHelp32.h>

extern DWORD GetProcessIdByExeName(const char* exe_name) {
	DWORD ret = 0;

	auto snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snap == INVALID_HANDLE_VALUE) {
		Log("Snapshot failed");
		goto END;
	}

	PROCESSENTRY32 proc;
	proc.dwSize = sizeof(proc);

	if (!Process32First(snap, &proc)) {
		Log("Process32First failed");
		goto CLEANUP_HANDLE;
	}

	do {
		if (0 == strcmp(exe_name, proc.szExeFile)) {
			Log("process %s found", exe_name);
			ret = proc.th32ProcessID;
			goto CLEANUP_HANDLE;
		}
	} while (Process32Next(snap, &proc));

	CLEANUP_HANDLE:
	CloseHandle(snap);

	END:
	return ret;
}


static uintptr_t GetProcessBaseAddress(HANDLE process) {
	HMODULE modules[1024];
	DWORD count = 0;

	EnumProcessModules(process, modules, sizeof(modules), &count);
	count /= sizeof(HMODULE);

	for (DWORD i = 0; i < count; ++i) {
		char module_name[MAX_PATH];
		GetModuleFileNameExA(process, modules[i], module_name, MAX_PATH);
		//Log("Evaluating module: %s", module_name);
		unsigned len = 0;
		while (module_name[len]) ++len;
		if (::tolower(module_name[--len]) != 'e') continue;
		if (::tolower(module_name[--len]) != 'x') continue;
		if (::tolower(module_name[--len]) != 'e') continue;
		if (::tolower(module_name[--len]) != '.') continue;
		Log("Base Address %p", modules[i]);
		return (uintptr_t)modules[i];
	}

	Log("Base Address not found");
	return 0;
}


extern void GetProcessMemoryBlocks(void) {
	typedef LONG(NTAPI *PNTAPI)(
		HANDLE ProcessHandle,
		PVOID BaseAddress,
		int MemoryInformationClass, //must be 0
		PVOID Buffer,
		SIZE_T Length,
		PSIZE_T ResultLength
		);

	GameProcessInfo.blocks.clear();

	Log("Heap analysis");

	static const uintptr_t ADDR_MIN = { 0x000000000000ULL };
	static const uintptr_t ADDR_MAX = { 0x7FFFFFFFFFFFULL };
	static const auto NtQueryVirtualMemory = (PNTAPI)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryVirtualMemory");
	static const uintptr_t end = GameProcessInfo.base_address;

	MEMORY_BASIC_INFORMATION mbi;
	for (uintptr_t address = ADDR_MIN; address < ADDR_MAX; address += mbi.RegionSize) {
		NtQueryVirtualMemory(GameProcessInfo.process, (PVOID)address, 0, &mbi, sizeof(mbi), 0);

		if (!mbi.RegionSize) break;
		if (mbi.State != MEM_COMMIT) continue;
		if (!(mbi.Type & MEM_PRIVATE)) continue;
		if (mbi.Protect & (PAGE_GUARD | PAGE_NOCACHE | PAGE_WRITECOMBINE | PAGE_NOACCESS)) continue;
		if (mbi.RegionSize < (1 << 27)) continue; //skip (<128MB) blocks
		if (address > end) continue;

		MemoryBlock blk;
		blk.address = address;
		blk.size = mbi.RegionSize;
		blk.flags = 0;
		blk.flags |= (mbi.Protect & (PAGE_EXECUTE_READ | PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY | PAGE_WRITECOPY)) ? MemoryFlag_Read : 0;
		blk.flags |= (mbi.Protect & (PAGE_WRITECOPY | PAGE_READWRITE | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) ? MemoryFlag_Write : 0;
		blk.flags |= (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) ? MemoryFlag_Execute : 0;
		if (blk.flags & MemoryFlag::MemoryFlag_Execute) continue;
		if (blk.flags * MemoryFlag::MemoryFlag_Write) {
			GameProcessInfo.blocks.push_back(blk);
		}
		Log("Adding Memory Block: %p", address);
	}
}

extern MemoryBlock GetProcessBlock(void) {
	MemoryBlock ret = {0};
	HMODULE base = (HMODULE) GetProcessBaseAddress(GameProcessInfo.process);

	MODULEINFO modinf;
	if (GetModuleInformation(GameProcessInfo.process, base, &modinf, sizeof(modinf))) {
		ret.address = (uintptr_t)base;
		ret.size = modinf.SizeOfImage;
	}

	return ret;
}


extern bool RPM(HANDLE process, uintptr_t address, void* buffer, uint64_t read_size) {
	SIZE_T bytes_read;
	BOOL result = ReadProcessMemory(process, (LPCVOID)address, (LPVOID)buffer, (SIZE_T)read_size, &bytes_read);
	const auto ret = (result && (read_size == bytes_read));
	if (!ret) {
		Log("RPM Failed: %p", address);
	}
	return ret;
}

extern bool WPM(HANDLE process, uintptr_t address, void* buffer, uint64_t write_size) {
	SIZE_T bytes_read;
	BOOL result = WriteProcessMemory(process, (LPVOID)address, (LPCVOID)buffer, (SIZE_T)write_size, &bytes_read);
	const auto ret = (result && (write_size == bytes_read));
	if (!ret) {
		Log("WPM Failed: %p", address);
	}
	return ret;
}