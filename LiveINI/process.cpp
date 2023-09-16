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


extern bool RPM(uintptr_t address, void* buffer, uint64_t read_size) {
	const auto proc = GameProcessInfo.process;
	assert(proc != NULL);
	SIZE_T bytes_read;
	BOOL result = ReadProcessMemory(proc, (LPCVOID)address, (LPVOID)buffer, (SIZE_T)read_size, &bytes_read);
	const auto ret = (result && (read_size == bytes_read));
	if (!ret) {
		Log("RPM Failed: %p", address);
	}
	return ret;
}

extern bool WPM(uintptr_t address, void* buffer, uint64_t write_size) {
	const auto proc = GameProcessInfo.process;
	assert(proc != NULL);
	SIZE_T bytes_written;
	BOOL result = WriteProcessMemory(proc, (LPVOID)address, (LPCVOID)buffer, (SIZE_T)write_size, &bytes_written);
	const auto ret = (result && (write_size == bytes_written));
	if (!ret) {
		Log("WPM Failed: %p", address);
	}
	return ret;
}