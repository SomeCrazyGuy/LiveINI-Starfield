#pragma once

#include "main.h"

extern DWORD GetProcessIdByWindowTitle(const wchar_t* window_title);
extern DWORD GetProcessIdByExeName(const char* exe_name);
extern void GetProcessMemoryBlocks(void);
extern MemoryBlock GetProcessBlock(const HANDLE process_handle);
extern bool RPM(uintptr_t address, void* buffer, uint64_t read_size);
extern bool WPM(uintptr_t address, void* buffer, uint64_t write_size);