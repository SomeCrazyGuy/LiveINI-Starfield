#pragma once

#include "main.h"


extern DWORD GetProcessIdByExeName(const char* exe_name);
extern void GetProcessMemoryBlocks(void);
extern MemoryBlock GetProcessBlock(void);
extern bool RPM(HANDLE process, uintptr_t address, void* buffer, uint64_t read_size);
extern bool WPM(HANDLE process, uintptr_t address, void* buffer, uint64_t write_size);