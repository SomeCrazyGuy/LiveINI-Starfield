#include "main.h"

struct GameInfo {
	HWND hwnd;
	HANDLE process;
	uintptr_t base_address;
	uintptr_t module_size;
};

extern GameInfo* GetGameInfo();