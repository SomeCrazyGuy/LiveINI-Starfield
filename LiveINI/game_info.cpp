#include "game_info.h"

extern GameInfo* GetGameInfo() {
	static GameInfo ret{};
	return &ret;
}