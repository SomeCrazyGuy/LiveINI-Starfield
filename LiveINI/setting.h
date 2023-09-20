#pragma once
#include "main.h"

union GameValue {
	uintptr_t as_ptr;
	uint8_t   as_bool;
	int       as_int;
	float     as_float; 
	unsigned  as_unsigned;
};

struct GameSetting {
	uintptr_t vTable;
	GameValue Active;
	GameValue Default;
	uintptr_t Name;
};

template<typename T>
static constexpr const uint64_t next_bit(const T flag) noexcept {
        return flag << 1;
}

enum GameSettingFlag : uint64_t {
	TypeUnknown  = 1 << 0,
	TypeInt      = 1 << 1,
	TypeUnsigned = 1 << 2,
	TypeBool     = 1 << 3,
	TypeFloat    = 1 << 4,
	TypeRGB      = 1 << 5,
	TypeRGBA     = 1 << 6,
	TypeString   = 1 << 7,

	OriginUnknown		= 1 << 8,
	OriginINI		= 1 << 9,
	OriginRendererQuality   = 1 << 10,
	OriginRendererPref	= 1 << 11,
	OriginGameSetting	= 1 << 12,

	FlagChanged = 1 << 13,
};


struct Setting {
	uint64_t m_flags;
	GameSetting m_setting;
	std::string m_name;
	std::string m_search_name;
	GameValue m_active;
	GameValue m_current;
	uintptr_t m_address;
	bool search_match;

	static GameSettingFlag GetGameSettingType(const char c);
	static const char* GetGameSettingTypeName(const uint64_t gst);
	static const char* GetGameSettingOriginName(const uint64_t gso);

	bool Update();
};