#include "setting.h"
#include "process.h"

GameSettingFlag Setting::GetGameSettingType(const char c) {
	switch (::tolower(c)) {
	case 'f': return GameSettingFlag::TypeFloat;
	case 'b': return GameSettingFlag::TypeBool;
	case 'i': return GameSettingFlag::TypeInt;
	case 's': return GameSettingFlag::TypeString;
	case 'u':
	case 'c':
	case 'h': return GameSettingFlag::TypeUnsigned;
	case 'r': return GameSettingFlag::TypeRGB;
	case 'a': return GameSettingFlag::TypeRGBA;
	default: return GameSettingFlag::TypeUnknown;
	}
}

const char* Setting::GetGameSettingTypeName(const uint64_t gst) {
	if (gst & GameSettingFlag::TypeBool) return "Bool";
	if (gst & GameSettingFlag::TypeFloat) return "Float";
	if (gst & GameSettingFlag::TypeInt) return "Int";
	if (gst & GameSettingFlag::TypeRGB) return "ColorRGB";
	if (gst & GameSettingFlag::TypeRGBA) return "ColorRGBA";
	if (gst & GameSettingFlag::TypeString) return "String";
	if (gst & GameSettingFlag::TypeUnknown) return "Unknown";
	if (gst & GameSettingFlag::TypeUnsigned) return "Unsigned";
	return "(error)";
}

const char* Setting::GetGameSettingOriginName(const uint64_t gso) {
	if (gso & GameSettingFlag::OriginINI) return "INI";
	if (gso & GameSettingFlag::OriginRendererQuality) return "RendererQuality";
	if (gso & GameSettingFlag::OriginRendererPref) return "RendererPref";
	if (gso & GameSettingFlag::OriginGameSetting) return "GameSetting";
	if (gso & GameSettingFlag::OriginRegSetting) return "RegSetting";
	if (gso & GameSettingFlag::OriginUnknown) return "Unknown";
	return "(error)";
}


bool Setting::Update() {
	GameSetting setting;
	Log("->%s", this->m_name.c_str());
	if (!RPM(this->m_address, &setting, sizeof(setting))) return false;
	if (setting.vTable != this->m_setting.vTable) {
		Log("vTable Mismatch!");
		return false;
	}
	if (setting.Name != this->m_setting.Name) {
		Log("Name Mismatch!");
		return false;
	}
	if (setting.Default.as_ptr != this->m_setting.Default.as_ptr) {
		Log("Default Value Changed!");
		return false;
	}
	setting.Active = this->m_current;
	this->m_active = this->m_current;
	if (!WPM(this->m_address, &setting, sizeof(setting))) return false;
	return true;
}