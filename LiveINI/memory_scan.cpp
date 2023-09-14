#include "main.h"
#include "process.h"
#include "setting.h"

extern "C" {
	#include "minilibs/regexp.h"
}

#ifdef _MSC_VER 
#define __PRETTY_FUNCTION__ __FUNCSIG__
#endif

static std::vector<Setting> results{};

class Pointer {
	const uintptr_t m_value;
public:
	Pointer() = delete;
	Pointer(const void* const ptr): m_value {(uintptr_t)ptr} {}
	Pointer(uintptr_t ptr) : m_value{ ptr } {}
	template<typename T> T as() const { return (T)m_value; }
	template<typename T> void set(T* out) { *out = (T*)m_value; }
	uintptr_t value() const { return m_value; }
	const Pointer operator+(const Pointer& other) const { return Pointer(m_value + other.m_value); }
	const Pointer operator-(const Pointer& other) const { return Pointer(m_value - other.m_value); }
	const Pointer operator*(const Pointer& other) const { return Pointer(m_value * other.m_value); }
	const Pointer operator/(const Pointer& other) const { return Pointer(m_value / other.m_value); }
	bool operator==(const Pointer& other) const { return (m_value == other.m_value); }
	bool operator!=(const Pointer& other) const { return (m_value != other.m_value); }
	bool operator<(const Pointer& other) const { return (m_value < other.m_value); }
	bool operator>(const Pointer& other) const { return (m_value > other.m_value); }
	bool operator>=(const Pointer& other) const { return (m_value >= other.m_value); }
	bool operator<=(const Pointer& other) const { return (m_value <= other.m_value); }
};


template<typename T>
static uintptr_t find(const Pointer haystack, const Pointer endptr, uint64_t * const offset, const T needle) {
	const Pointer start(haystack + *offset);
	if (start >= endptr) return 0;
	const auto b = start.as<const T*>();
	const auto count = ((endptr - start) / sizeof(T)).as<unsigned>();
	for (unsigned i = 0; i < count; ++i) {
		if (b[i] == needle) {
			*offset += (i * sizeof(T));
			return *offset;
		}
	}
	return 0;
}

//should cache result?
extern void perform_exe_section_analysis() {
	assert(GameProcessInfo.buffer != NULL);
	assert(GameProcessInfo.buffer_size != 0);
	const Pointer haystack{ GameProcessInfo.buffer };

	IMAGE_DOS_HEADER hdr;
	memcpy(&hdr, haystack.as<const void*>(), sizeof(hdr));

	IMAGE_NT_HEADERS64 hdr2;
	memcpy(&hdr2, (haystack + hdr.e_lfanew).as<const void*>(), sizeof(IMAGE_NT_HEADERS64));

	const auto sections = (haystack + hdr.e_lfanew + sizeof(IMAGE_NT_HEADERS64)).as<const IMAGE_SECTION_HEADER*>();
	const auto nr_sections = hdr2.FileHeader.NumberOfSections;

	for (auto i = 0; i < nr_sections; ++i) {
		const auto &s = sections[i];
			
		if (memcmp(".text", s.Name, sizeof(".text") - 1) == 0) {
			GameProcessInfo.exe.text = { s.VirtualAddress, s.SizeOfRawData };
		}
		else if (memcmp(".rdata", s.Name, sizeof(".rdata") - 1) == 0) {
			GameProcessInfo.exe.rdata = { s.VirtualAddress, s.SizeOfRawData };
		}
		else if (memcmp(".data", s.Name, sizeof(".data") - 1) == 0) {
			GameProcessInfo.exe.data = { s.VirtualAddress, s.SizeOfRawData };
		}
		else if (memcmp(".rsrc", s.Name, sizeof(".rsrc") - 1) == 0) {
			GameProcessInfo.exe.rsrc = { s.VirtualAddress, s.SizeOfRawData };
		}
		else {
			continue;
		}

		Log("%8.8s: %8X - %8X", s.Name, s.VirtualAddress, (s.VirtualAddress + s.SizeOfRawData));
	}

}


extern void build_rtti_list(void) {
	GameProcessInfo.rtti_map.clear();
	GameProcessInfo.rtti_map.reserve(32768);

	const Pointer haystack{ GameProcessInfo.buffer };
	uintptr_t pos = GameProcessInfo.exe.rdata.offset;
	static const uint32_t rtti_bytes = *(const uint32_t*)".?AV";
	while (find(haystack, haystack + GameProcessInfo.buffer_size, &pos, rtti_bytes)) {
		const std::string tmp = { (haystack + pos).as<const char*>() };
		GameProcessInfo.rtti_map[tmp] = (unsigned)pos;
		auto len = tmp.length();
		if (len & 3) {
			len = (len | 3) + 1;
		}
		pos += len;
	}

	Log("rtti names found: %u", GameProcessInfo.rtti_map.size());
}


extern uintptr_t find_vtable(const char* const rtti_name) {
	Log("Locate: %s", rtti_name);

	const auto search = GameProcessInfo.rtti_map.find(std::string{ rtti_name });
	if (search == GameProcessInfo.rtti_map.end()) return 0;
	uintptr_t rtti_name_offset = search->second;

	Log("Rtti name offset: %p", rtti_name_offset);
	if (!rtti_name_offset) return 0;

	rtti_name_offset -= 0x10; //backup 16 bytes to get base address
	rtti_name_offset <<= 32; //shift up value to match how its stored (4 byte preceeded by padding)


	const Pointer haystack{ GameProcessInfo.buffer };
	const auto offset = GameProcessInfo.exe.rdata.offset;
	uintptr_t object_locator_offset = offset;
	while (find(haystack, haystack + GameProcessInfo.buffer_size, &object_locator_offset, rtti_name_offset)) {
		if (*(haystack + object_locator_offset - 0x8).as<uint64_t*>() == 0x1ULL) {
			object_locator_offset -= 8;
			break;
		}
		object_locator_offset += 8;
	}
	Log("Object locator offset: %p", object_locator_offset);
	if (!object_locator_offset) return 0;

	uintptr_t object_locator_pointer = offset;
	find(haystack, haystack + GameProcessInfo.buffer_size, &object_locator_pointer, GameProcessInfo.base_address + object_locator_offset);
	Log("Object locator pointer: %p", object_locator_pointer);

	uintptr_t vtable = (GameProcessInfo.base_address + object_locator_pointer + 0x8);
	Log("vTable: %p", vtable);

	return vtable;
}


static DWORD WINAPI vtable_scan_threadproc(LPVOID) {
	results.clear();
	results.reserve(16384); //more than enough for all game settings

	const auto sz = GameProcessInfo.buffer_size;
	const Pointer buffer(GameProcessInfo.buffer);

	struct vtable_offsets {
		uintptr_t offset;
		GameSettingFlag origin;
	} const settings_vtable[] = {
		{find_vtable(".?AV?$SettingT@VINISettingCollection@@@@"), GameSettingFlag::OriginINI},
		{find_vtable(".?AVRendererQualitySetting@CreationRenderer@@"), GameSettingFlag::OriginINIPref},
		{find_vtable(".?AV?$SettingT@VGameSettingCollection@@@@"), GameSettingFlag::OriginGameSetting},
		{0, GameSettingFlag::OriginUnknown},
	};

	const auto start_offset = GameProcessInfo.exe.rdata.offset;
	for (uint64_t vt = 0; settings_vtable[vt].offset; ++vt) {
		uintptr_t offset = start_offset;
                char tmp_name[128];
		while (find(buffer, buffer + sz, &offset, settings_vtable[vt].offset)) {
			Setting s;
			s.m_address = GameProcessInfo.base_address + offset;
			s.m_setting = *(buffer + offset).as<const GameSetting*>();
			//s.m_name = ((Pointer(s.m_setting.Name) - GameProcessInfo.base_address) + buffer).as<const char*>();
                        
                        if (!RPM(GameProcessInfo.process, s.m_setting.Name, tmp_name, 128)) {
                                continue;
                        }

			tmp_name[127] = 0;
                        s.m_name = tmp_name;
			s.m_flags = settings_vtable[vt].origin | s.GetGameSettingType(s.m_name[0]);
			for (const auto chr : s.m_name) {
				s.m_search_name += (char)::tolower(chr);
			}
			s.m_current = s.m_setting.Active;
			s.m_active = s.m_setting.Active;
			results.push_back(s);
			offset += sizeof(GameSetting);
		}
	}
	return 0;
}


static float* UnsignedToColor(unsigned in) {
	static float ret[4];
	ret[0] = ((in >> 24) & 0xFF) / 255.f;
	ret[1] = ((in >> 16) & 0xFF) / 255.f;
	ret[2] = ((in >> 8) & 0xFF) / 255.f;
	ret[3] = ((in >> 0) & 0xFF) / 255.f;
	return ret;
}

static unsigned ColorToUnsigned(const float* in) {
	unsigned ret = 0;
	ret |= ((unsigned)(in[0] * 255) << 24);
	ret |= ((unsigned)(in[1] * 255) << 16);
	ret |= ((unsigned)(in[2] * 255) << 8);
	ret |= ((unsigned)(in[3] * 255) << 0);
	return ret;
}

static std::string stringify_value(const GameValue& v, const uint64_t t) {
	if (t & GameSettingFlag::TypeBool) return (v.as_bool) ? "True" : "False";
	if (t & GameSettingFlag::TypeFloat) return std::to_string(v.as_float);
	if (t & GameSettingFlag::TypeInt) return std::to_string(v.as_int);
	if (t & GameSettingFlag::TypeUnsigned) return std::to_string(v.as_unsigned);
	if (t & GameSettingFlag::TypeUnknown) return "<unknown>";
        if (t & GameSettingFlag::TypeString) {
                char localbuffer[1024];
                RPM(GameProcessInfo.process, v.as_ptr, localbuffer, 1024);
                localbuffer[1023] = '\0';
                return std::string{ localbuffer };
        }
	if (t & (GameSettingFlag::TypeRGB | GameSettingFlag::TypeRGBA))
	{
		char str[64];
		snprintf(str, 64, "\"%u,%u,%u,%u\"", (v.as_unsigned >> 24) & 0xFF, (v.as_unsigned >> 16) & 0xFF, (v.as_unsigned >> 8) & 0xFF, v.as_unsigned & 0xFF);
		return std::string{ str };
	}
	return "<error>";
}

static void EditSetting(Setting& s) {
	ImGui::Text("Setting Starfield.exe+%X", (Pointer(s.m_address) - GameProcessInfo.base_address).as<unsigned>());
	ImGui::Text("Type Name: %s", s.GetGameSettingTypeName(s.m_flags));
	ImGui::Text("Setting Origin: %s", s.GetGameSettingOriginName(s.m_flags));

	const auto str_default = stringify_value(s.m_setting.Default, s.m_flags);
	const auto str_ini = stringify_value(s.m_setting.Active, s.m_flags);
	const auto str_active = stringify_value(s.m_active, s.m_flags);
	const bool is_color = !!(s.m_flags & (GameSettingFlag::TypeRGB | GameSettingFlag::TypeRGBA));


	if (ImGui::Button("Revert##default")) {
		s.m_current = s.m_setting.Default;
		s.Update(GameProcessInfo.process);
		s.m_flags |= GameSettingFlag::FlagChanged;
	}
	ImGui::SameLine();
	if (is_color) {
		ImGui::ColorEdit4("##color_default", UnsignedToColor(s.m_setting.Default.as_unsigned), ImGuiColorEditFlags_NoInputs);
		ImGui::SameLine();
	}
	ImGui::Text("Default Value: %s", str_default.c_str());

	if (ImGui::Button("Revert##ini")) {
		s.m_current = s.m_setting.Active;
		s.Update(GameProcessInfo.process);
		s.m_flags &= ~GameSettingFlag::FlagChanged;
	}
	ImGui::SameLine();
	if (is_color) {
		ImGui::ColorEdit4("INI Value", UnsignedToColor(s.m_setting.Active.as_unsigned), ImGuiColorEditFlags_NoInputs);
		ImGui::SameLine();
	}
	ImGui::Text("INI Value: %s", str_ini.c_str());

	if (ImGui::Button("Revert##active")) {
		s.m_current = s.m_active;
	}
	ImGui::SameLine();
	if (is_color) {
		ImGui::ColorEdit4("Active Value", UnsignedToColor(s.m_active.as_unsigned), ImGuiColorEditFlags_NoInputs);
		ImGui::SameLine();
	}
	ImGui::Text("Active Value %s", str_active.c_str());

	if (ImGui::Button("Apply")) {
		s.Update(GameProcessInfo.process);
		s.m_flags |= GameSettingFlag::FlagChanged;
	}
	ImGui::SameLine();

	if (s.m_flags & GameSettingFlag::TypeFloat)	
		ImGui::DragFloat("##edit_value", &s.m_current.as_float);
	else if (s.m_flags & GameSettingFlag::TypeBool)
		ImGui::Checkbox("##edit_value", (bool*) &s.m_current.as_bool);
	else if (s.m_flags & (GameSettingFlag::TypeInt | GameSettingFlag::TypeUnsigned))
		ImGui::DragInt("##edit_value", (int*)&s.m_current.as_unsigned);
	else if (is_color) {
		auto color = UnsignedToColor(s.m_current.as_unsigned);
		ImGui::ColorEdit4("##edit_value", color);
		s.m_current.as_unsigned = ColorToUnsigned(color);
	}
	else ImGui::Text("(not currently editable)");
}

static bool StyleCollapsingHeader(const char* const name) {
	ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2{ 0.f, 2.f });
	auto ret = ImGui::CollapsingHeader(name);
	ImGui::PopStyleVar();

	return ret;
}


static void reset_changed_settings(void) {
	for (auto& x : results) {
		if (!(x.m_flags & GameSettingFlag::FlagChanged)) continue;
		x.m_flags &= ~GameSettingFlag::FlagChanged;
		x.m_current = x.m_setting.Active;
		x.Update(GameProcessInfo.process);
	}
}

extern void scan_vtable(void) {
        //CreateThread(NULL, 0, &vtable_scan_threadproc, nullptr, 0, NULL);
        vtable_scan_threadproc(nullptr);
}

extern void scan_window_draw(void) {
	static char searchtext[64] = {};
	static uint64_t include_mask = UINT64_MAX;
	static uint64_t exclude_mask = 0;
	static auto results_begin = results.begin();
	static auto results_end = results.end();
	static auto results_count = std::distance(results_begin, results_end);

	if (results.empty()) {
		ImGui::Text("Press the Scan Starfield button in the log window!");
		return;
	}

	if (ImGui::InputText("Search", searchtext, 64)) {
		results_begin = results.begin();
		results_end = results.end();

		for (unsigned i = 0; searchtext[i]; ++i) {
			searchtext[i] = (char)::tolower(searchtext[i]);
		}

		const char* error_message = NULL;
		Reprog* prog = regcomp(searchtext, 0, &error_message);

		for (auto& x : results) {
			x.search_match = false;

			if (!(x.m_flags & include_mask)) continue;
			if (x.m_flags & exclude_mask) continue;

			if (*searchtext) {
				if (prog && (error_message == NULL)) {
					Resub sub;
					regexec(prog, x.m_search_name.c_str(), &sub, 0);
					if (sub.sub[0].sp == NULL) continue;
				}
				else {
					if (x.m_search_name.find(searchtext) == x.m_search_name.npos) continue;
				}
			}

			x.search_match = true;
		}
		regfree(prog);

		results_end = std::partition(
			results_begin,
			results_end,
			[](const Setting& s) -> bool {
				return s.search_match;
			});

		std::sort(
			results_begin,
			results_end,
			[](const Setting& a, const Setting& b) -> bool {
				return (a.m_address < b.m_address);
			});

		results_count = std::distance(results_begin, results_end);
	}

	if (ImGui::TreeNode("Search Options")) {
		ImGui::Text("Include Any of these properties");
		include_mask = 0;
		{ static bool b{true}; ImGui::Checkbox("Type Bool", &b); if(b) include_mask |= GameSettingFlag::TypeBool; }
		{ static bool b{true}; ImGui::Checkbox("Type Float", &b); if(b) include_mask |= GameSettingFlag::TypeFloat; }
		{ static bool b{true}; ImGui::Checkbox("Type Int", &b); if(b) include_mask |= GameSettingFlag::TypeInt; }
		{ static bool b{true}; ImGui::Checkbox("Type RGB", &b); if(b) include_mask |= GameSettingFlag::TypeRGB; }
		{ static bool b{true}; ImGui::Checkbox("Type RGBA", &b); if(b) include_mask |= GameSettingFlag::TypeRGBA; }
		{ static bool b{true}; ImGui::Checkbox("Type String", &b); if(b) include_mask |= GameSettingFlag::TypeString; }
		{ static bool b{true}; ImGui::Checkbox("Type Unknown", &b); if(b) include_mask |= GameSettingFlag::TypeUnknown; }
		{ static bool b{true}; ImGui::Checkbox("Type Unsigned", &b); if(b) include_mask |= GameSettingFlag::TypeUnsigned; }
		ImGui::Separator();
		{ static bool b{true}; ImGui::Checkbox("Origin INI", &b); if(b) include_mask |= GameSettingFlag::OriginINI; }
		{ static bool b{true}; ImGui::Checkbox("Origin INI Pref", &b); if(b) include_mask |= GameSettingFlag::OriginINIPref; }
		{ static bool b{true}; ImGui::Checkbox("Origin GameSetting", &b); if(b) include_mask |= GameSettingFlag::OriginGameSetting; }
		{ static bool b{true}; ImGui::Checkbox("Origin Unknown", &b); if(b) include_mask |= GameSettingFlag::OriginUnknown; }
		ImGui::Separator();
		{ static bool b{true}; ImGui::Checkbox("Flag Changed", &b); if(b) include_mask |= GameSettingFlag::FlagChanged; }

		ImGui::Separator();
		ImGui::Separator();

		ImGui::Text("Exclude any of these properties");
		exclude_mask = 0;
		{ static bool b{ false }; ImGui::Checkbox("Type Bool##exclude", &b); if (b) exclude_mask |= GameSettingFlag::TypeBool; }
		{ static bool b{ false }; ImGui::Checkbox("Type Float##exclude", &b); if (b) exclude_mask |= GameSettingFlag::TypeFloat; }
		{ static bool b{ false }; ImGui::Checkbox("Type Int##exclude", &b); if (b) exclude_mask |= GameSettingFlag::TypeInt; }
		{ static bool b{ false }; ImGui::Checkbox("Type RGB##exclude", &b); if (b) exclude_mask |= GameSettingFlag::TypeRGB; }
		{ static bool b{ false }; ImGui::Checkbox("Type RGBA##exclude", &b); if (b) exclude_mask |= GameSettingFlag::TypeRGBA; }
		{ static bool b{ false }; ImGui::Checkbox("Type String##exclude", &b); if (b) exclude_mask |= GameSettingFlag::TypeString; }
		{ static bool b{ false }; ImGui::Checkbox("Type Unknown##exclude", &b); if (b) exclude_mask |= GameSettingFlag::TypeUnknown; }
		{ static bool b{ false }; ImGui::Checkbox("Type Unsigned##exclude", &b); if (b) exclude_mask |= GameSettingFlag::TypeUnsigned; }
		ImGui::Separator();
		{ static bool b{ false }; ImGui::Checkbox("Origin INI##exclude", &b); if (b) exclude_mask |= GameSettingFlag::OriginINI; }
		{ static bool b{ false }; ImGui::Checkbox("Origin INI Pref##exclude", &b); if (b) exclude_mask |= GameSettingFlag::OriginINIPref; }
		{ static bool b{ false }; ImGui::Checkbox("Origin GameSetting##exclude", &b); if (b) exclude_mask |= GameSettingFlag::OriginGameSetting; }
		{ static bool b{ false }; ImGui::Checkbox("Origin Unknown##exclude", &b); if (b) exclude_mask |= GameSettingFlag::OriginUnknown; }
		ImGui::Separator();
		{ static bool b{ false }; ImGui::Checkbox("Flag Changed##exclude", &b); if (b) exclude_mask |= GameSettingFlag::FlagChanged; }

		ImGui::Separator();
		ImGui::Separator();

		if (ImGui::Button("Save Search Results to ./search_results.txt")) {
			FILE* f = NULL;
			fopen_s(&f, "search_results.txt", "wb");
			assert(f != NULL);
			fprintf(f, "## Generated by LiveINI - https://www.nexusmods.com/starfield/mods/976\r\n");
			const auto& v = GameProcessInfo.exe.version;
			fprintf(f, "## Starfield EXE version: %u.%u.%u.%u\r\n", v.major, v.minor, v.build, v.revision);
			fprintf(f, "## Double pipe characters are used as the unique delimiter\r\n");
			fprintf(f, "## Setting || DefaultValue || INIValue || CurrentValue || Origin\r\n");

			for (auto i = results_begin; i != results_end; ++i) {
				auto vdefault = stringify_value(i->m_setting.Default, i->m_flags);
				auto vini = stringify_value(i->m_setting.Active, i->m_flags);
				auto vcur = stringify_value(i->m_current, i->m_flags);
				auto origin = Setting::GetGameSettingOriginName(i->m_flags);
				fprintf(f, "%s || %s || %s || %s || %s\r\n", i->m_name.c_str(), vdefault.c_str(), vini.c_str(), vcur.c_str(), origin);
			}

			fclose(f);
		}

		if (ImGui::Button("Reset All changed settings")) {
			reset_changed_settings();
		}
		ImGui::TreePop();
	}

	ImGui::SameLine();
	ImGui::Text("| Results: %u/%I64d", results_count, results.size());

	ImGui::BeginChild("results_section", ImVec2{}, false, ImGuiWindowFlags_NoScrollbar);

	ImGuiListClipper clip;
	clip.Begin((int)results_count, ImGui::GetTextLineHeightWithSpacing());
	while (clip.Step()) {
		for (auto i = clip.DisplayStart; i < clip.DisplayEnd; ++i) {
			auto& x = results[i];
			ImGui::PushID(&x);
			if (StyleCollapsingHeader(x.m_name.c_str())) {
				EditSetting(x);
			}
			ImGui::PopID();
		}
	}
	ImGui::EndChild();
}


extern void perform_exe_version_analysis() {
	const Pointer data{ GameProcessInfo.buffer };
	
	const wchar_t* searchtext = L"ProductVersion";
	const wchar_t* haystack = (const wchar_t*)((char*)(GameProcessInfo.buffer) + GameProcessInfo.exe.rsrc.offset);
	const auto count = GameProcessInfo.exe.rsrc.size / sizeof(*haystack);

	for (auto i = 0; i < count; ++i) {
		auto match = 0;
		auto cur = haystack[i];
		auto cmp = searchtext[match];

		while (cur == cmp) {
			++i;
			++match;
			if (cmp == L'\0') {
				auto& v = GameProcessInfo.exe.version;
				auto ret = swscanf_s(&haystack[i], L"%u.%u.%u.%u", &v.major, &v.minor, &v.build, &v.revision);
				assert(ret == 4);
				goto FINISHED;
			}
			cur = haystack[i];
			cmp = searchtext[match];
		}
	}

FINISHED:
	const auto& v = GameProcessInfo.exe.version;
	Log("Game Version: %u.%u.%u.%u", v.major, v.minor, v.build, v.revision);
}