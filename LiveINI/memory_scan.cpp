#include "main.h"
#include "process.h"
#include "setting.h"
#include "aobscan.h"

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

extern void turbo_vtable_algorithm() {
	// Utilize the 2 step turbo vtable algorithm to automagically resolve
	// an rtti mangled name into the corresponding vtable pointer
	// no, there are no google results for "turbo vtable algorithm" yet

	const auto text_start = GameProcessInfo.base_address + GameProcessInfo.exe.text.offset;
	const auto text_end = text_start + GameProcessInfo.exe.text.size;
#define is_text_ptr(PTR) (((PTR) >= text_start) && ((PTR) <= text_end))

	const auto rdata_start = GameProcessInfo.base_address + GameProcessInfo.exe.rdata.offset;
	const auto rdata_end = rdata_start + GameProcessInfo.exe.rdata.size;
#define is_rdata_ptr(PTR) (((PTR) >= rdata_start) && ((PTR) <= rdata_end))

	const auto data_start = GameProcessInfo.exe.data.offset;
	const auto data_end = data_start + GameProcessInfo.exe.data.size;
#define is_data_offset(OFF) (((OFF) >= data_start) && ((OFF) <= data_end))


	const uint64_t* haystack = (uint64_t*)((char*)GameProcessInfo.buffer + GameProcessInfo.exe.rdata.offset);
	const uint32_t count = GameProcessInfo.exe.rdata.size / sizeof(*haystack);
	const uint32_t rdata_offset = GameProcessInfo.exe.rdata.offset;
	const uint64_t base = GameProcessInfo.base_address;

	struct Candidate {
		uint32_t vtable_offset;
		uint32_t object_locator_offset;
		uint32_t func_count;
	};
	std::vector<Candidate> Candidates;
	Candidates.reserve(32768);

	//step 1: find a pointer in .rdata that:
	//	-points to somewhere else in .rdata and
	//      -is immediately followed by a pointer inside .text
	//	-keep track of the count of class members
	for (uint32_t i = 0; i < count; ++i) {
		if (is_rdata_ptr(haystack[i])) {
			if (is_text_ptr(haystack[i + 1])) {
				uint32_t ol_offset = (uint32_t)(12 + (haystack[i] - base));
				uint32_t func_count = 0;
				++i;
				uint32_t vt_offset = (rdata_offset + (i * sizeof(*haystack)));
				while (is_text_ptr(haystack[i])) {
					++func_count;
					++i;
				}
				--i;
				
				Candidates.push_back(Candidate{ vt_offset, ol_offset, func_count });
			}
		}
	}

	GameProcessInfo.rtti_map.clear();
	GameProcessInfo.rtti_map.reserve(32768);

	//step 2: heuristically determine which candidates are accurate by:
	//              -checking if the typedescriptor pointer is in .data and
	//              -the type descriptor name starts with '.'
	//		-on collisions, choose the class with more members
	const auto count2 = Candidates.size();
	const char* const baseptr = (char*)GameProcessInfo.buffer;
	for (size_t i = 0; i < count2; ++i) {
		uint32_t td_offset = *(uint32_t*)(baseptr + Candidates[i].object_locator_offset);
		if (!is_data_offset(td_offset)) continue;
		const char* const name = (baseptr + td_offset + 16);
		if (name[0] != '.') continue;
		const RTTI_Info info{name, Candidates[i].func_count, Candidates[i].vtable_offset};

		auto& result = GameProcessInfo.rtti_map[std::string{ name }];
		if (result.func_count < info.func_count) {
			result = info;
		}
	}

#undef is_text_ptr
#undef is_rdata_ptr
#undef is_data_offset
}


extern uintptr_t find_vtable(const char* const rtti_name) {
	Log("find_vtable: %s", rtti_name);
	const auto search = GameProcessInfo.rtti_map.find(std::string{ rtti_name });
	if (search == GameProcessInfo.rtti_map.end()) return 0;
	auto ret = GameProcessInfo.base_address + search->second.vtable_offset;
	Log("Found: %p", (void*)ret);
	return ret;
}


extern void scan_vtable() {
	results.clear();
	results.reserve(16384); //more than enough for all game settings

	const auto sz = GameProcessInfo.buffer_size;
	const Pointer buffer(GameProcessInfo.buffer);

	struct vtable_offsets {
		uintptr_t offset;
		GameSettingFlag origin;
	} const settings_vtable[] = {
		{find_vtable(".?AV?$SettingT@VINISettingCollection@@@@"), GameSettingFlag::OriginINI},
		{find_vtable(".?AVRendererQualitySetting@CreationRenderer@@"), GameSettingFlag::OriginRendererQuality},
		{find_vtable(".?AVRendererQualityPref@CreationRenderer@@"), GameSettingFlag::OriginRendererPref},
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
                        
                        if (!RPM(s.m_setting.Name, tmp_name, 128)) {
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
                RPM(v.as_ptr, localbuffer, 1024);
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
		s.Update();
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
		s.Update();
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
		s.Update();
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

static void reset_changed_settings(void) {
	for (auto& x : results) {
		if (!(x.m_flags & GameSettingFlag::FlagChanged)) continue;
		x.m_flags &= ~GameSettingFlag::FlagChanged;
		x.m_current = x.m_setting.Active;
		x.Update();
	}
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
		{ static bool b{true}; ImGui::Checkbox("INI", &b); if(b) include_mask |= GameSettingFlag::OriginINI; }
		{ static bool b{true}; ImGui::Checkbox("RendererQuality", &b); if(b) include_mask |= GameSettingFlag::OriginRendererQuality; }
		{ static bool b{true}; ImGui::Checkbox("RendererPref", &b); if(b) include_mask |= GameSettingFlag::OriginRendererPref; }
		{ static bool b{true}; ImGui::Checkbox("GameSetting", &b); if(b) include_mask |= GameSettingFlag::OriginGameSetting; }
		{ static bool b{true}; ImGui::Checkbox("Unknown", &b); if(b) include_mask |= GameSettingFlag::OriginUnknown; }
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
		{ static bool b{ false }; ImGui::Checkbox("INI##exclude", &b); if (b) exclude_mask |= GameSettingFlag::OriginINI; }
		{ static bool b{ false }; ImGui::Checkbox("RendererQuality##exclude", &b); if (b) exclude_mask |= GameSettingFlag::OriginRendererQuality; }
		{ static bool b{ false }; ImGui::Checkbox("RendererPref##exclude", &b); if (b) exclude_mask |= GameSettingFlag::OriginRendererPref; }
		{ static bool b{ false }; ImGui::Checkbox("GameSetting##exclude", &b); if (b) exclude_mask |= GameSettingFlag::OriginGameSetting; }
		{ static bool b{ false }; ImGui::Checkbox("Unknown##exclude", &b); if (b) exclude_mask |= GameSettingFlag::OriginUnknown; }
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
			if (ImGui::CollapsingHeader(x.m_name.c_str())) {
				EditSetting(x);
			}
			ImGui::PopID();
		}
	}
	ImGui::EndChild();
}


extern void perform_exe_version_analysis() {
	// instead of using the windows api for getting the executable version information its actually faster
	// to brute-force search the .rsrc section of the exe since we already have it in a buffer

	// L"ProductVersion"
	AOB_SIG aob = aob_compile("50 00 72 00 6f 00 64 00 75 00 63 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00");
	auto offset = aob_scan(GameProcessInfo.buffer, (unsigned)GameProcessInfo.buffer_size, GameProcessInfo.exe.rsrc.offset, aob);
	aob_free(aob);
	assert(offset != AOB_NO_MATCH);
	offset += 30; // L"ProductVersion" + wchar_t null terminator 
	const char* buffer = (char*)GameProcessInfo.buffer;
	auto& v = GameProcessInfo.exe.version;
	auto ret = swscanf_s((wchar_t*) & buffer[offset], L"%u.%u.%u.%u", &v.major, &v.minor, &v.build, &v.revision);
	assert(ret == 4);
	Log("Game Version: %u.%u.%u.%u", v.major, v.minor, v.build, v.revision);
}