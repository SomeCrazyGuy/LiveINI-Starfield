#include "main.h"
#include "rtti_window.h"
#include "memory_scan.h"

extern "C" {
        #include "minilibs/regexp.h"
}

struct RTTIDetail {
        std::string name;
        std::string search_name;
        uintptr_t vtable_ptr;
        unsigned offset;
        bool match;
};


void draw_rtti_window() {
        static char searchbuffer[128];
        static std::vector<RTTIDetail> rtti;

        if (GameProcessInfo.rtti_map.empty()) return;

        if (rtti.empty()) {
                rtti.reserve(GameProcessInfo.rtti_map.size());
                for (const auto& x : GameProcessInfo.rtti_map) {
                        RTTIDetail d;
                        d.name = x.first;
                        d.offset = x.second;
                        d.vtable_ptr = 0;
                        d.match = false;
                        for (const auto i : d.name) {
                                d.search_name += (char)::tolower(i);
                        }
                        rtti.push_back(d);
                }
        }

        static auto match_begin = rtti.begin();
        static auto match_end = rtti.end();

        if (ImGui::InputText("Search", searchbuffer, 128)) {
                for (unsigned i = 0; searchbuffer[i]; ++i) {
                        searchbuffer[i] = (char)::tolower(searchbuffer[i]);
                }

                const char* error_string = NULL;
                Reprog* regex = regcomp(searchbuffer, 0, &error_string);

                for (auto& x : rtti) {
                        if (*searchbuffer == '\0') {
                                x.match = true;
                        }
                        else if (regex && (error_string == NULL)) {
                                Resub result;
                                regexec(regex, x.search_name.c_str(), &result, 0);
                                x.match = (result.sub[0].sp != NULL);
                        }
                        else {
                                x.match = (x.search_name.find(searchbuffer) != std::string::npos);
                        }
                }

                regfree(regex);

                match_end = std::partition(
                        match_begin,
                        rtti.end(),
                        [](const RTTIDetail& x) noexcept -> bool {
                                return x.match;
                        });
        }

        auto result_count = std::distance(match_begin, match_end);
        ImGui::Text("Results: %d / %d", result_count, rtti.size());

        ImGui::BeginChild("rtti_results_section", ImVec2{}, false, ImGuiWindowFlags_NoScrollbar);

        ImGuiListClipper clip{};
        clip.Begin((int)result_count, ImGui::GetTextLineHeightWithSpacing());
        while (clip.Step()) {
                for (auto i = clip.DisplayStart; i < clip.DisplayEnd; ++i) {
                        ImGui::PushID(i);
                        auto& r = rtti[i];
                        if (ImGui::CollapsingHeader(r.name.c_str())) {
                                static char vtable_text[64];

                                if (r.vtable_ptr == 0) {
                                        r.vtable_ptr = find_vtable(r.name.c_str());
                                }

                                snprintf(vtable_text, 64, "0x%p", (void*)r.vtable_ptr);
                                ImGui::InputText("Vtable Pointer", vtable_text, 64, ImGuiInputTextFlags_ReadOnly);
                        }
                        ImGui::PopID();
                }
        }
        ImGui::EndChild();
}