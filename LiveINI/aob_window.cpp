#include "main.h"
#include "aob_window.h"
#include "aobscan.h"

void draw_aob_window() {
        static char buffer[256];
        static std::vector<uint32_t> results;

        if (!GameProcessInfo.rtti_map.size()) {
                ImGui::Text("Press Scan Starfield in the log window");
                return;
        }


        ImGui::InputText("Signature", buffer, 256);
        ImGui::SameLine();
        if (ImGui::Button("Search")) {
                results.clear();

                AOB_SIG sig = aob_compile(buffer);
                if (sig) {
                        const auto buff = GameProcessInfo.buffer;
                        const auto text = GameProcessInfo.exe.text;
                        unsigned offset = text.offset;

                        do {
                                offset = aob_scan(buff, text.offset + text.size, offset, sig);
                                if (offset == AOB_NO_MATCH) break;

                                results.push_back(offset);
                                ++offset;
                        } while (true);

                        free(sig);
                }
        }

        ImGui::Text("%u results", results.size());

        ImGui::BeginChild("aob_search_results");

        ImGuiListClipper clip;
        clip.Begin((int)results.size(), ImGui::GetTextLineHeightWithSpacing());
        while (clip.Step())
        {
                for (auto i = clip.DisplayStart; i < clip.DisplayEnd; ++i) {
                        char name[64];
                        snprintf(name, sizeof(name), "starfield.exe+%x (%p)", results[i], (void*)(GameProcessInfo.base_address + results[i]));
                        ImGui::PushID(i);
                        ImGui::InputText("Offset", name, sizeof(name), ImGuiInputTextFlags_ReadOnly);
                        ImGui::PopID();
                }
        }


        ImGui::EndChild();
}