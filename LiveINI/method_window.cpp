#include "main.h"
#include "method_window.h"


struct Result {
        const char* name; //rtti name
        uint32_t method_number; //index into the array of methods on the vtable
        uint32_t method_count; //count of methods in class
        uint32_t offset; //imagebase offset of vtable method
};

extern void draw_method_window() {
        static char buffer[64];
        static std::vector<Result> Results{};

        if (!GameProcessInfo.rtti_map.size()) {
                ImGui::Text("Press Scan Starfield in the log window");
                return;
        }

        if (ImGui::InputText("Offset", buffer, 64)) {
                const auto text_start = GameProcessInfo.base_address + GameProcessInfo.exe.text.offset;
                const auto text_end = text_start + GameProcessInfo.exe.text.size;
                #define is_text_ptr(PTR) (((PTR) >= text_start) && ((PTR) <= text_end))

                const auto func_offset = strtoull(buffer, NULL, 16);
                uint64_t ptr = GameProcessInfo.base_address + func_offset;
                Results.clear();

                if (is_text_ptr(ptr)) {
                        for (const auto& x : GameProcessInfo.rtti_map) {
                                const uintptr_t* methods = (uintptr_t*)((char*)GameProcessInfo.buffer + x.second.vtable_offset);

                                for (uint32_t i = 0; i < x.second.func_count; ++i) {
                                        if (ptr == methods[i]) {
                                                Log("Found Method");
                                                Results.push_back(Result{ x.second.name, i, x.second.func_count, x.second.vtable_offset + (i * 8) });
                                        }
                                }
                        }
                }

                #undef is_text_ptr
        }

        ImGuiListClipper clip;
        clip.Begin((int)Results.size(), ImGui::GetTextLineHeightWithSpacing());

        ImGui::BeginChild("method_window");
        while (clip.Step()) {
                for (int i = clip.DisplayStart; i < clip.DisplayEnd; ++i) {
                        ImGui::PushID(i);
                        const auto r = Results[i];
                        if (ImGui::CollapsingHeader(r.name)) {
                                char text[64];
                                snprintf(text, sizeof(text), "Starfield.exe+0x%X (method %u of %u)", r.offset, r.method_number, r.method_count);
                                ImGui::InputText("Info", text, sizeof(text), ImGuiInputTextFlags_ReadOnly);
                        }
                        ImGui::PopID();
                }
        }
        ImGui::EndChild();
}