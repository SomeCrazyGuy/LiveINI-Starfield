#include "main.h"
#include "method_window.h"


struct Result {
        std::string name; //rtti name
        uint32_t method_number; //index into the array of methods on the vtable
        uint32_t offset; //imagebase offset of vtable method
};

void draw_method_window() {
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

                                uint32_t method_num = 0;
                                while (is_text_ptr(methods[method_num])) {


                                        if (ptr == methods[method_num]) {
                                                Log("Found Method");
                                                Results.push_back(Result{x.first, method_num, x.second.vtable_offset + (method_num * 8)});
                                        }

                                        ++method_num;

                                        if (x.second.vtable_offset == 0x44DD370) {
                                                Log("Testing Method %u (%p)", method_num, methods[method_num]);
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
                        if (ImGui::CollapsingHeader(r.name.c_str())) {
                                char text[64];
                                snprintf(text, sizeof(text), "Starfield.exe+0x%X (method %u)", r.offset, r.method_number);
                                ImGui::InputText("Info", text, sizeof(text), ImGuiInputTextFlags_ReadOnly);
                        }
                        ImGui::PopID();
                }
        }
        ImGui::EndChild();
}