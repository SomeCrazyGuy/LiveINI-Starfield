#include "main.h"
#include "heap_window.h"
#include "process.h"

static std::vector<MemoryBlock> Heaps{};

void build_heap_list() {
        MEMORY_BASIC_INFORMATION mbi;
        constexpr auto mbi_size = sizeof(mbi);
        constexpr auto min_heap_size = 120 * 1024 * 1024; //only consider heaps larger than 120MB


        Heaps.clear();
        for (uintptr_t address = 0; VirtualQueryEx(GameProcessInfo.process, (LPCVOID)address, &mbi, mbi_size); address += mbi.RegionSize) {
                if (!mbi.RegionSize) break;
                if (mbi.State != MEM_COMMIT) continue;
                if (mbi.Protect & (PAGE_GUARD | PAGE_NOCACHE | PAGE_WRITECOMBINE | PAGE_NOACCESS)) continue;
                if (mbi.RegionSize < min_heap_size) continue; 
                if (address > GameProcessInfo.base_address) continue;

                MemoryBlock mb;
                mb.address = address;
                mb.size = mbi.RegionSize;
                Heaps.push_back(mb);
        }
}


static std::vector<uintptr_t> ScanResults{};
void scan_heap(const MemoryBlock heap, uintptr_t instance) {
        static uintptr_t* ScanBuffer = NULL;
        static const uint32_t ScanBufferSize = (60 * 1024 * 1024);

        ScanResults.clear();

        if (!ScanBuffer) {
                ScanBuffer = (uintptr_t*) malloc(ScanBufferSize);
                assert(ScanBuffer != NULL);
        }

        uint64_t offset = 0;
        do {
                uint64_t scan_size = ((offset + ScanBufferSize) > heap.size) ? (heap.size - offset) : ScanBufferSize;
                uint64_t count = scan_size / sizeof(ScanBuffer[0]);
                if (!RPM(heap.address + offset, ScanBuffer, scan_size)) break;

                for (uint64_t i = 0; i < count; ++i) {
                        if (ScanBuffer[i] == instance) {
                                ScanResults.push_back(heap.address + offset + (i * sizeof(ScanBuffer[0])));
                        }
                }

                offset += scan_size;
        } while (offset < heap.size);
}





extern void draw_heap_window() {
        static unsigned selected_heap = 0;

        if (!GameProcessInfo.rtti_map.size()) {
                ImGui::Text("Press Scan Starfield in the log window");
                return;
        }

        if (ImGui::Button("Scan Heaps")) {
                build_heap_list();
        } 

        //TODO: add search bar
        static char search[64];
        ImGui::InputText("Instance Ptr", search, 64);

        ImGui::SameLine();
        
        if (ImGui::Button("Scan")) {
                scan_heap(Heaps[selected_heap], strtoull(search, NULL, 16));
        }

        for (auto i = 0; i < Heaps.size(); ++i) {
                ImGui::PushID(i);
                const auto& x = Heaps[i];
                char buffer[64];
                snprintf(buffer, 64, "Address %p, Size: %uMB", (void*)x.address, (uint32_t)(x.size / (1024 * 1024)));
                static int radio_state = 0;
                if (ImGui::RadioButton(buffer, &radio_state, i)) {
                        selected_heap = i;
                }
                ImGui::PopID();
        }

        ImGui::BeginChild("heaps window");
        ImGuiListClipper clip;
        clip.Begin((int)ScanResults.size());
        while (clip.Step()) {
                for (auto i = clip.DisplayStart; i < clip.DisplayEnd; ++i) {
                        char buffer[64];
                        snprintf(buffer, sizeof(buffer), "%p", (void*)ScanResults[i]);
                        ImGui::PushID(i);
                        ImGui::InputText("Address", buffer, sizeof(buffer), ImGuiInputTextFlags_ReadOnly);
                        ImGui::PopID();
                }
        }
        ImGui::EndChild();
}