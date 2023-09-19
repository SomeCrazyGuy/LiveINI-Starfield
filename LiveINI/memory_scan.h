#pragma once

extern uintptr_t find_vtable(const char* const rtti_name);
extern void scan_window_draw(void);
extern void scan_vtable(void);

//perform the following steps in this exact order:
extern void perform_exe_section_analysis();
extern void perform_exe_version_analysis();
//extern void build_rtti_list(void);
extern void turbo_vtable_algorithm();