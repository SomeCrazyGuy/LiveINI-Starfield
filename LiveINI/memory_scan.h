#pragma once

extern void build_rtti_list(void);
extern uintptr_t find_vtable(const char* const rtti_name);
extern void scan_window_draw(void);
extern void scan_vtable(void);
extern void perform_exe_section_analysis();