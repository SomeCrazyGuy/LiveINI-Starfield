#pragma once

#define WIN32_LEAN_AND_MEAN
#define VC_EXTRA_LEAN

#define NOGDICAPMASKS         //CC_ * , LC_*, PC_*, CP_*, TC_*, RC_
//#define NOVIRTUALKEYCODES     //VK_ *
//#define NOWINMESSAGES         //WM_ * , EM_*, LB_*, CB_*
//#define NOWINSTYLES           //WS_ * , CS_*, ES_*, LBS_*, SBS_*, CBS_*
#define NOSYSMETRICS          //SM_ *
#define NOMENUS               //MF_ *
#define NOICONS               //IDI_ *
#define NOKEYSTATES           //MK_ *
//#define NOSYSCOMMANDS         //SC_ *
#define NORASTEROPS           //Binary and Tertiary raster ops
//#define NOSHOWWINDOW          //SW_ *
#define NOATOM                //Atom Manager routines
#define NOCLIPBOARD           //Clipboard routines
#define NOCOLOR               //Screen colors
#define NOCTLMGR              //Control and Dialog routines
#define NODRAWTEXT            //DrawText() and DT_*
#define NOGDI                 //All GDI defines and routines
#define NOKERNEL              //All KERNEL defines and routines
#define NONLS                 //All NLS defines and routines
//#define NOUSER                //All USER defines and routines
//#define NOMB                  //MB_ * and MessageBox()
#define NOMEMMGR              //GMEM_ * , LMEM_*, GHND, LHND, associated routines
#define NOMETAFILE            //typedef METAFILEPICT
#define NOMINMAX              //Macros min(a, b) and max(a, b)
//#define NOMSG                 //typedef MSG and associated routines
#define NOOPENFILE            //OpenFile(), OemToAnsi, AnsiToOem, and OF_*
#define NOSCROLL              //SB_ * and scrolling routines
#define NOSERVICE             //All Service Controller routines, SERVICE_ equates, etc.
#define NOSOUND               //Sound driver routines
#define NOTEXTMETRIC          //typedef TEXTMETRIC and associated routines
#define NOWH                  //SetWindowsHook and WH_*
//#define NOWINOFFSETS          //GWL_ * , GCL_*, associated routines
#define NOCOMM                //COMM driver routines
#define NOKANJI               //Kanji support stuff.
#define NOHELP                //Help engine interface.
#define NOPROFILER            //Profiler interface.
#define NODEFERWINDOWPOS      //DeferWindowPos routines
#define NOMCX                 //Modem Configuration Extensions

#include <d3d11.h>
#include <Windows.h>
#include <Psapi.h>


#include "imgui/imgui.h"
#include "imgui/imgui_impl_win32.h"
#include "imgui/imgui_impl_dx11.h"

#include <vector>
#include <cstdint>
#include <string>
#include <algorithm>
#include <iterator>
#include <unordered_map>

//log functions from log_window.cpp
extern void Log(const char* const fmt, ...);
extern void draw_log_window(void);


enum MemoryFlag : unsigned {
	MemoryFlag_Read = 1 << 0,
	MemoryFlag_Write = 1 << 1,
	MemoryFlag_Execute = 1 << 2,
};

struct MemoryBlock {
	uintptr_t address;
	uint64_t size;
	unsigned flags;
};

struct ProcessInfo {
	HANDLE process;
	void* buffer;
	uint64_t buffer_size;
	uint64_t base_address;
	DWORD proc_id;
	std::unordered_map<std::string, unsigned> rtti_map;
	
	struct ExeInfo {
		struct SectionInfo {
			uint32_t offset;
			uint32_t size;
		}
		text, rdata, data, rsrc;

		struct VersionInfo {
			unsigned major;
			unsigned minor;
			unsigned build;
			unsigned revision;
		} version;
	} exe;

	std::vector<MemoryBlock> blocks;
};

extern ProcessInfo GameProcessInfo;